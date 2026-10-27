# Universal Command allows multiple Vendor commands to be used by a single Universal Command

CONSTANT_PACK_VERSION = '3.3.1'
demisto.debug('pack id = soc-optimization-unified, pack version = 3.3.1')

import json
import re
import uuid
from datetime import datetime

CTX_REF_RE = re.compile(r"^\$\{(.+?)\}$")


def utc_now():
    return datetime.utcnow().isoformat() + "Z"


def warroom_log(title, payload, tags=None, footer=""):
    try:
        readable = f"### {title}\n```json\n{json.dumps(payload, indent=2)}\n```"
        if footer:
            readable += f"\n{footer}"
        entry = {
            "Type": EntryType.NOTE,
            "ContentsFormat": "json",
            "Contents": payload,
            "HumanReadable": readable
        }

        if tags:
            entry["Tags"] = tags

        demisto.results(entry)

    except Exception as e:
        demisto.debug(f"warroom_log failed: {str(e)}")


def shadow_go_live_command(action, actor):
    """The SOCFWConfig command that makes this action real for this actor."""
    who = str(actor or "").strip().lower() or "<actor>"
    return (f"!SOCFWConfig command=shadow action={action} actor={who} "
            "value=off apply=yes")


def shadow_footer(action, actor):
    """How to make this specific action real, printed where it is noticed.

    Names the action and the actor, because they are separable: an analyst
    clicking a layout button and the containment JOB are different actors and
    can be taken off shadow independently.
    """
    return (
        "\n**This was a simulation.** No vendor command ran.\n\n"
        f"To make `{action}` real for this actor, run:\n\n"
        "```\n"
        f"{shadow_go_live_command(action, actor)}\n"
        "```\n\n"
        "Run it without `apply=yes` first to see the change.\n\n"
        "_Actions stay simulated until someone changes this deliberately._"
    )


def _try_json_loads(s):
    try:
        return json.loads(s)
    except Exception:
        return None


def _resolve_ctx_string(s, ctx):
    """
    Keep this behavior aligned with SOCFrameworkActions.
    Resolve only from playbook/data context for recognized paths.
    """
    if not isinstance(s, str):
        return s

    s = s.strip()

    m = CTX_REF_RE.match(s)
    if m:
        return _resolve_ctx_path(ctx, m.group(1))

    if (
            s.startswith("SOCFramework.")
            or s.startswith("incident.")
            or s.startswith("alert.")
            or s.startswith("issue.")
            or s.startswith("parentIncidentFields.")
    ):
        return _resolve_ctx_path(ctx, s)

    return s


def _is_ctx_template(raw):
    """
    True when an inline_args template is a CONTEXT REFERENCE rather than a
    static literal — i.e. it is the kind of arg that carries evidence from the
    alert, and whose absence means there is nothing to act on.

    Must mirror the recognised forms in _resolve_ctx_string exactly, or the
    emptiness guard will disagree with what actually got resolved.
    """
    if not isinstance(raw, str):
        return False

    s = raw.strip()

    if CTX_REF_RE.match(s):
        return True

    return s.startswith((
        "SOCFramework.",
        "incident.",
        "alert.",
        "issue.",
        "parentIncidentFields.",
    ))


def _resolve_ctx_path(ctx, path):
    """
    Resolve a dotted context path, traversing intermediate lists.

    demisto.get() only walks dict keys, so a path like
    SOCFramework.Email.threat_id resolves to None whenever an
    intermediate node (e.g. SOCFramework.Email) is stored as a list —
    which Normalize/Enrich frequently produce. Walk segment by segment,
    flattening list nodes as we go, then return the first non-empty
    scalar (matching prior leaf-list behavior).
    """
    node = ctx

    for segment in path.split("."):
        if isinstance(node, list):
            # Flatten: collect this segment from every dict element
            collected = []
            for item in node:
                if isinstance(item, dict) and segment in item:
                    v = item[segment]
                    if isinstance(v, list):
                        collected.extend(v)
                    else:
                        collected.append(v)
            node = collected
        elif isinstance(node, dict):
            node = node.get(segment)
        else:
            return None

        if node in (None, "", [], {}):
            return None

    if isinstance(node, list):
        node = next((v for v in node if v not in (None, "", [], {})), None)

    return node


def _resolve_ctx_path_list(ctx, path):
    """Resolve a dotted context path keeping the WHOLE leaf list.

    _resolve_ctx_path deliberately returns the first non-empty scalar so that
    single-valued args stay scalars. Target expansion needs the opposite: when
    an issue carries four domains, all four are the work. Same traversal,
    different leaf rule — a list comes back filtered of empties, a scalar
    comes back as itself.
    """
    node = ctx

    for segment in str(path).split("."):
        if isinstance(node, list):
            collected = []
            for item in node:
                if isinstance(item, dict) and segment in item:
                    v = item[segment]
                    if isinstance(v, list):
                        collected.extend(v)
                    else:
                        collected.append(v)
            node = collected
        elif isinstance(node, dict):
            node = node.get(segment)
        else:
            return None

        if node in (None, "", [], {}):
            return None

    if isinstance(node, list):
        return [v for v in node if v not in (None, "", [], {})]

    return node


def _resolve_templates(obj, ctx):
    if isinstance(obj, dict):
        return {k: _resolve_templates(v, ctx) for k, v in obj.items()}

    if isinstance(obj, list):
        return [_resolve_templates(x, ctx) for x in obj]

    if isinstance(obj, str):
        return _resolve_ctx_string(obj, ctx)

    return obj


def append_context(key, record):
    ctx = demisto.context()
    existing = demisto.get(ctx, key)

    if not existing:
        demisto.setContext(key, [record])
        return

    if not isinstance(existing, list):
        existing = [existing]

    existing.append(record)
    demisto.setContext(key, existing)


def _extract_entry_context(result):
    """
    Pull the merged EntryContext dict from an executeCommand result list.
    Commands may return multiple entries; merge all EntryContext dicts.

    XSOAR integration commands use DT (demisto transforms) expression keys
    for dedup/append control, e.g.:
        "MsGraph.Hunt(val.query && val.query == obj.query)": [...]

    We strip the DT parenthetical so output_map can resolve against the
    clean base path. The raw value (what the command actually returned)
    is preserved — it is NOT the accumulated array from investigation
    context, just this execution's output.
    """
    merged = {}
    if not result or not isinstance(result, list):
        return merged
    for entry in result:
        if isinstance(entry, dict):
            ec = entry.get("EntryContext")
            if isinstance(ec, dict):
                for key, value in ec.items():
                    # Strip DT expression: "MsGraph.Hunt(val.x == obj.x)" → "MsGraph.Hunt"
                    clean_key = re.sub(r'\(.*\)$', '', key)
                    merged[clean_key] = value
    return merged


def _resolve_from_entry_context(ec, path):
    """
    Resolve a dotted path against a flat-key EntryContext dict.

    EntryContext keys are flat dotted strings (after DT stripping), e.g.
    "MsGraph.Hunt", not nested dicts. demisto.get() does nested dict
    traversal and won't match flat keys, so we match directly.

    Tries exact match first, then prefix match for sub-path access
    (e.g., path "MsGraph.Hunt.results" against key "MsGraph.Hunt").
    """
    if not ec or not isinstance(ec, dict) or not path:
        return None

    # Exact match — output_map source == EntryContext key
    if path in ec:
        return ec[path]

    # Sub-path: output_map asks for "MsGraph.Hunt.results" but EC key is "MsGraph.Hunt"
    # Find the longest matching EC key that is a prefix of path
    best_key = ""
    for ec_key in ec:
        if path.startswith(ec_key + ".") and len(ec_key) > len(best_key):
            best_key = ec_key

    if best_key:
        remainder = path[len(best_key) + 1:]  # strip prefix + dot
        value = ec[best_key]
        # Walk the remainder into the value
        for part in remainder.split("."):
            if isinstance(value, dict):
                value = value.get(part)
            elif isinstance(value, list) and value:
                # If it's a list, try walking into the first element
                value = value[0].get(part) if isinstance(value[0], dict) else None
            else:
                return None
        return value

    return None


def apply_output_map(output_map, ctx, shadow_mode, entry_context=None):
    """
    Write UC.* canonical keys from vendor-specific context paths.

    output_map format (defined per vendor response in SOCFrameworkActions_V3):
      { "UC.Email.Forensics.behavior": "Proofpoint.Report.Behavior", ... }

    In shadow mode: writes "shadow_mode" sentinel so downstream conditions
    can use isExists(UC.*) without erroring.

    In execute mode: resolves each source path from the executeCommand
    EntryContext (fresh return value), falling back to investigation context
    only if entry_context lookup fails. Skips entries where source
    resolves empty.
    """
    if not output_map or not isinstance(output_map, dict):
        return

    for dest_key, source_path in output_map.items():
        if not dest_key or not source_path:
            continue

        if shadow_mode:
            demisto.setContext(dest_key, "shadow_mode")
            demisto.debug(f"apply_output_map shadow: {dest_key} = shadow_mode")
            continue

        # Resolve source path — strip filter expressions (e.g. path[key=val].count)
        # Use the base path only; playbook transformers handle filtering
        base_path = re.split(r'[\[\.]', source_path)[0] if '[' in source_path else source_path
        # Re-add dotted sub-path if no filter was present
        if '[' not in source_path:
            base_path = source_path

        value = None

        # 1. Try fresh EntryContext from this executeCommand's return value
        if entry_context:
            value = _resolve_from_entry_context(entry_context, base_path)
            if value not in (None, "", [], {}):
                demisto.debug(f"apply_output_map: {dest_key} <- {base_path} (from EntryContext)")

        # 2. Fallback: investigation context (stale but covers side-effect writes)
        if value in (None, "", [], {}):
            value = demisto.get(ctx, base_path)
            if value not in (None, "", [], {}):
                demisto.debug(f"apply_output_map: {dest_key} <- {base_path} (from investigation context fallback)")

        if value in (None, "", [], {}):
            demisto.debug(f"apply_output_map: {dest_key} skipped — source {base_path} empty in both contexts")
            continue

        demisto.setContext(dest_key, value)
        demisto.debug(f"apply_output_map: {dest_key} set successfully")


def integration_failed(result):
    if not result:
        return True, "Empty result"

    entry = result[0]

    if entry.get("Type") == entryTypes["error"]:
        return True, entry.get("Contents")

    contents = entry.get("Contents")

    if isinstance(contents, str) and "error" in contents.lower():
        return True, contents

    return False, None


def parse_tags(raw_tags):
    if not raw_tags:
        return []

    if isinstance(raw_tags, list):
        return [str(t).strip() for t in raw_tags if str(t).strip()]

    if isinstance(raw_tags, str):
        s = raw_tags.strip()

        if not s:
            return []

        if s.startswith("[") and s.endswith("]"):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    return [str(t).strip() for t in parsed if str(t).strip()]
            except Exception:
                pass

        return [t.strip() for t in s.split(",") if t.strip()]

    return [str(raw_tags).strip()]


def get_or_create_run_id(ctx):
    run_id = demisto.get(ctx, "SOCFramework.RunID")
    if run_id not in (None, "", [], {}):
        return run_id

    run_id = str(uuid.uuid4())
    demisto.setContext("SOCFramework.RunID", run_id)
    return run_id


TENANT_CONFIG_LIST = "SOCFWTenantConfig"


def _read_tenant_config_list(name):
    """None when the list does not exist; {} when it exists but is unusable."""
    try:
        res = demisto.executeCommand("getList", {"listName": name})
        entry = res[0] if res and isinstance(res, list) and isinstance(res[0], dict) else {}
    except Exception as e:
        demisto.debug(f"SOCCommandWrapper: {name} unreadable ({e})")
        return None
    raw = entry.get("Contents")
    # A missing list comes back as an error entry: " - Item not found (8) on list [<name>] (2609)".
    if not raw or entry.get("Type") == 4 or "Item not found" in str(raw):
        return None
    cfg = _try_json_loads(raw) if isinstance(raw, str) else raw
    if not isinstance(cfg, dict):
        demisto.debug(f"SOCCommandWrapper: {name} is not a JSON object; ignoring it")
        return {}
    return cfg


def load_tenant_config():
    """The customer's values, from the tenant-only config list.

    Created on the tenant, never shipped in a pack, so an upgrade cannot
    overwrite it. Missing or unreadable means nothing is configured, and any
    action that needs a value skips with a reason naming it.
    """
    return _read_tenant_config_list(TENANT_CONFIG_LIST) or {}


def brand_available(brand):
    """Whether the vendor's brand is registered and has an active instance.

    Answers from the in-process module registry, so it costs nothing. It only
    short-circuits the dispatch when the brand IS registered and every instance
    of it is inactive — the one case where absence is proven. An unregistered
    brand is dispatched anyway, because the platform routes by command name and
    a differently-named integration may serve the same command.

    Reachability is out of scope: a configured instance with bad credentials
    still has to be discovered by calling it.

    Fails open. A checker that cannot read the registry must not be the reason
    an action is skipped.
    """
    try:
        modules = demisto.getModules() or {}
    except Exception as e:
        demisto.debug(f"SOCCommandWrapper: getModules unavailable ({e}); dispatching anyway.")
        return True

    if not modules:
        return True

    registered = []
    for module in modules.values():
        if not isinstance(module, dict):
            continue
        if module.get("brand") == brand:
            registered.append(module)

    # No module claims this brand. That is not evidence the command is missing:
    # the platform dispatches by command name, and the vendor labels in
    # SOCFrameworkActions_V3 do not always equal the installed brand string
    # ('Trend Micro Vision One' vs 'Trend Micro Vision One V3'). Skipping here
    # would silently disable actions that work. Dispatch and let the platform
    # answer.
    if not registered:
        demisto.debug(f"SOCCommandWrapper: no module registered for brand '{brand}'; dispatching.")
        return True

    return any(m.get("state") == "active" for m in registered)


# Actions in these phases only read. Every other action can change something.
READ_ONLY_PHASES = ("enrichment", "investigation")


def is_read_only(action_entry):
    return str(action_entry.get("phase") or "").strip().lower() in READ_ONLY_PHASES


def _as_bool(value):
    """True/False for a bool or a "true"/"false" string; None for anything else."""
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "false"):
        return text == "true"
    return None


# "framework" was the starring path's name for an unattended run; it is now
# "automation". Read as automation for one release so playbooks already
# deployed keep working - unless the setting being read names "framework"
# itself, so a list edited on a tenant does not change behaviour silently.
LEGACY_ACTOR_ALIASES = {"framework": "automation"}


def _shadow_actor(raw_actor, named):
    actor = str(raw_actor or "").strip().lower()
    alias = LEGACY_ACTOR_ALIASES.get(actor)
    return alias if alias and actor not in named else actor


def tenant_shadow_override(tenant_config, action, raw_actor):
    """The customer's shadow setting for this action and actor, or None.

    Lives in the tenant config as {"shadow": {action: {actor: bool}}}, written
    by SOCFWConfig. One entry per action per actor, never a catch-all, so the
    answer for any pair is either named here or comes from the shipped row.
    A value that is not a boolean is ignored rather than guessed.
    """
    if not str(raw_actor or "").strip() or not isinstance(tenant_config, dict):
        return None
    section = tenant_config.get("shadow")
    per_action = section.get(action) if isinstance(section, dict) else None
    if not isinstance(per_action, dict):
        return None
    actor = _shadow_actor(raw_actor, per_action)
    if actor not in per_action:
        return None
    value = _as_bool(per_action[actor])
    if value is None:
        demisto.debug(
            f"SOCCommandWrapper: ignoring non-boolean shadow override "
            f"{action}/{actor}={per_action[actor]!r}")
    return value


def resolve_shadow_mode(action_entry, raw_actor, tenant_override=None):
    """Whether this dispatch is simulated, for this caller.

    A tenant override for this action and actor (tenant_shadow_override)
    decides first. Without one, the shipped action row decides as below.

    An action row says it one of two ways, never both:

        "shadow_mode": true                    one setting for every actor
        "shadow_mode_by_actor": {"analyst": false, "ai": true,
                                 "automation": true}

    The per-actor form lets a customer have analysts really act from the issue
    layout while unattended runs still simulate - a human in the loop on every
    real action before any of it runs unattended. An actor the per-actor form
    does not name is simulated. A row still carrying both (a list edited before
    this rule) is read as before: the named actor, else shadow_mode.

    Resolved on the raw actor, because normalize_action_actor rewrites "analyst"
    to "shadow" once shadowing is decided and would erase the distinction.

    Fails closed. An action that can change something (any phase but
    enrichment or investigation) is simulated when its shadow_mode is missing or
    is not plainly true or false, and a garbled per-actor value falls back to
    that default. Only a deliberate false makes such an action run.
    """
    if tenant_override is not None:
        demisto.debug(f"resolve_shadow_mode: tenant override shadow={tenant_override}")
        return tenant_override

    default = _as_bool(action_entry.get("shadow_mode"))
    if default is None:
        default = not is_read_only(action_entry)
        demisto.debug(
            f"resolve_shadow_mode: shadow_mode missing or unreadable "
            f"({action_entry.get('shadow_mode')!r}); using {default}")

    by_actor = action_entry.get("shadow_mode_by_actor")
    if not isinstance(by_actor, dict):
        return default

    actor = _shadow_actor(raw_actor, by_actor)
    # An unrecognised or absent caller falls back to the action default rather
    # than to whichever entry happens to be first - an unknown caller is the
    # case where simulating is the safer guess.
    if actor not in by_actor:
        return default

    value = _as_bool(by_actor[actor])
    if value is None:
        demisto.debug(f"resolve_shadow_mode: unreadable value for {actor} "
                      f"({by_actor[actor]!r}); using the action default {default}")
        return default
    demisto.debug(
        f"resolve_shadow_mode: actor={actor} shadow={value} (default {default})")
    return value


def normalize_action_actor(raw_actor, shadow_mode):
    actor = str(raw_actor or "").strip().lower()

    if shadow_mode and actor in ("", "analyst"):
        return "shadow"

    if actor in ("automation", "analyst", "shadow", "system", "layout", "ai", "framework"):
        return actor

    return "analyst"


def sanitize_name(value):
    return re.sub(r"[^A-Za-z0-9_]+", "_", str(value or "").strip()).strip("_")


def get_schema_list_candidates(ctx, lifecycle_value):
    candidates = []

    lifecycle_ctx = demisto.get(ctx, "SOCFramework.lifecycle")
    lifecycle = lifecycle_value or lifecycle_ctx or ""
    lifecycle_sanitized = sanitize_name(lifecycle)

    if lifecycle:
        candidates.append(f"SOCFrameworkSchema_{lifecycle}")
    if lifecycle_sanitized and lifecycle_sanitized != lifecycle:
        candidates.append(f"SOCFrameworkSchema_{lifecycle_sanitized}")

    candidates.append("SOCFrameworkSchema")
    candidates.append("SOCFrameworkExecutionSchema")

    seen = set()
    ordered = []
    for name in candidates:
        if name and name not in seen:
            ordered.append(name)
            seen.add(name)

    return ordered


def load_schema_entries(ctx, lifecycle_value):
    """
    Schema format:
    [
      {"field": "alert_event_time", "source": "issue.timestamp", "default": ""},
      {"field": "mitre_tactic_id", "source": "SOCFramework.Mitre.Tactic.ID", "default": ""}
    ]

    Resolution is context-only, same model as SOCFrameworkActions.
    """
    for list_name in get_schema_list_candidates(ctx, lifecycle_value):
        try:
            result = demisto.executeCommand("getList", {"listName": list_name})
            if not result or "Contents" not in result[0]:
                continue

            parsed = _try_json_loads(result[0]["Contents"])
            if isinstance(parsed, list):
                demisto.debug(f"SOCCommandWrapper using schema list: {list_name}")
                return parsed
        except Exception as e:
            demisto.debug(f"SOCCommandWrapper failed loading schema list {list_name}: {str(e)}")

    return None


def default_schema_entries():
    """
    Built-in fallback schema for testing if no list exists yet.
    These resolve from context only. Missing values can be enriched later.
    """
    return [
        {"field": "alert_event_time", "source": "issue.timestamp", "default": ""},
        {"field": "alert_ingest_time", "source": "issue.local_insert_ts", "default": ""},
        {"field": "incident_id", "source": "issue.id", "default": ""},
        {"field": "investigation_id", "source": "issue.parentXDRIncident", "default": ""},
        {"field": "parent_xdr_incident", "source": "parentIncidentFields.incident_id", "default": ""},
        {"field": "lifecycle", "source": "SOCFramework.lifecycle", "default": ""},
        {"field": "lifecycle_version", "source": "SOCFramework.lifecycle_version", "default": ""},
        {"field": "phase", "source": "SOCFramework.phase", "default": ""},
        {"field": "scenario", "source": "SOCFramework.Scenario", "default": ""},
        {"field": "action_actor", "source": "", "default": ""},
        {"field": "mitre_tactic_id", "source": "SOCFramework.Mitre.Tactic.ID", "default": ""},
        {"field": "mitre_tactic", "source": "SOCFramework.Mitre.Tactic.Name", "default": ""},
        {"field": "mitre_technique_id", "source": "SOCFramework.Mitre.Technique.ID", "default": ""},
        {"field": "mitre_technique", "source": "SOCFramework.Mitre.Technique.Name", "default": ""},
        {"field": "mitre_subtechnique_id", "source": "SOCFramework.Mitre.SubTechnique.ID", "default": ""},
        {"field": "mitre_subtechnique", "source": "SOCFramework.Mitre.SubTechnique.Name", "default": ""},
        {"field": "alert_name", "source": "issue.name", "default": ""},
        {"field": "alert_source", "source": "issue.sourceBrand", "default": ""},
        {"field": "alert_category", "source": "SOCFramework.Product.category", "default": ""},
        {"field": "alert_domain", "source": "issue.alert_domain", "default": ""},
        {"field": "severity", "source": "issue.severity", "default": ""},
        {"field": "status", "source": "issue.status", "default": ""},
        {"field": "run_status", "source": "issue.runStatus", "default": ""},
        {"field": "entity_type", "source": "SOCFramework.Primary.EntityType", "default": ""},
        {"field": "entity_value", "source": "SOCFramework.Primary.EntityValue", "default": ""},
        {"field": "playbook_id", "source": "issue.playbookId", "default": ""},
        {"field": "playbook_name", "source": "issue.playbookName", "default": ""},
        {"field": "task_name", "source": "SOCFramework.Task.Name", "default": ""}
    ]


def resolve_schema_payload(schema_entries, ctx):
    payload = {}

    for entry in schema_entries:
        if not isinstance(entry, dict):
            continue

        field = entry.get("field")
        source = entry.get("source")
        default = entry.get("default", "")

        if not field:
            continue

        value = default
        if source:
            resolved = _resolve_ctx_string(source, ctx)
            if resolved not in (None, "", [], {}):
                value = resolved

        payload[field] = value

    return payload


def get_current_incident_id():
    try:
        incidents = demisto.incidents()
        if incidents and isinstance(incidents[0], dict):
            return incidents[0].get("id")
    except Exception:
        pass
    return None


def normalize_getissues_contents(contents):
    """
    Normalize getIssues Contents into a single issue dict.
    """
    if isinstance(contents, str):
        try:
            contents = json.loads(contents)
        except Exception:
            return {}

    if isinstance(contents, list):
        if contents and isinstance(contents[0], dict):
            return contents[0]
        return {}

    if isinstance(contents, dict):
        data = contents.get("data")
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            return data[0]

        issue = contents.get("issue")
        if isinstance(issue, dict):
            return issue

        return contents

    return {}


def get_issue_data():
    issue_id = get_current_incident_id()
    if not issue_id:
        return {}

    try:
        result = demisto.executeCommand("getIssues", {"id": issue_id})
        if not result or not isinstance(result[0], dict):
            return {}

        contents = result[0].get("Contents")
        issue = normalize_getissues_contents(contents)

        demisto.debug(f"SOCCommandWrapper getIssues normalized issue: {json.dumps(issue)[:4000]}")

        return issue if isinstance(issue, dict) else {}

    except Exception as e:
        demisto.debug(f"SOCCommandWrapper getIssues failed: {str(e)}")
        return {}


def set_if_missing(payload, key, value):
    if key not in payload or payload.get(key) in (None, "", [], {}):
        if value not in (None, "", [], {}):
            payload[key] = value


def enrich_payload(payload, ctx, issue, wrapper_values, args):
    """
    Context-only schema first.
    Then inject wrapper/runtime and getIssues-derived values behind the scenes.
    """
    payload["timestamp"] = wrapper_values["timestamp"]
    payload["event_type"] = wrapper_values["event_type"]
    payload["run_id"] = wrapper_values["run_id"]
    payload["universal_command"] = wrapper_values["action"]
    payload["vendor"] = wrapper_values["vendor"]
    payload["vendor_command"] = wrapper_values["command"]
    payload["action_taken"] = wrapper_values["action"]
    payload["action_status"] = wrapper_values["action_status"]
    payload["action_actor"] = wrapper_values["action_actor"]
    payload["execution_mode"] = wrapper_values["execution_mode"]
    payload["shadow_mode_state"] = wrapper_values["shadow_mode_state"]
    payload["action_time_minutes"] = wrapper_values.get("action_time_minutes", 0)
    payload["action_time_category"] = wrapper_values.get("action_time_category", "")
    payload["has_error"] = wrapper_values["has_error"]
    payload["error_type"] = wrapper_values["error_type"]
    payload["error_message"] = wrapper_values["error_message"]
    # Present only when the run fanned out over a list of targets, so each
    # row says which domain, host or user it acted on.
    if wrapper_values.get("action_target") is not None:
        payload["action_target"] = wrapper_values["action_target"]

    set_if_missing(payload, "lifecycle", args.get("LifeCycle"))
    set_if_missing(payload, "lifecycle", demisto.get(ctx, "SOCFramework.lifecycle"))
    set_if_missing(payload, "lifecycle_version", demisto.get(ctx, "SOCFramework.lifecycle_version"))
    set_if_missing(payload, "phase", args.get("Phase"))
    set_if_missing(payload, "phase", demisto.get(ctx, "SOCFramework.phase"))
    set_if_missing(payload, "phase", demisto.get(ctx, "SOCFramework.NISTIR.Phase"))

    if isinstance(issue, dict) and issue:
        event_time = issue.get("timestamp") or issue.get("created") or issue.get("modified")
        ingest_time = issue.get("local_insert_ts") or issue.get("created")

        set_if_missing(payload, "alert_event_time", event_time)
        set_if_missing(payload, "alert_ingest_time", ingest_time)

        set_if_missing(payload, "incident_id", issue.get("id"))
        set_if_missing(payload, "investigation_id", issue.get("investigationId") or issue.get("parentXDRIncident") or issue.get("id"))
        set_if_missing(payload, "parent_xdr_incident", issue.get("parentXDRIncident"))

        set_if_missing(payload, "alert_name", issue.get("name"))
        set_if_missing(payload, "alert_source", issue.get("sourceBrand") or issue.get("sourceInstance") or issue.get("source"))
        set_if_missing(payload, "alert_category",
                       demisto.get(ctx, "SOCFramework.Product.category") or
                       issue.get("categoryname") or
                       issue.get("category"))
        set_if_missing(payload, "alert_domain", issue.get("alert_domain"))

        set_if_missing(payload, "severity", issue.get("severity"))
        set_if_missing(payload, "status", issue.get("custom_status") or issue.get("resolution_status") or issue.get("status"))
        set_if_missing(payload, "run_status", issue.get("runStatus"))

        set_if_missing(payload, "playbook_id", issue.get("playbookId"))
        set_if_missing(payload, "playbook_name", issue.get("playbookName"))

    return payload


def post_dataset_payload(payload, tags=None):
    # A dynamic layout section re-runs on every render, so recording its calls
    # would count opening an issue as acting on it. Layout reads are display
    # only; the value dataset stays limited to executions the framework or an
    # analyst actually performed.
    if payload.get("action_actor") == "layout":
        demisto.debug("Layout-actor call - dataset write skipped.")
        return

    try:
        result = demisto.executeCommand(
            "socfw-post-to-dataset",
            {
                "using": "socfw_ir_execution_writer",
                "JSON": json.dumps(payload)
            }
        )

        failed, error_msg = integration_failed(result)
        if failed:
            warroom_log(
                "SOC Framework - Dataset Post Failure",
                {
                    "error": error_msg,
                    "payload": payload
                },
                tags
            )
        else:
            warroom_log(
                "SOC Framework - Dataset Post Success",
                payload,
                tags
            )

    except Exception as e:
        warroom_log(
            "SOC Framework - Dataset Post Exception",
            {
                "error": str(e),
                "payload": payload
            },
            tags
        )



def _dispatch_one(shared, vendor, vendor_data, command, inline_args, target, terminal):
    """Dispatch one (vendor, target) pair: shadow or execute, record, dataset row.

    Behavior for the terminal case (single vendor, single target — every action
    before dispatch modes existed) is the original main() body unchanged: the
    same war-room entries, the same records, return_error on command failure
    and a bare raise on unexpected exceptions. Non-terminal calls record the
    failure and report it in the dispatch summary instead, so one vendor or
    target cannot kill the rest of the fan-out.

    Returns {"vendor", "target", "outcome", "reason"} with outcome one of
    simulated | success | failed | skipped_no_artifact | integration_unavailable.
    """
    action = shared["action"]
    args = shared["args"]
    ctx = shared["ctx"]
    tags = shared["tags"]
    raw_tags = shared["raw_tags"]
    output_key = shared["output_key"]
    using = shared["using"]
    shadow_mode = shared["shadow_mode"]
    run_id = shared["run_id"]
    timestamp = shared["timestamp"]
    schema_entries = shared["schema_entries"]
    issue = shared["issue"]
    action_time_minutes = shared["action_time_minutes"]
    action_time_category = shared["action_time_category"]

    resolved_payload = {
        "run_id": run_id,
        "action": action,
        "vendor": vendor,
        "command": command,
        "args": inline_args,
        "shadow_mode": shadow_mode,
        "raw_tags": raw_tags,
        "raw_tags_type": str(type(raw_tags)),
        "tags": tags
    }
    if target is not None:
        resolved_payload["target"] = target

    warroom_log(
        "SOC Framework - Universal Command Resolved",
        resolved_payload,
        tags
    )

    if shadow_mode:
        record = {
            "run_id": run_id,
            "action": action,
            "vendor": vendor,
            "command": command,
            "args": inline_args,
            "shadow_mode": True,
            "success": False,
            "tags": tags,
            "timestamp": timestamp
        }
        if target is not None:
            record["target"] = target

        if output_key:
            append_context(output_key, record)

        base_payload = resolve_schema_payload(schema_entries, ctx)

        wrapper_values = {
            "timestamp": timestamp,
            "event_type": "command",
            "run_id": run_id,
            "action": action,
            "vendor": vendor,
            "command": command,
            "action_status": "simulated",
            "action_actor": normalize_action_actor(args.get("Action_Actor"), True),
            "execution_mode": "shadow",
            "shadow_mode_state": "collected",
            # Carried on the row so a dashboard or an export can say what to
            # change, not just that something was suppressed.
            "shadow_disable_hint": shadow_go_live_command(action, args.get("Action_Actor")),
            "has_error": False,
            "error_type": "",
            "error_message": "",
            "action_time_minutes": action_time_minutes,
            "action_time_category": action_time_category
        }
        if target is not None:
            wrapper_values["action_target"] = target

        dataset_payload = enrich_payload(base_payload, ctx, issue, wrapper_values, args)
        post_dataset_payload(dataset_payload, tags)

        # Write sentinel UC.* keys so downstream conditions work in shadow mode
        output_map = vendor_data.get("output_map", {})
        fresh_ctx = demisto.context()
        apply_output_map(output_map, fresh_ctx, shadow_mode=True)

        warroom_log(
            "SOC Framework - SHADOW MODE (Command Not Executed)",
            record,
            tags,
            footer=shadow_footer(action, args.get("Action_Actor"))
        )

        if terminal:
            return_results("Shadow Mode: command not executed")
        return {"vendor": vendor, "target": target, "outcome": "simulated"}

    try:
        warroom_log(
            "SOC Framework - Executing Command",
            {
                "command": command,
                "args": inline_args,
                "using": using
            },
            tags
        )

        # Drop args that failed context resolution — sending empty values
        # to vendor APIs causes 4xx errors (e.g. Proofpoint TAP 400 when
        # threatId/campaignId are present-but-empty).
        execute_args = {
            k: v for k, v in inline_args.items()
            if v not in (None, "", [], {})
        }
        if using:
            execute_args["using"] = using

        # Ask the module registry before dispatching. An unavailable brand is
        # shaped as the error the post-dispatch handler already recognizes, so
        # the outcome, the record and the dataset row are identical to a real
        # error 23 — the only difference is that nothing was called.
        if not brand_available(vendor):
            result = [{
                "Type": entryTypes["error"],
                "ContentsFormat": formats["text"],
                "Contents": (f"Unsupported Command: {command} — no active instance "
                             f"of brand '{vendor}' on this tenant."),
            }]
        else:
            result = demisto.executeCommand(command, execute_args)

        failed, error_msg = integration_failed(result)

        if failed:
            # Check for error 23 — integration not installed or not enabled in this tenant.
            # Soft-fail so the playbook can continue in degraded mode rather than halting
            # the entire lifecycle. Shadow mode never reaches this path (vendor command is
            # suppressed), so this check is execute-only by construction.
            integration_unavailable = (
                    "Unsupported Command" in (error_msg or "")
                    or "(23)" in (error_msg or "")
            )

            record = {
                "run_id": run_id,
                "action": action,
                "vendor": vendor,
                "command": command,
                "args": inline_args,
                "shadow_mode": False,
                "success": False,
                "error": error_msg,
                "tags": tags,
                "timestamp": timestamp
            }
            if target is not None:
                record["target"] = target

            if output_key:
                append_context(output_key, record)

            base_payload = resolve_schema_payload(schema_entries, ctx)

            wrapper_values = {
                "timestamp": timestamp,
                "event_type": "command",
                "run_id": run_id,
                "action": action,
                "vendor": vendor,
                "command": command,
                "action_status": "integration_unavailable" if integration_unavailable else "failed",
                "action_actor": normalize_action_actor(args.get("Action_Actor"), False),
                "execution_mode": "production",
                "shadow_mode_state": "not_applicable",
                "has_error": True,
                "error_type": "integration_unavailable" if integration_unavailable else "command_execution",
                "error_message": error_msg,
                "action_time_minutes": action_time_minutes,
                "action_time_category": action_time_category
            }
            if target is not None:
                wrapper_values["action_target"] = target

            dataset_payload = enrich_payload(base_payload, ctx, issue, wrapper_values, args)
            post_dataset_payload(dataset_payload, tags)

            warroom_log(
                "SOC Framework - Command Failure",
                record,
                tags
            )

            if integration_unavailable:
                # Null out UC.* output keys so downstream conditions evaluate cleanly
                # (missing key → default/blocked path) rather than raising errors
                output_map = vendor_data.get("output_map", {})
                for dest_key in (output_map or {}).keys():
                    demisto.setContext(dest_key, None)

                return_warning(
                    f"[SOCCommandWrapper] Integration not available for action '{action}'. "
                    f"Command: {command}. "
                    f"Install and configure the required integration to enable this action."
                )
                return_results(CommandResults(
                    readable_output=(
                        f"⚠️ Integration unavailable: `{command}`\n\n"
                        f"Action `{action}` requires an integration that is not installed or enabled. "
                        f"Playbook continues in degraded mode."
                    ),
                    outputs_prefix="UC",
                    outputs={"action": action, "status": "integration_unavailable", "command": command}
                ))
                return {"vendor": vendor, "target": target,
                        "outcome": "integration_unavailable", "reason": error_msg}

            if terminal:
                return_error(error_msg)
            return {"vendor": vendor, "target": target,
                    "outcome": "failed", "reason": error_msg}

        record = {
            "run_id": run_id,
            "action": action,
            "vendor": vendor,
            "command": command,
            "args": inline_args,
            "shadow_mode": False,
            "success": True,
            "tags": tags,
            "timestamp": timestamp
        }
        if target is not None:
            record["target"] = target

        if output_key:
            append_context(output_key, record)

        base_payload = resolve_schema_payload(schema_entries, ctx)

        wrapper_values = {
            "timestamp": timestamp,
            "event_type": "command",
            "run_id": run_id,
            "action": action,
            "vendor": vendor,
            "command": command,
            "action_status": "success",
            "action_actor": normalize_action_actor(args.get("Action_Actor"), False),
            "execution_mode": "production",
            "shadow_mode_state": "not_applicable",
            "has_error": False,
            "error_type": "",
            "error_message": "",
            "action_time_minutes": action_time_minutes,
            "action_time_category": action_time_category
        }
        if target is not None:
            wrapper_values["action_target"] = target

        dataset_payload = enrich_payload(base_payload, ctx, issue, wrapper_values, args)
        post_dataset_payload(dataset_payload, tags)

        # Map vendor output to canonical UC.* context keys
        output_map = vendor_data.get("output_map", {})
        fresh_ctx = demisto.context()
        entry_context = _extract_entry_context(result)
        apply_output_map(output_map, fresh_ctx, shadow_mode=False, entry_context=entry_context)

        warroom_log(
            "SOC Framework - Command Success",
            record,
            tags
        )

        return_results(result)
        return {"vendor": vendor, "target": target, "outcome": "success"}

    except Exception as e:
        record = {
            "run_id": run_id,
            "action": action,
            "vendor": vendor,
            "command": command,
            "args": inline_args,
            "shadow_mode": False,
            "success": False,
            "error": str(e),
            "tags": tags,
            "timestamp": timestamp
        }
        if target is not None:
            record["target"] = target

        if output_key:
            append_context(output_key, record)

        try:
            base_payload = resolve_schema_payload(schema_entries, ctx)

            wrapper_values = {
                "timestamp": timestamp,
                "event_type": "command",
                "run_id": run_id,
                "action": action,
                "vendor": vendor,
                "command": command,
                "action_status": "failed",
                "action_actor": normalize_action_actor(args.get("Action_Actor"), False),
                "execution_mode": "production",
                "shadow_mode_state": "not_applicable",
                "has_error": True,
                "error_type": "command_execution",
                "error_message": str(e),
                "action_time_minutes": action_time_minutes,
                "action_time_category": action_time_category
            }
            if target is not None:
                wrapper_values["action_target"] = target

            dataset_payload = enrich_payload(base_payload, ctx, issue, wrapper_values, args)
            post_dataset_payload(dataset_payload, tags)
        except Exception as enrich_e:
            warroom_log(
                "SOC Framework - Dataset Enrichment Error",
                {"error": str(enrich_e)},
                tags
            )

        warroom_log(
            "SOC Framework - Command Execution Error",
            record,
            tags
        )

        if terminal:
            raise
        return {"vendor": vendor, "target": target, "outcome": "failed", "reason": str(e)}


def _dispatch_vendor(shared, vendor, vendor_data, target_arg, single_vendor):
    """Resolve one vendor branch's args and dispatch it once per target.

    target_arg names the inline arg that carries the thing being acted on;
    when its context reference resolves to a list, each usable element gets
    its own dispatch. Scalars behave exactly as before.
    """
    action = shared["action"]
    ctx = shared["ctx"]
    tags = shared["tags"]
    shadow_mode = shared["shadow_mode"]
    output_key = shared["output_key"]

    command = vendor_data.get("command")
    _inline_args_template = vendor_data.get("inline_args", {})
    inline_args = _resolve_templates(_inline_args_template, ctx)

    # Customer-specific values (a block-list ID, a proxy category) come from
    # the tenant config list, keyed by vendor then arg name. They fill
    # only args the registry ships as empty literals - never an arg bound to
    # evidence on the issue - so the registry stays upgradeable and the
    # customer's values survive every pack install.
    for k, v in (shared.get("tenant_config", {}).get(vendor) or {}).items():
        if (k in _inline_args_template and _inline_args_template.get(k) in (None, "")
                and not _is_ctx_template(_inline_args_template.get(k))):
            inline_args[k] = v

    # Guard: the action declares argument templates but every CONTEXT-DERIVED
    # one resolved empty (e.g. soc-enrich-file's sha256=${SOCFramework.Artifacts.Hash}
    # when this alert carries no file hash). Firing a command with a missing required
    # arg fails and hangs the lifecycle, so skip cleanly with a recorded reason --
    # mirroring the Upon-Trigger enrichment, which only fires when the artifact is
    # non-empty.
    #
    # Only context references count toward "is there anything to act on". A static
    # literal carries no evidence, and letting it vote here keeps the dispatch alive
    # after the identifying arg has already been dropped below. Observed on
    # soc-enrich-user/Microsoft Graph User, where properties=displayName,... is static
    # and user=${...Identity.User.UPN} resolved empty: the call fired with only
    # properties, and Graph rejected the malformed path with
    # "Unexpected segment DynamicPathSegment. Expected property/$value".
    _ctx_arg_keys = [
        k for k, raw in _inline_args_template.items() if _is_ctx_template(raw)
    ]
    _empty_ctx_args = [
        k for k in _ctx_arg_keys
        if inline_args.get(k) in (None, "", [], {}, "null", "None")
    ]

    if _ctx_arg_keys and len(_empty_ctx_args) == len(_ctx_arg_keys):
        skip_record = {
            "action": action, "vendor": vendor, "command": command,
            "args": inline_args, "shadow_mode": shadow_mode, "success": False,
            "skipped": True,
            "skip_reason": (
                "no non-empty artifact for command args: "
                + ", ".join(sorted(_empty_ctx_args))
            ),
            "tags": tags or [], "run_id": shared["run_id"],
            "timestamp": shared["timestamp"],
        }
        if output_key:
            append_context(output_key, skip_record)
        warroom_log(
            f"SOC Framework - {action}: skipped (no artifact to act on)",
            {"reason": "all context-derived command args resolved empty",
             "empty_args": ", ".join(sorted(_empty_ctx_args)),
             "action": action, "vendor": vendor, "command": command},
            tags,
        )
        return_results(f"{action} skipped - no non-empty artifact for {command}")
        return [{"vendor": vendor, "target": None,
                 "outcome": "skipped_no_artifact",
                 "reason": "all context-derived command args resolved empty"}]

    # Guard: a response branch may name args that are tenant facts rather than
    # evidence - a block-list ID, a proxy category. Shipped empty, they are set
    # per customer in the tenant config list. Until they are, the branch skips and says
    # which value is missing, in shadow as well, because a simulation without
    # them would show a call that could never succeed.
    _missing_cfg = [
        k for k in (vendor_data.get("required_args") or [])
        if inline_args.get(k) in (None, "", [], {}, "null", "None")
    ]
    if _missing_cfg:
        reason = (
            "not configured: set " + ", ".join(_missing_cfg)
            + f" for {vendor} in {TENANT_CONFIG_LIST}"
        )
        skip_record = {
            "action": action, "vendor": vendor, "command": command,
            "args": inline_args, "shadow_mode": shadow_mode, "success": False,
            "skipped": True, "skip_reason": reason,
            "tags": tags or [], "run_id": shared["run_id"],
            "timestamp": shared["timestamp"],
        }
        if output_key:
            append_context(output_key, skip_record)
        warroom_log(
            f"SOC Framework - {action}: skipped (vendor not configured)",
            {"reason": reason, "action": action, "vendor": vendor, "command": command},
            tags,
        )
        if single_vendor:
            return_results(f"{action} skipped - {reason}")
        return [{"vendor": vendor, "target": None,
                 "outcome": "skipped_not_configured", "reason": reason}]

    # Resolve the target arg's RAW context value. Template resolution above
    # deliberately collapses a leaf list to its first non-empty scalar (the
    # right rule for ordinary args) — which is exactly how multi-value issues
    # lost all but one target. The target arg alone gets the list-preserving
    # walk.
    target_values = None
    if target_arg:
        raw_tmpl = _inline_args_template.get(target_arg)
        if _is_ctx_template(raw_tmpl):
            s = str(raw_tmpl).strip()
            m = CTX_REF_RE.match(s)
            target_values = _resolve_ctx_path_list(ctx, m.group(1) if m else s)
        elif isinstance(inline_args.get(target_arg), list):
            target_values = inline_args.get(target_arg)

    targets = [None]
    if target_arg and isinstance(target_values, list):
        usable, seen = [], set()
        for t in target_values:
            key = str(t)
            if t in (None, "") or key in seen:
                continue
            seen.add(key)
            usable.append(t)
        if not usable:
            skip_record = {
                "action": action, "vendor": vendor, "command": command,
                "args": inline_args, "shadow_mode": shadow_mode, "success": False,
                "skipped": True,
                "skip_reason": f"target list {target_arg} resolved to no usable values",
                "tags": tags or [], "run_id": shared["run_id"],
                "timestamp": shared["timestamp"],
            }
            if output_key:
                append_context(output_key, skip_record)
            warroom_log(
                f"SOC Framework - {action}: skipped (no usable targets)",
                {"reason": f"target list {target_arg} resolved to no usable values",
                 "action": action, "vendor": vendor, "command": command},
                tags,
            )
            return_results(f"{action} skipped - no usable targets for {command}")
            return [{"vendor": vendor, "target": None,
                     "outcome": "skipped_no_artifact",
                     "reason": f"target list {target_arg} resolved to no usable values"}]
        targets = usable

    results = []
    for t in targets:
        call_args = dict(inline_args)
        if t is not None:
            call_args[target_arg] = t
        terminal = single_vendor and len(targets) == 1
        results.append(
            _dispatch_one(shared, vendor, vendor_data, command, call_args, t, terminal)
        )
    return results



def main():
    args = demisto.args()
    ctx = demisto.context()

    demisto.debug(f"RAW TAGS: {args.get('tags')} | TYPE: {type(args.get('tags'))}")

    action = args.get("action")
    using = args.get("using")
    list_name = args.get("list_name")
    output_key = args.get("output_key")
    # shadow_mode is now read from the action entry in SOCFrameworkActions_V3.
    # Analysis/Enrichment: shadow_mode: false — always execute.
    # C/E/R: shadow_mode: true — suppressed until PS flips to false.
    # To go live: edit shadow_mode on the specific action in the list.
    # The args shadow_mode field is retained for backward compat but ignored.

    raw_tags = args.get("tags")
    tags = parse_tags(raw_tags)

    if not action:
        return_error("Missing action")

    if not list_name:
        return_error("Missing list_name")

    list_data = demisto.executeCommand("getList", {"listName": list_name})

    if not list_data or "Contents" not in list_data[0]:
        return_error("Failed to load action list")

    action_map = _try_json_loads(list_data[0]["Contents"])

    if not action_map:
        return_error("Invalid JSON in action list")

    action_entry = action_map.get(action)

    if not action_entry:
        return_error(f"Action not found: {action}")

    # Load action time map — soft fail if list not present or action not listed.
    # SOCActionTimeMap_V3 is customer-editable: one entry per SOC Framework
    # action name with time_minutes and action_category fields.
    # Both values are written to the dataset so dashboards need no join.
    _time_map_result = demisto.executeCommand("getList", {"listName": "SOCActionTimeMap_V3"})
    _time_map: dict = {}
    if _time_map_result and isinstance(_time_map_result, list) and "Contents" in _time_map_result[0]:
        _time_map = _try_json_loads(_time_map_result[0].get("Contents", "")) or {}
    _time_entry = _time_map.get(action, {}) if isinstance(_time_map, dict) else {}
    action_time_minutes = int(_time_entry.get("time_minutes", 0)) if isinstance(_time_entry, dict) else 0
    action_time_category = str(_time_entry.get("action_category", "")) if isinstance(_time_entry, dict) else ""
    demisto.debug(
        f"SOCActionTimeMap_V3: action={action} "
        f"time_minutes={action_time_minutes} "
        f"action_category={action_time_category}"
    )

    # Shadow: the tenant config's setting for this action and actor if it names
    # one, otherwise the shipped action entry.
    tenant_config = load_tenant_config()
    shadow_mode = resolve_shadow_mode(
        action_entry, args.get("Action_Actor"),
        tenant_shadow_override(tenant_config, action, args.get("Action_Actor")))

    responses = action_entry.get("responses", {})

    # ── Dispatch mode ────────────────────────────────────────────────────────
    # dispatch on the action entry decides fan-out. Absent means "routed":
    # exactly one vendor, resolved by the routing ladder below — the original
    # behavior, unchanged. "all_applicable" dispatches every vendor branch the
    # action declares, each checked and recorded on its own; the routing ladder
    # is skipped because the answer is all of them. The field lives on registry
    # rows authored with the framework; it is not an operator setting.
    dispatch_mode = str(action_entry.get("dispatch") or "routed").strip().lower()
    if dispatch_mode not in ("routed", "all_applicable"):
        demisto.debug(
            f"SOCCommandWrapper: unknown dispatch {dispatch_mode!r} on {action} - treating as routed"
        )
        dispatch_mode = "routed"

    vendor = None
    vendor_data = None

    if dispatch_mode == "routed":
        # ── Multi-vendor response routing ─────────────────────────────────────────
        # Resolution order:
        # 1. Look up the action's class (endpoint/identity/email/indicator/network)
        #    from SOCActionClassMap_V3.
        # 2. Look up responses.{class} in the alert's SOCProductCategoryMap entry.
        #    This is the correct integration for this action type on this source.
        # 3. Fall back to SOCFramework.Product.response (legacy single-vendor field).
        # 4. Fall back to first available vendor in the action's responses dict.
        #
        # This allows a CrowdStrike Endpoint alert to use CrowdStrike for endpoint
        # actions but Active Directory for identity actions — configured in one place
        # (SOCProductCategoryMap_V3) without touching playbooks.
        # ─────────────────────────────────────────────────────────────────────────

        vendor = None
        vendor_data = None

        # Step 1: get action class from SOCActionClassMap_V3
        action_class_map = demisto.executeCommand(
            "getList", {"listName": "SOCActionClassMap_V3"}
        )
        action_class = None
        if action_class_map and isinstance(action_class_map, list):
            acm_raw = action_class_map[0].get("Contents", "")
            if acm_raw and acm_raw != "Item not found":
                import json as _json
                try:
                    acm = _json.loads(acm_raw)
                    action_class = acm.get(action)
                except Exception:
                    pass

        # Step 2: look up responses.{action_class} from the category map entry
        if action_class:
            category_responses = demisto.get(ctx, "SOCFramework.Product.responses") or {}
            if isinstance(category_responses, str):
                try:
                    category_responses = _json.loads(category_responses)
                except Exception:
                    category_responses = {}
            class_vendor = category_responses.get(action_class)
            if class_vendor:
                vendor_data = responses.get(class_vendor)
                if vendor_data:
                    vendor = class_vendor
                    demisto.debug(
                        f"SOCCommandWrapper: multi-vendor routing — action={action} "
                        f"class={action_class} vendor={vendor}"
                    )

        # Step 2b: platform actions are not vendor actions.
        #
        # Starring a case, raising its severity and closing an issue are done by the
        # platform itself, so they carry a single "Builtin" implementation and no
        # source vendor can satisfy them. Routing them by vendor skipped them on every
        # alert: soc-star-case was skipped as "no implementation for source vendor
        # 'CrowdStrike Falcon'", and soc-close-issue has the same shape.
        #
        # This is narrow on purpose. It applies ONLY when Builtin is the action's one
        # and only implementation, so there is no vendor ambiguity to resolve wrongly -
        # which is what the "never fall back to first available vendor" rule below
        # exists to prevent. An action with Builtin plus vendor branches still routes
        # by vendor.
        if not vendor_data and set(responses.keys()) == {"Builtin"}:
            vendor_data = responses.get("Builtin")
            if vendor_data:
                vendor = "Builtin"
                demisto.debug(
                    f"SOCCommandWrapper: platform action — action={action} "
                    f"dispatched as Builtin, independent of source vendor"
                )

        # Step 3: fall back to legacy SOCFramework.Product.response
        if not vendor_data:
            vendor = demisto.get(ctx, "SOCFramework.Product.response")
            vendor_data = responses.get(vendor) if vendor else None
            if vendor_data:
                demisto.debug(
                    f"SOCCommandWrapper: legacy response routing — vendor={vendor}"
                )

        # Step 4: no matching vendor — skip cleanly with a recorded reason.
        # Do NOT fall back to "first available vendor": that silently dispatches a
        # non-matching vendor's command (e.g. core-quarantine-files against a
        # CrowdStrike host because soc-quarantine-files lacks a CrowdStrike branch).
        # Instead, write a skipped execution record so SOCSummarizePhase and the
        # case audit trail show the action was attempted but had no vendor
        # implementation for the alert's source.
        if not vendor_data:
            legacy_vendor = demisto.get(ctx, "SOCFramework.Product.response")
            available = sorted(responses.keys())
            skip_reason = (
                f"no implementation for source vendor {legacy_vendor!r} in "
                f"{action}.responses; available: {available}"
            )
            demisto.debug(
                f"SOCCommandWrapper: skipping {action} — {skip_reason} "
                f"(action_class={action_class})"
            )

            skip_record = {
                "action": action,
                "vendor": legacy_vendor or "(unresolved)",
                "command": None,
                "args": {},
                "shadow_mode": shadow_mode,
                "success": False,
                "skipped": True,
                "skip_reason": skip_reason,
                "tags": tags or [],
                "run_id": get_or_create_run_id(ctx),
                "timestamp": utc_now(),
            }
            if output_key:
                append_context(output_key, skip_record)

            warroom_log(
                f"SOC Framework — {action}: skipped (no vendor implementation)",
                {
                    "reason": "no implementation for source vendor",
                    "source_vendor": legacy_vendor or "(unresolved)",
                    "action_class": action_class,
                    "action": action,
                    "available_vendors": available,
                },
                tags,
            )
            return_results(
                f"{action} skipped — no implementation for source vendor "
                f"{legacy_vendor or '(unresolved)'} in this action's responses"
            )
            return

    plan = []
    if dispatch_mode == "all_applicable":
        plan = [(v, responses[v]) for v in sorted(responses)
                if isinstance(responses.get(v), dict)]
        if not plan:
            skip_reason = f"{action} declares dispatch all_applicable but no response branches"
            demisto.debug(f"SOCCommandWrapper: skipping {action} - {skip_reason}")
            skip_record = {
                "action": action, "vendor": "(none)", "command": None, "args": {},
                "shadow_mode": shadow_mode, "success": False, "skipped": True,
                "skip_reason": skip_reason, "tags": tags or [],
                "run_id": get_or_create_run_id(ctx), "timestamp": utc_now(),
            }
            if output_key:
                append_context(output_key, skip_record)
            warroom_log(
                f"SOC Framework - {action}: skipped (no response branches)",
                {"reason": skip_reason, "action": action},
                tags,
            )
            return_results(f"{action} skipped - no response branches declared")
            return
    else:
        plan = [(vendor, vendor_data)]

    # target_arg names the one inline arg that carries the thing being acted
    # on. When its context reference resolves to a list, the wrapper
    # dispatches once per element - one approval upstream still covers the
    # whole run.
    target_arg = action_entry.get("target_arg")

    timestamp = utc_now()
    run_id = get_or_create_run_id(ctx)

    schema_entries = load_schema_entries(ctx, args.get("LifeCycle"))
    if not schema_entries:
        schema_entries = default_schema_entries()

    issue = get_issue_data()

    shared = {
        "action": action, "args": args, "ctx": ctx, "using": using,
        "output_key": output_key, "tags": tags, "raw_tags": raw_tags,
        "shadow_mode": shadow_mode, "run_id": run_id, "timestamp": timestamp,
        "schema_entries": schema_entries, "issue": issue,
        "action_time_minutes": action_time_minutes,
        "action_time_category": action_time_category,
        "tenant_config": tenant_config,
    }

    single_vendor = len(plan) == 1
    outcomes = []
    for pair_vendor, pair_data in plan:
        # Vendors name the same target differently (ioc_domain vs url), so a
        # response branch may carry its own target_arg; the action's is the default.
        pair_target_arg = (pair_data or {}).get("target_arg") or target_arg
        outcomes.extend(
            _dispatch_vendor(shared, pair_vendor, pair_data, pair_target_arg, single_vendor)
        )

    # One summary entry whenever the run fanned out - per-pair entries above
    # carry the detail; this is the at-a-glance line. Legacy single dispatch
    # emits nothing extra, so existing actions read exactly as before.
    if len(outcomes) > 1:
        counts = {}
        for o in outcomes:
            counts[o["outcome"]] = counts.get(o["outcome"], 0) + 1
        warroom_log(
            f"SOC Framework - {action}: dispatch summary",
            {
                "dispatch": dispatch_mode,
                "vendors": sorted({str(o["vendor"]) for o in outcomes}),
                "results": counts,
                "detail": [
                    {k: o.get(k) for k in ("vendor", "target", "outcome", "reason")
                     if o.get(k) is not None}
                    for o in outcomes
                ],
            },
            tags,
        )
        hard_failures = [o for o in outcomes if o["outcome"] == "failed"]
        if hard_failures and len(hard_failures) == len(outcomes):
            return_error(
                f"{action}: every dispatch failed - "
                + "; ".join(
                    f"{o['vendor']}: {o.get('reason', 'error')}" for o in hard_failures
                )
            )
        return_results(
            f"{action}: "
            + ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
        )


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()

