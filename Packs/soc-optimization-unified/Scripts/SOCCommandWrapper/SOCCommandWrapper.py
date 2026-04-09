# Load these for testing, but ignore in operation
# Universal Command allows multiple Vendor commands to be used by a single Universal Command
import demistomock as demisto  # type: ignore
from CommonServerPython import *  # type: ignore

CONSTANT_PACK_VERSION = '3.3.1'
demisto.debug('pack id = soc-optimization-unified, pack version = 3.3.1')

import json
import re
import uuid
from datetime import datetime

CTX_REF_RE = re.compile(r"^\$\{(.+?)\}$")


def utc_now():
    return datetime.utcnow().isoformat() + "Z"


def warroom_log(title, payload, tags=None):
    try:
        entry = {
            "Type": EntryType.NOTE,
            "ContentsFormat": "json",
            "Contents": payload,
            "HumanReadable": f"### {title}\n```json\n{json.dumps(payload, indent=2)}\n```"
        }

        if tags:
            entry["Tags"] = tags

        demisto.results(entry)

    except Exception as e:
        demisto.debug(f"warroom_log failed: {str(e)}")


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
        return demisto.get(ctx, m.group(1))

    if (
            s.startswith("SOCFramework.")
            or s.startswith("incident.")
            or s.startswith("alert.")
            or s.startswith("issue.")
            or s.startswith("parentIncidentFields.")
    ):
        val = demisto.get(ctx, s)
        # Context values are often stored as lists — extract first non-empty element
        if isinstance(val, list):
            val = next((v for v in val if v not in (None, "", [], {})), None)
        return val

    return s


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


def apply_output_map(output_map, ctx, shadow_mode):
    """
    Write UC.* canonical keys from vendor-specific context paths.

    output_map format (defined per vendor response in SOCFrameworkActions_V3):
      { "UC.Email.Forensics.behavior": "Proofpoint.Report.Behavior", ... }

    In shadow mode: writes "shadow_mode" sentinel so downstream conditions
    can use isExists(UC.*) without erroring.

    In execute mode: resolves each source path from context and writes
    to the destination UC.* key. Skips entries where source resolves empty.
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

        value = demisto.get(ctx, base_path)

        if value in (None, "", [], {}):
            demisto.debug(f"apply_output_map: {dest_key} skipped — source {base_path} empty")
            continue

        demisto.setContext(dest_key, value)
        demisto.debug(f"apply_output_map: {dest_key} <- {base_path}")


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


def normalize_action_actor(raw_actor, shadow_mode):
    actor = str(raw_actor or "").strip().lower()

    if shadow_mode and actor in ("", "analyst"):
        return "shadow"

    if actor in ("automation", "analyst", "shadow", "system"):
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
    payload["has_error"] = wrapper_values["has_error"]
    payload["error_type"] = wrapper_values["error_type"]
    payload["error_message"] = wrapper_values["error_message"]

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
    try:
        result = demisto.executeCommand(
            "xql-post-to-dataset",
            {
                "using": "socfw_ir_execution",
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

    # Read shadow_mode from the action entry — single source of truth
    shadow_mode = action_entry.get("shadow_mode", False)
    if not isinstance(shadow_mode, bool):
        shadow_mode = str(shadow_mode).lower() == "true"

    responses = action_entry.get("responses", {})

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

    # Step 3: fall back to legacy SOCFramework.Product.response
    if not vendor_data:
        vendor = demisto.get(ctx, "SOCFramework.Product.response")
        vendor_data = responses.get(vendor) if vendor else None
        if vendor_data:
            demisto.debug(
                f"SOCCommandWrapper: legacy response routing — vendor={vendor}"
            )

    # Step 4: fall back to first available vendor
    if not vendor_data:
        demisto.debug(
            "SOCCommandWrapper: no vendor resolved from category map or legacy response. "
            f"action={action}, action_class={action_class}, "
            f"available={list(responses.keys())}"
        )
        for k, v in responses.items():
            vendor = k
            vendor_data = v
            break

    if not vendor_data:
        return_error("No vendor response defined")

    command = vendor_data.get("command")
    inline_args = vendor_data.get("inline_args", {})
    inline_args = _resolve_templates(inline_args, ctx)

    timestamp = utc_now()
    run_id = get_or_create_run_id(ctx)

    schema_entries = load_schema_entries(ctx, args.get("LifeCycle"))
    if not schema_entries:
        schema_entries = default_schema_entries()

    issue = get_issue_data()

    warroom_log(
        "SOC Framework - Universal Command Resolved",
        {
            "run_id": run_id,
            "action": action,
            "vendor": vendor,
            "command": command,
            "args": inline_args,
            "shadow_mode": shadow_mode,
            "raw_tags": raw_tags,
            "raw_tags_type": str(type(raw_tags)),
            "tags": tags
        },
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
            "has_error": False,
            "error_type": "",
            "error_message": ""
        }

        dataset_payload = enrich_payload(base_payload, ctx, issue, wrapper_values, args)
        post_dataset_payload(dataset_payload, tags)

        # Write sentinel UC.* keys so downstream conditions work in shadow mode
        output_map = vendor_data.get("output_map", {})
        fresh_ctx = demisto.context()
        apply_output_map(output_map, fresh_ctx, shadow_mode=True)

        warroom_log(
            "SOC Framework - SHADOW MODE (Command Not Executed)",
            record,
            tags
        )

        return_results("Shadow Mode: command not executed")
        return

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

        execute_args = dict(inline_args)
        if using:
            execute_args["using"] = using

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
                "error_message": error_msg
            }

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
                return

            return_error(error_msg)

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
            "error_message": ""
        }

        dataset_payload = enrich_payload(base_payload, ctx, issue, wrapper_values, args)
        post_dataset_payload(dataset_payload, tags)

        # Map vendor output to canonical UC.* context keys
        output_map = vendor_data.get("output_map", {})
        fresh_ctx = demisto.context()
        apply_output_map(output_map, fresh_ctx, shadow_mode=False)

        warroom_log(
            "SOC Framework - Command Success",
            record,
            tags
        )

        return_results(result)

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
                "error_message": str(e)
            }

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

        raise


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
