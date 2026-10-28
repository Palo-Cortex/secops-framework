"""Configure the SOC Framework on this tenant.

Writes go to SOCFWTenantConfig, the one list a customer's settings live in. It
is created on the tenant by this script as a JSON list, never shipped in a pack,
so an upgrade cannot overwrite it and shipped lists never need detaching.

Commands
  status   Which mutating actions are live or simulated, per actor, and the exact
           field that decided each one; and which customer values are set.
  shadow   Take one action on or off shadow for named actors, or return it to
           what SOCFrameworkActions_V3 says. Dry run unless apply=yes.
  set      Set one customer value (a block-list id, a proxy category, an
           instance), or remove it with value=default. Dry run unless apply=yes.
  job      Turn a framework JOB's schedule on or off - the only on/off. A JOB
           cannot be turned on until it has an owner. Dry run unless apply=yes.
  owner    Give a framework JOB an owner who is a user on this tenant; the pack
           ships a placeholder. Dry run unless apply=yes.
  emergency
           List the emergency response policies (shipped and this tenant's), or
           edit one by its label, add one, or return one to what shipped with
           enabled=default. Dry run unless apply=yes.

Each command takes only its own arguments; one that belongs to another command
is refused rather than ignored.

Every command returns the same data twice: a War Room table for people and
SOCFWConfig.* context for the PoV harness. contract_version changes when a key
or a value of a key changes meaning.

SOCCommandWrapper reads what this script writes:
  {"shadow": {action: {actor: bool}}}   checked before the action's row
  {vendor: {arg: value}}                fills args the action ships empty
SOCFWEmergencyResponse reads:
  {"emergency": {"policies": {label: {field: value}}}}
"""

import json

CONTRACT_VERSION = 2

ACTIONS_LIST = "SOCFrameworkActions_V3"
TENANT_CONFIG_LIST = "SOCFWTenantConfig"

# The actors the framework passes to the wrapper. Status always shows these;
# any other actor named in the tenant config is shown as well.
ACTORS = ("analyst", "ai", "automation", "issue_emergency")

# Old actor names the wrapper still reads, and what they mean now. Kept in step
# with LEGACY_ACTOR_ALIASES in SOCCommandWrapper.
LEGACY_ACTOR_ALIASES = {"framework": "automation"}

# Actions in these phases only read. They run live and are never shadowed.
READ_ONLY_PHASES = ("enrichment", "investigation")

SHADOW_VALUES = {"on": True, "off": False, "default": None}

DATASET_COMMAND = "socfw-post-to-dataset"
DATASET_INSTANCE = "socfw_ir_execution_writer"

# Where each status cell came from.
# JOBs the framework ships. The pack installs them off; the owner must be a
# user on the customer's tenant or every run errors. The placeholder is treated
# as no owner wherever it appears.
JOBS = ("Auto Triage V3", "SOC Case Analysis")
OWNER_PLACEHOLDER = "set-owner-with-SOCFWConfig"
JOB_VALUES = {"on": True, "off": False}

FROM_TENANT = "tenant_config"          # SOCFWTenantConfig shadow.<action>.<actor>
FROM_ACTOR = "action_actor"            # SOCFrameworkActions_V3 <action>.shadow_mode_by_actor.<actor>
FROM_DEFAULT = "action_default"        # SOCFrameworkActions_V3 <action>.shadow_mode


class ConfigError(Exception):
    pass


# ── Lists ────────────────────────────────────────────────────────────────────

def _read_list(name):
    """(exists, parsed). parsed is None when the content is not a JSON object."""
    res = demisto.executeCommand("getList", {"listName": name})
    entry = res[0] if res and isinstance(res, list) and isinstance(res[0], dict) else {}
    raw = entry.get("Contents")
    # A missing list comes back as an error entry: " - Item not found (8) on list [<name>] (2609)".
    if not raw or "Item not found" in str(raw):
        return False, None
    if entry.get("Type") == 4:
        raise ConfigError(f"could not read {name}: {raw}")
    if isinstance(raw, dict):
        return True, raw
    try:
        parsed = json.loads(raw)
    except Exception:
        return True, None
    return True, parsed if isinstance(parsed, dict) else None


def load_actions():
    exists, actions = _read_list(ACTIONS_LIST)
    if not exists or actions is None:
        raise ConfigError(f"{ACTIONS_LIST} is missing or not valid JSON; "
                          "reinstall soc-optimization-unified")
    return {k: v for k, v in actions.items() if isinstance(v, dict) and "responses" in v}


def load_tenant_config():
    """(config, exists).

    A SOCFWTenantConfig that exists but is not a JSON object is an error rather
    than an empty config: writing over it would destroy whatever is in it.
    """
    exists, cfg = _read_list(TENANT_CONFIG_LIST)
    if exists and cfg is None:
        raise ConfigError(f"{TENANT_CONFIG_LIST} is not a JSON object; fix or empty it "
                          "in Settings > Lists before running SOCFWConfig")
    return (cfg or {}), exists


def write_tenant_config(cfg, exists):
    """Write, then read back: a write that did not land is reported, not assumed.

    A new list is created through the REST API so it is a JSON list; the
    built-in createList always makes a plain-text one. setList keeps the type of
    an existing list.
    """
    data = json.dumps(cfg, indent=2, sort_keys=True)
    if exists:
        how = "setList"
        res = demisto.executeCommand("setList", {"listName": TENANT_CONFIG_LIST, "listData": data})
    else:
        how = "core-api-post /xsoar/public/v1/lists/save"
        body = json.dumps({"name": TENANT_CONFIG_LIST, "data": data, "type": "json"})
        res = demisto.executeCommand("core-api-post", {"uri": "/xsoar/public/v1/lists/save",
                                                       "body": body})
    written_exists, written = _read_list(TENANT_CONFIG_LIST)
    if not written_exists or written != cfg:
        detail = _error_text(res) or "no error returned"
        hint = ("" if exists else "; creating it needs the Core REST API integration, the "
                "same one SOCFWHealthCheck uses")
        raise ConfigError(f"could not write {TENANT_CONFIG_LIST} ({how}: {detail}){hint}")


def _is_error(res):
    return any(isinstance(e, dict) and e.get("Type") == 4 for e in (res or []))


def _error_text(res):
    return "; ".join(str(e.get("Contents")) for e in (res or [])
                     if isinstance(e, dict) and e.get("Type") == 4)


def _record(rows):
    """Post config_change rows to the execution dataset, one object per call.

    No incident_id and no phase: the value dashboards group by incident and pick
    rows by phase, so a configuration change must not land in either. Recording
    never fails the command; the change is already written and read back.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    recorded = bool(rows)
    for row in rows:
        row = dict({"event_type": "config_change", "timestamp": now}, **row)
        try:
            res = demisto.executeCommand(DATASET_COMMAND,
                                         {"using": DATASET_INSTANCE, "JSON": json.dumps(row)})
            recorded = recorded and not _is_error(res)
        except Exception as e:  # noqa: BLE001
            demisto.debug(f"SOCFWConfig: config_change row not recorded: {e}")
            recorded = False
    return recorded


# ── Shadow resolution — the same rules SOCCommandWrapper applies ────────────

def _as_bool(value):
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    return text == "true" if text in ("true", "false") else None


def is_read_only(row):
    return str(row.get("phase") or "").lower() in READ_ONLY_PHASES


def _shadow_actor(actor, named):
    alias = LEGACY_ACTOR_ALIASES.get(actor)
    return alias if alias and actor not in named else actor


def tenant_value(cfg, action, actor):
    section = cfg.get("shadow") if isinstance(cfg, dict) else None
    per_action = section.get(action) if isinstance(section, dict) else None
    if not isinstance(per_action, dict):
        return None
    actor = _shadow_actor(actor, per_action)
    if actor not in per_action:
        return None
    return _as_bool(per_action[actor])


def effective(cfg, action, row, actor):
    """(shadow, decided_by, field) - field is the exact setting that decided it."""
    override = tenant_value(cfg, action, actor)
    if override is not None:
        named = (cfg.get("shadow") or {}).get(action) or {}
        return override, FROM_TENANT, (f"{TENANT_CONFIG_LIST} shadow.{action}."
                                       f"{_shadow_actor(actor, named)}")
    by_actor = row.get("shadow_mode_by_actor")
    if isinstance(by_actor, dict):
        key = _shadow_actor(actor, by_actor)
        if key in by_actor and _as_bool(by_actor[key]) is not None:
            return (_as_bool(by_actor[key]), FROM_ACTOR,
                    f"{ACTIONS_LIST} {action}.shadow_mode_by_actor.{key}")
        if _as_bool(row.get("shadow_mode")) is None:
            # Per-actor row that does not name this actor: simulated.
            return (not is_read_only(row), FROM_DEFAULT,
                    f"{ACTIONS_LIST} {action}.shadow_mode_by_actor.{key} (not named)")
    value = _as_bool(row.get("shadow_mode"))
    if value is None:
        # Same fail-closed rule as the wrapper: missing or unreadable means
        # simulated for anything that can change something.
        return (not is_read_only(row), FROM_DEFAULT,
                f"{ACTIONS_LIST} {action}.shadow_mode (missing or unreadable)")
    return value, FROM_DEFAULT, f"{ACTIONS_LIST} {action}.shadow_mode"


def _state(shadow):
    return "shadow" if shadow else "live"


MARK = {FROM_TENANT: " ✱", FROM_ACTOR: "", FROM_DEFAULT: " †"}


# ── Customer values — the args the wrapper fills from the tenant config ─────

def value_slots(actions):
    """{(vendor, arg): {"used_by": [...], "required": bool}}.

    A slot is an arg a shipped response leaves empty for the customer to fill,
    which is exactly what SOCCommandWrapper fills from the tenant config.
    required means some action skips without it.
    """
    slots = {}
    for name, row in actions.items():
        for vendor, binding in (row.get("responses") or {}).items():
            if not isinstance(binding, dict):
                continue
            required = set(binding.get("required_args") or [])
            for arg, template in (binding.get("inline_args") or {}).items():
                if template in (None, ""):
                    slot = slots.setdefault((vendor, arg), {"used_by": [], "required": False})
                    slot["used_by"].append(name)
                    slot["required"] = slot["required"] or arg in required
    for slot in slots.values():
        slot["used_by"] = sorted(set(slot["used_by"]))
    return slots


def _current_value(cfg, vendor, arg):
    per_vendor = cfg.get(vendor)
    return per_vendor.get(arg) if isinstance(per_vendor, dict) else None


# ── status ───────────────────────────────────────────────────────────────────

def status(args):
    actions = load_actions()
    cfg, exists = load_tenant_config()

    wanted = _split(args.get("action"))
    unknown = [a for a in wanted if a not in actions]
    if unknown:
        raise ConfigError(f"unknown action {', '.join(unknown)}; run !SOCFWConfig "
                          "command=status to list them")

    named = set()
    section = cfg.get("shadow")
    if isinstance(section, dict):
        for per_action in section.values():
            if isinstance(per_action, dict):
                named |= {_shadow_actor(str(a).lower(), {}) for a in per_action}
    actors = list(ACTORS) + sorted(named - set(ACTORS))

    rows, table, read_only = [], [], 0
    for name in sorted(actions):
        row = actions[name]
        ro = is_read_only(row)
        read_only += ro
        if wanted:
            if name not in wanted:
                continue
        elif ro:
            continue
        cells = []
        for actor in actors:
            shadow, decided_by, field = effective(cfg, name, row, actor)
            rows.append({"action": name, "actor": actor, "shadow": shadow,
                         "state": _state(shadow), "decided_by": decided_by,
                         "field": field, "read_only": ro})
            cells.append(_state(shadow) + MARK[decided_by])
        table.append([name] + cells)

    values = []
    for (vendor, arg), slot in sorted(value_slots(actions).items()):
        current = _current_value(cfg, vendor, arg)
        values.append({"vendor": vendor, "arg": arg, "value": current,
                       "set": current not in (None, ""), "required": slot["required"],
                       "used_by": slot["used_by"]})

    outputs = {"contract_version": CONTRACT_VERSION, "command": "status",
               "tenant_config_list": TENANT_CONFIG_LIST, "tenant_config_exists": exists,
               "actors": actors, "rows": rows, "values": values}

    md = ["### SOC Framework — live or simulated, by actor", "",
          "| Action | " + " | ".join(actors) + " |",
          "|---|" + "---|" * len(actors)]
    md += ["| " + " | ".join(r) + " |" for r in table]
    md += ["",
           f"✱ `{TENANT_CONFIG_LIST}` → `shadow.<action>.<actor>`",
           f"(no mark) `{ACTIONS_LIST}` → `<action>.shadow_mode_by_actor.<actor>`",
           f"† `{ACTIONS_LIST}` → `<action>.shadow_mode`, one setting for every actor"]
    if not wanted:
        md.append(f"{read_only} read-only actions (enrichment, investigation) always run "
                  "live and are not listed.")
    md += ["", "Change one: `!SOCFWConfig command=shadow action=<action> actor=<actor> "
               "value=on|off|default` — add `apply=yes` to write."]

    md += ["", f"### Customer values in {TENANT_CONFIG_LIST}", "",
           "| Vendor | Setting | Value | Used by |", "|---|---|---|---|"]
    for v in values:
        shown = (f"`{v['value']}`" if v["set"]
                 else ("**missing** — required" if v["required"] else "not set (optional)"))
        md.append(f"| {v['vendor']} | {v['arg']} | {shown} | {', '.join(v['used_by'])} |")
    md += ["", "Set one: `!SOCFWConfig command=set vendor=<vendor> arg=<setting> "
               "value=<value>` — add `apply=yes` to write."]
    if not exists:
        md += ["", f"{TENANT_CONFIG_LIST} does not exist yet; the first `apply=yes` creates it."]

    outputs["jobs"], job_md = _job_status()
    md += job_md
    try:
        section = load_emergency_section()
        policies = merge_policies(section, cfg)
        local = sum(1 for p in policies if p.get("origin") != "shipped")
        outputs["emergency"] = {"enabled": section.get("enabled") is True,
                                "policies": len(policies), "tenant_policies": local}
        md += ["", "### Emergency response", "",
               f"{'On' if section.get('enabled') is True else 'Off'}: {len(policies)} policies, "
               f"{local} edited or added on this tenant. See them: `!SOCFWConfig command=emergency`"]
    except ConfigError as e:
        md += ["", f"Emergency response policies unreadable: {e}"]
    return CommandResults(readable_output="\n".join(md), outputs_prefix="SOCFWConfig.Status",
                          outputs=outputs)


# ── shadow ───────────────────────────────────────────────────────────────────

def shadow(args):
    actions = load_actions()
    action = str(args.get("action") or "").strip()
    actors = [a.lower() for a in _split(args.get("actor"))]
    value = str(args.get("value") or "").strip().lower()
    apply = _yes(args.get("apply"))

    if not action:
        raise ConfigError("action is required, e.g. action=soc-star-case")
    if action not in actions:
        raise ConfigError(f"unknown action {action}; run !SOCFWConfig command=status to list them")
    if value not in SHADOW_VALUES:
        raise ConfigError("value must be on, off or default")
    if not actors:
        raise ConfigError("actor is required: one or more of " + ", ".join(ACTORS))
    renamed = [f"{a} is now {LEGACY_ACTOR_ALIASES[a]}" for a in actors if a in LEGACY_ACTOR_ALIASES]
    if renamed:
        raise ConfigError("; ".join(renamed) + " - use that name instead")
    valid_actors = set(ACTORS)
    for r in actions.values():
        valid_actors |= {str(a).lower() for a in (r.get("shadow_mode_by_actor") or {})}
    valid_actors -= set(LEGACY_ACTOR_ALIASES)
    unknown = [a for a in actors if a not in valid_actors]
    if unknown:
        raise ConfigError(f"unknown actor {', '.join(unknown)}; use one or more of "
                          + ", ".join(ACTORS))

    row = actions[action]
    outputs = {"contract_version": CONTRACT_VERSION, "command": "shadow",
               "dry_run": not apply, "applied": False, "action": action, "value": value,
               "changes": [], "refused": [], "tenant_config_list": TENANT_CONFIG_LIST,
               "creates_list": False, "recorded": False,
               "apply_command": (f"!SOCFWConfig command=shadow action={action} "
                                 f"actor={','.join(actors)} value={value} apply=yes")}

    if is_read_only(row):
        outputs["refused"].append({
            "action": action,
            "reason": f"read-only action (phase {row.get('phase')}); it always runs live "
                      "and is never shadowed"})
        return _shadow_result(outputs)

    cfg, exists = load_tenant_config()
    new_cfg = json.loads(json.dumps(cfg))
    section = new_cfg.setdefault("shadow", {})
    if not isinstance(section, dict):
        raise ConfigError(f"'shadow' in {TENANT_CONFIG_LIST} is not an object; fix it in "
                          "Settings > Lists")
    per_action = section.setdefault(action, {})
    if not isinstance(per_action, dict):
        raise ConfigError(f"'shadow.{action}' in {TENANT_CONFIG_LIST} is not an object; fix it "
                          "in Settings > Lists")

    for actor in actors:
        before, before_by, before_field = effective(cfg, action, row, actor)
        if SHADOW_VALUES[value] is None:
            per_action.pop(actor, None)
        else:
            per_action[actor] = SHADOW_VALUES[value]
        after, after_by, after_field = effective(new_cfg, action, row, actor)
        outputs["changes"].append({
            "actor": actor, "from": _state(before), "to": _state(after),
            "decided_by_before": before_by, "decided_by_after": after_by,
            "field_after": after_field,
            "changed": (before, before_by) != (after, after_by)})

    if not per_action:
        section.pop(action, None)
    if not section:
        new_cfg.pop("shadow", None)

    if not any(c["changed"] for c in outputs["changes"]):
        return _shadow_result(outputs)

    outputs["creates_list"] = not exists
    if apply:
        write_tenant_config(new_cfg, exists)
        outputs["applied"] = True
        outputs["recorded"] = _record([
            {"universal_command": action, "action_actor": c["actor"],
             "shadow_mode_state": c["to"], "action_status": f"set {value}",
             "action_taken": f"{c['from']} -> {c['to']}"}
            for c in outputs["changes"] if c["changed"]])
    return _shadow_result(outputs)


def _shadow_result(o):
    md = []
    if o["refused"]:
        md.append(f"### {o['action']}: not changed")
        md += [f"- {r['reason']}" for r in o["refused"]]
    elif not any(c["changed"] for c in o["changes"]):
        md.append(f"### {o['action']}: already set — nothing to change")
    else:
        md.append(f"### {o['action']}: " + ("applied" if o["applied"]
                                             else "dry run, nothing written"))
    if o["changes"]:
        md += ["", "| Actor | Now | After | Decided by |", "|---|---|---|---|"]
        for c in o["changes"]:
            after = c["to"] + ("" if c["changed"] else " (unchanged)")
            md.append(f"| {c['actor']} | {c['from']} | {after} | `{c['field_after']}` |")
    md += _write_notes(o)
    return CommandResults(readable_output="\n".join(md), outputs_prefix="SOCFWConfig.Shadow",
                          outputs=o)


# ── set ──────────────────────────────────────────────────────────────────────

def set_value(args):
    actions = load_actions()
    vendor_arg = str(args.get("vendor") or "").strip()
    arg_arg = str(args.get("arg") or "").strip()
    raw_value = args.get("value")
    value = "" if raw_value is None else str(raw_value).strip()
    apply = _yes(args.get("apply"))

    slots = value_slots(actions)
    valid = ", ".join(f"{v} {a}" for v, a in sorted(slots))
    if not vendor_arg or not arg_arg:
        raise ConfigError(f"vendor and arg are required; settable values: {valid}")
    match = [(v, a) for v, a in slots
             if v.lower() == vendor_arg.lower() and a.lower() == arg_arg.lower()]
    if not match:
        raise ConfigError(f"{vendor_arg} {arg_arg} is not a customer value any action uses; "
                          f"settable values: {valid}")
    vendor, arg = match[0]
    if value == "":
        raise ConfigError("value is required; use value=default to remove the setting")
    remove = value.lower() == "default"

    cfg, exists = load_tenant_config()
    if vendor in cfg and not isinstance(cfg[vendor], dict):
        raise ConfigError(f"'{vendor}' in {TENANT_CONFIG_LIST} is not an object; fix it in "
                          "Settings > Lists")
    before = _current_value(cfg, vendor, arg)
    new_cfg = json.loads(json.dumps(cfg))
    per_vendor = new_cfg.setdefault(vendor, {})
    if remove:
        per_vendor.pop(arg, None)
        if not per_vendor:
            new_cfg.pop(vendor, None)
    else:
        per_vendor[arg] = value
    after = _current_value(new_cfg, vendor, arg)

    slot = slots[(vendor, arg)]
    outputs = {"contract_version": CONTRACT_VERSION, "command": "set",
               "dry_run": not apply, "applied": False, "vendor": vendor, "arg": arg,
               "from": before, "to": after, "changed": before != after,
               "required": slot["required"], "used_by": slot["used_by"],
               "tenant_config_list": TENANT_CONFIG_LIST, "creates_list": False,
               "recorded": False,
               "apply_command": f"!SOCFWConfig command=set vendor={vendor} arg={arg} "
                                f"value={value} apply=yes"}

    if outputs["changed"]:
        outputs["creates_list"] = not exists
        if apply:
            write_tenant_config(new_cfg, exists)
            outputs["applied"] = True
            outputs["recorded"] = _record([{
                "vendor": vendor, "action_status": f"set {arg}",
                "action_taken": f"{arg}: {_plain(before)} -> {_plain(after)}"}])

    md = []
    if not outputs["changed"]:
        md.append(f"### {vendor} {arg}: already set — nothing to change")
    else:
        md.append(f"### {vendor} {arg}: " + ("applied" if outputs["applied"]
                                              else "dry run, nothing written"))
    md += ["", "| Now | After | Used by |", "|---|---|---|",
           f"| {_shown(before)} | {_shown(after)} | {', '.join(slot['used_by'])} |"]
    if remove and slot["required"] and outputs["changed"]:
        md += ["", f"Without it, {', '.join(slot['used_by'])} skip for {vendor} with "
                   "\"not configured\"."]
    md += _write_notes(outputs)
    return CommandResults(readable_output="\n".join(md), outputs_prefix="SOCFWConfig.Set",
                          outputs=outputs)


# ── job ──────────────────────────────────────────────────────────────────────

def _core_api(uri, body):
    """POST through the Core REST API integration; the response object, or ConfigError."""
    res = demisto.executeCommand("core-api-post", {"uri": uri, "body": json.dumps(body)})
    if _is_error(res):
        raise ConfigError(f"{uri} failed ({_error_text(res)}); jobs are read and written through "
                          "the Core REST API integration, the same one SOCFWHealthCheck uses")
    for e in res or []:
        contents = e.get("Contents") if isinstance(e, dict) else None
        if isinstance(contents, dict) and "response" in contents:
            return contents["response"]
    raise ConfigError(f"{uri} returned nothing readable")


def load_jobs():
    """The framework JOBs on this tenant, by name."""
    found = _core_api("/xsoar/public/v1/jobs/search", {"page": 0, "size": 200})
    data = found.get("data") if isinstance(found, dict) else found
    return {j.get("name"): j for j in (data or []) if isinstance(j, dict) and j.get("name") in JOBS}


def load_users():
    """Lowercased usernames and emails of the tenant's users, or None if unreadable."""
    try:
        res = demisto.executeCommand("getUsers", {})
    except Exception as e:  # noqa: BLE001
        demisto.debug(f"SOCFWConfig: getUsers failed: {e}")
        return None
    if _is_error(res):
        return None
    users, readable = set(), False
    for e in res or []:
        if not isinstance(e, dict):
            continue
        found = []
        if isinstance(e.get("Contents"), list):
            found = e["Contents"]
        else:
            for value in (e.get("EntryContext") or {}).values():
                found += value if isinstance(value, list) else [value]
        for u in found:
            if isinstance(u, dict):
                readable = True
                for key in ("username", "email", "id"):
                    if u.get(key):
                        users.add(str(u[key]).strip().lower())
    return users if readable else None


def _owner_ok(owner, users):
    """True a user, False not one, None when the user list could not be read."""
    if not owner or owner == OWNER_PLACEHOLDER:
        return False
    return None if users is None else owner.strip().lower() in users


def _on_off(scheduled):
    return "on" if scheduled else "off"


def _job_status():
    """Rows and table for status. Unreadable jobs are reported, never fatal."""
    md = ["", "### Framework JOBs", ""]
    try:
        jobs = load_jobs()
    except ConfigError as e:
        return [], md + [f"Could not read the jobs: {e}"]
    users = load_users()
    rows = []
    md += ["| Job | Schedule | Owner | Owner is a user | Next run |", "|---|---|---|---|---|"]
    for name in JOBS:
        j = jobs.get(name)
        if not j:
            rows.append({"job": name, "installed": False})
            md.append(f"| {name} | not installed | | | |")
            continue
        ok = _owner_ok(j.get("owner"), users)
        rows.append({"job": name, "installed": True, "scheduled": bool(j.get("scheduled")),
                     "owner": j.get("owner"), "owner_is_user": ok,
                     "next_run": j.get("nextRunTime") if j.get("scheduled") else None})
        md.append(f"| {name} | {_on_off(j.get('scheduled'))} | {_shown(j.get('owner'))} | "
                  f"{ {True: 'yes', False: '**no**', None: 'unknown'}[ok] } | "
                  f"{(j.get('nextRunTime') or '') if j.get('scheduled') else ''} |")
    md += ["", 'Owner: `!SOCFWConfig command=owner job="<job>" owner=<user>`; on or off: '
               '`!SOCFWConfig command=job job="<job>" value=on|off` — add `apply=yes` to write.']
    return rows, md


def _pick_job(args):
    name = str(args.get("job") or "").strip()
    match = [j for j in JOBS if j.lower() == name.lower()]
    if not match:
        raise ConfigError("job is required: one of " + ", ".join(JOBS))
    current = load_jobs().get(match[0])
    if not current:
        raise ConfigError(f"{match[0]} is not on this tenant; install soc-optimization-unified")
    return match[0], current


def _owner_command(name):
    return f'!SOCFWConfig command=owner job="{name}" owner=<user>'


def job(args):
    """Turn a framework JOB's schedule on or off. The owner is set by command=owner."""
    if str(args.get("owner") or "").strip():
        raise ConfigError("job turns the schedule on or off; set the owner with "
                          + _owner_command(str(args.get("job") or "<job>").strip()))
    value = str(args.get("value") or "").strip().lower()
    if value not in JOB_VALUES:
        raise ConfigError("value must be on or off")
    name, current = _pick_job(args)
    owner = current.get("owner") or ""
    before, after = bool(current.get("scheduled")), JOB_VALUES[value]
    if after and _owner_ok(owner, load_users()) is False:
        # Verified on deathstar 27 Oct 2026: the platform accepts it, then every run errors.
        raise ConfigError(f"{name} cannot run without an owner who is a user on this tenant "
                          f"(now {_plain(owner)}); set one first: {_owner_command(name)}")
    change = f"schedule: {_on_off(before)} -> {_on_off(after)}" if before != after else ""
    return _write_job(name, current, dict(current, scheduled=after), change,
                      f'!SOCFWConfig command=job job="{name}" value={value} apply=yes', args)


def owner(args):
    """Give a framework JOB an owner who is a user on this tenant. The schedule is unchanged."""
    who = str(args.get("owner") or "").strip()
    if not who:
        raise ConfigError("owner is required: an email or username on this tenant")
    name, current = _pick_job(args)
    ok = _owner_ok(who, load_users())
    if ok is None:
        raise ConfigError("could not read the tenant's users (getUsers) to check the owner")
    if not ok:
        raise ConfigError(f"{who} is not a user on this tenant; the owner must be one")
    before = current.get("owner") or ""
    change = f"owner: {_plain(before)} -> {who}" if before != who else ""
    return _write_job(name, current, dict(current, owner=who), change,
                      f'!SOCFWConfig command=owner job="{name}" owner={who} apply=yes', args)


def _write_job(name, current, updated, change, apply_cmd, args):
    """Dry run unless apply=yes; write, read back, record. Shared by job and owner."""
    apply = _yes(args.get("apply"))
    before = {"owner": current.get("owner") or "", "scheduled": bool(current.get("scheduled"))}
    after = {"owner": updated.get("owner") or "", "scheduled": bool(updated.get("scheduled"))}
    command = str(args.get("command") or "").strip().lower()
    outputs = {"contract_version": CONTRACT_VERSION, "command": command, "job": name,
               "dry_run": not apply, "applied": False, "changed": bool(change),
               "from": before, "to": after, "recorded": False, "apply_command": apply_cmd}
    if change and apply:
        _core_api("/xsoar/public/v1/jobs", updated)
        back = load_jobs().get(name) or {}
        landed = {"owner": back.get("owner") or "", "scheduled": bool(back.get("scheduled"))}
        if landed != after:
            raise ConfigError(f"{name} did not change on the tenant (read back owner "
                              f"{_plain(landed['owner'])}, schedule {_on_off(landed['scheduled'])})")
        outputs["applied"] = True
        outputs["next_run"] = back.get("nextRunTime") if after["scheduled"] else None
        outputs["recorded"] = _record([{"vendor": "SOCFramework", "job": name,
                                        "action_status": command,
                                        "action_taken": f"{name}: {change}"}])
    md = [f"### {name}: " + ("nothing to change" if not change
                             else "applied" if outputs["applied"] else "dry run, nothing written"),
          "", "| | Now | After |", "|---|---|---|",
          f"| Owner | {_shown(before['owner'])} | {_shown(after['owner'])} |",
          f"| Schedule | {_on_off(before['scheduled'])} | {_on_off(after['scheduled'])} |"]
    if outputs.get("next_run"):
        md += ["", f"Next run: {outputs['next_run']}"]
    if after["scheduled"] is False and _owner_ok(after["owner"], None) is False:
        md += ["", f"Before turning it on, set an owner: `{_owner_command(name)}`"]
    md += _write_notes(outputs)
    return CommandResults(readable_output="\n".join(md), outputs_prefix="SOCFWConfig.Job",
                          outputs=outputs)


def _plain(value):
    return str(value) if value not in (None, "") else "(not set)"


def _shown(value):
    return f"`{value}`" if value not in (None, "") else "(not set)"


def _write_notes(o):
    changed = o["changed"] if "changed" in o else any(c["changed"] for c in o.get("changes", []))
    md = []
    if o.get("creates_list") and changed:
        md += ["", ("Created " if o["applied"] else "Will create ")
               + f"{o['tenant_config_list']} as a JSON list."]
    if o["applied"] and not o["recorded"]:
        md += ["", "The change is written, but its record in the execution dataset was not "
                   "(check the socfw_ir_execution_writer instance)."]
    if o["dry_run"] and changed:
        md += ["", f"To write it: `{o['apply_command']}`"]
    return md


# ── emergency ────────────────────────────────────────────────────────────────

POLICY_LIST = "SOCFrameworkPhasePolicy_V3"
EMERGENCY_ACTOR = "issue_emergency"
# Fields a policy can carry, in the order they are shown. Comma lists except
# confidence (a floor). about, source, rule_id and name_contains say which issues;
# verdict, confidence and exposure are the assessment gate.
EMERGENCY_FIELDS = ("about", "source", "rule_id", "name_contains",
                    "verdict", "confidence", "exposure", "actions")
SUBJECT_FIELDS = ("about", "source", "rule_id", "name_contains")
VERDICTS = ("malicious", "suspicious", "benign", "inconclusive", "any")
CONFIDENCES = ("low", "medium", "high", "any")
EXPOSURES = ("none", "attempted", "delivered", "executed", "unknown", "any")
ENABLED_VALUES = {"on": True, "off": False, "default": None}


def merge_policies(section, tenant_cfg):
    """Shipped policies edited by the tenant's, then the tenant's own, in order.

    The same merge SOCFWEmergencyResponse applies; a test holds the two to each other.
    """
    tenant = ((tenant_cfg or {}).get("emergency") or {}).get("policies") or {}
    if not isinstance(tenant, dict):
        tenant = {}
    out, seen = [], set()
    for p in (section or {}).get("policies") or []:
        if not isinstance(p, dict) or not p.get("policy"):
            continue
        name = p["policy"]
        merged = dict(p)
        edit = tenant.get(name)
        if isinstance(edit, dict):
            merged.update({k: v for k, v in edit.items() if k != "policy"})
            merged["origin"] = "shipped, edited on this tenant"
        else:
            merged["origin"] = "shipped"
        out.append(merged)
        seen.add(name)
    for name, p in tenant.items():
        if name in seen or not isinstance(p, dict):
            continue
        out.append(dict(p, policy=name, origin="this tenant"))
    return out


def load_emergency_section():
    exists, doc = _read_list(POLICY_LIST)
    if not exists or doc is None:
        raise ConfigError(f"{POLICY_LIST} is missing or not valid JSON; "
                          "reinstall soc-optimization-unified")
    return ((doc.get("phases") or {}).get("triage") or {}).get("emergency") or {}


def _policy_on(p):
    return not (p.get("enabled") is False or str(p.get("enabled")).strip().lower() == "false")


def _gate(p):
    verdict = "/".join(_split(p.get("verdict")) or ["malicious"])
    confidence = str(p.get("confidence") or "high")
    gate = [f"verdict {verdict}"]
    if confidence != "any":
        gate.append(f"{confidence}+ confidence")
    if _split(p.get("exposure")):
        gate.append("exposure " + "/".join(_split(p.get("exposure"))))
    return ", ".join(gate)


def _subject(p):
    parts = []
    for field in SUBJECT_FIELDS:
        values = _split(p.get(field))
        if values:
            parts.append(f"{field} {', '.join(values)}")
    return "; ".join(parts) or "**nothing - never fires**"


def _name_only(p):
    return bool(_split(p.get("name_contains"))) and not any(
        _split(p.get(f)) for f in ("about", "source", "rule_id"))


def _policy_view(p, actions, cfg):
    acts = []
    for a in _split(p.get("actions")):
        row = actions.get(a)
        state = "unknown action" if row is None else _state(effective(cfg, a, row, EMERGENCY_ACTOR)[0])
        acts.append({"action": a, "state": state})
    view = {f: p.get(f) for f in EMERGENCY_FIELDS
            if f != "actions" and p.get(f) not in (None, "", [])}
    view.update({"policy": p.get("policy"), "origin": p.get("origin"), "on": _policy_on(p),
                 "subject": _subject(p), "gate": _gate(p), "actions": acts,
                 "name_only": _name_only(p)})
    return view


def _emergency_table(views):
    md = ["| Policy | | Which issues | Gate | Actions (for issue_emergency) | From |",
          "|---|---|---|---|---|---|"]
    for v in views:
        acts = ", ".join(f"{a['action']} ({a['state']})" for a in v["actions"]) or "none"
        flag = " ⚠ name only" if v["name_only"] else ""
        md.append(f"| {v['policy']} | {'on' if v['on'] else 'off'} | {v['subject']}{flag} | "
                  f"{v['gate']} | {acts} | {v['origin']} |")
    return md


def _edit_from_args(args, actions, shipped):
    """The fields this command sets on the policy, validated."""
    edit = {}
    for field in ("about", "source"):
        if _split(args.get(field)):
            edit[field] = [v.lower() for v in _split(args.get(field))]
    for field in ("rule_id", "name_contains"):
        if _split(args.get(field)):
            if shipped:
                raise ConfigError(f"{field} belongs on a policy of this tenant's own, not on the "
                                  f"shipped {args.get('policy')}: rule ids are local to a tenant "
                                  "and names change. Give the new policy its own label.")
            edit[field] = _split(args.get(field))
    for field, allowed in (("verdict", VERDICTS), ("exposure", EXPOSURES)):
        values = [v.lower() for v in _split(args.get(field))]
        bad = [v for v in values if v not in allowed]
        if bad:
            raise ConfigError(f"{field} {', '.join(bad)} is not one of " + ", ".join(allowed))
        if values:
            edit[field] = values
    confidence = str(args.get("confidence") or "").strip().lower()
    if confidence:
        if confidence not in CONFIDENCES:
            raise ConfigError("confidence must be one of " + ", ".join(CONFIDENCES))
        edit["confidence"] = confidence
    wanted = _split(args.get("action"))
    if wanted:
        unknown = [a for a in wanted if a not in actions]
        if unknown:
            raise ConfigError(f"unknown action {', '.join(unknown)}; run !SOCFWConfig "
                              "command=status to list them")
        read_only = [a for a in wanted if is_read_only(actions[a])]
        if read_only:
            raise ConfigError(f"{', '.join(read_only)} only read; an emergency policy runs "
                              "actions that contain or eradicate")
        edit["actions"] = wanted
    enabled = str(args.get("enabled") or "").strip().lower()
    if enabled:
        if enabled not in ENABLED_VALUES:
            raise ConfigError("enabled must be on, off or default")
        if ENABLED_VALUES[enabled] is not None:
            edit["enabled"] = ENABLED_VALUES[enabled]
    return edit


def emergency(args):
    actions = load_actions()
    section = load_emergency_section()
    cfg, exists = load_tenant_config()
    label = str(args.get("policy") or "").strip()
    apply = _yes(args.get("apply"))
    shipped_names = [p.get("policy") for p in (section.get("policies") or []) if isinstance(p, dict)]

    if not label:
        if any(str(args.get(f) or "").strip() for f in
               ("about", "source", "rule_id", "name_contains", "verdict", "confidence",
                "exposure", "action", "enabled")):
            raise ConfigError("policy is required to change one: the label of a shipped policy "
                              f"({', '.join(shipped_names)}) or a new one")
        views = [_policy_view(p, actions, cfg) for p in merge_policies(section, cfg)]
        on = section.get("enabled") is True
        md = ["### Emergency response policies", "",
              f"Issue-level response is **{'on' if on else 'off'}** in `{POLICY_LIST}` → "
              "`phases.triage.emergency.enabled`. Each action's state is what the wrapper "
              "does for `issue_emergency`; shadow records what would have happened.", ""]
        md += _emergency_table(views)
        md += ["", "Every policy that matches fires; each action runs once. The issue is closed "
                   "as true positive, contained only when every action really ran.",
               "", "Edit or add: `!SOCFWConfig command=emergency policy=<label> ...` — "
                   "add `apply=yes` to write. Back to shipped: `enabled=default`."]
        if any(v["name_only"] for v in views):
            md += ["", "⚠ name only: matches on the issue name alone, so it depends on how "
                       "the detection is named. Prefer rule_id where the issue has one."]
        return CommandResults(readable_output="\n".join(md),
                              outputs_prefix="SOCFWConfig.Emergency",
                              outputs={"contract_version": CONTRACT_VERSION, "command": "emergency",
                                       "enabled": on, "policies": views})

    shipped = label in shipped_names
    enabled = str(args.get("enabled") or "").strip().lower()
    edit = _edit_from_args(args, actions, shipped)
    reset = enabled == "default"
    if reset and edit:
        raise ConfigError("enabled=default returns the policy to what shipped (or removes "
                          "this tenant's own); give it on its own")

    new_cfg = json.loads(json.dumps(cfg))
    em = new_cfg.setdefault("emergency", {})
    if not isinstance(em, dict) or not isinstance(em.setdefault("policies", {}), dict):
        raise ConfigError(f"'emergency' in {TENANT_CONFIG_LIST} is not an object; fix it in "
                          "Settings > Lists")
    tenant = em["policies"]
    before = tenant.get(label)
    if reset:
        tenant.pop(label, None)
    elif edit:
        merged = dict(before or {}, **edit)
        if not shipped:
            if not any(_split(merged.get(f)) for f in SUBJECT_FIELDS):
                raise ConfigError(f"{label} is a new policy and needs at least one of about, "
                                  "source, rule_id or name_contains")
            if not _split(merged.get("actions")):
                raise ConfigError(f"{label} is a new policy and needs action=<actions>")
        tenant[label] = merged
    if not tenant:
        em.pop("policies", None)
    if not em:
        new_cfg.pop("emergency", None)

    after = (new_cfg.get("emergency") or {}).get("policies", {}).get(label)
    changed = before != after
    view_before = next((v for v in (_policy_view(p, actions, cfg) for p in merge_policies(section, cfg))
                        if v["policy"] == label), None)
    view_after = next((v for v in (_policy_view(p, actions, new_cfg)
                                   for p in merge_policies(section, new_cfg))
                       if v["policy"] == label), None)
    if view_before is None and view_after is None:
        raise ConfigError(f"no policy {label}; shipped: {', '.join(shipped_names)}. To add one, "
                          "give it a subject (about, source, rule_id or name_contains) and action=")

    shown = " ".join(f"{k}={','.join(_split(args.get(k)))}" if k != "confidence"
                     else f"confidence={args.get(k)}"
                     for k in ("about", "source", "rule_id", "name_contains", "verdict",
                               "confidence", "exposure", "action", "enabled")
                     if str(args.get(k) or "").strip())
    outputs = {"contract_version": CONTRACT_VERSION, "command": "emergency",
               "dry_run": not apply, "applied": False, "policy": label, "shipped": shipped,
               "changed": changed, "from": view_before, "to": view_after,
               "tenant_config_list": TENANT_CONFIG_LIST, "creates_list": False,
               "recorded": False,
               "apply_command": f"!SOCFWConfig command=emergency policy={label} {shown} apply=yes"}
    if changed:
        outputs["creates_list"] = not exists
        if apply:
            write_tenant_config(new_cfg, exists)
            outputs["applied"] = True
            outputs["recorded"] = _record([{
                "universal_command": "emergency", "action_actor": EMERGENCY_ACTOR,
                "action_status": "reset" if reset else "set",
                "action_taken": f"policy {label}: " + (
                    "returned to shipped" if reset and shipped else
                    "removed" if reset else json.dumps(after, sort_keys=True))}])

    md = [f"### Emergency policy {label}: " + ("nothing to change" if not changed
                                                else "applied" if outputs["applied"]
                                                else "dry run, nothing written"), ""]
    rows = [v for v in (view_before, view_after) if v]
    if changed and view_before and view_after:
        md += ["Now:"] + _emergency_table([view_before]) + ["", "After:"] + _emergency_table([view_after])
    elif view_after:
        md += _emergency_table([view_after])
    else:
        md += _emergency_table(rows) + ["", f"After: {label} is removed."]
    if view_after and view_after["name_only"]:
        md += ["", "⚠ This matches on the issue name alone. Prefer rule_id where the issue has one."]
    md += _write_notes(outputs)
    return CommandResults(readable_output="\n".join(md), outputs_prefix="SOCFWConfig.Emergency",
                          outputs=outputs)


# ── entry ────────────────────────────────────────────────────────────────────

# The arguments each command takes. One given to the wrong command is refused, so
# a typo never reads as "done". job lists owner only to give its own, better error.
COMMAND_ARGS = {
    "status": {"action"},
    "shadow": {"action", "actor", "value"},
    "set": {"vendor", "arg", "value"},
    "job": {"job", "value", "owner"},
    "owner": {"job", "owner"},
    "emergency": {"policy", "about", "source", "rule_id", "name_contains", "verdict",
                  "confidence", "exposure", "action", "enabled"},
}
ALWAYS_ARGS = {"command", "apply"}


def check_args(command, args):
    known = set().union(*COMMAND_ARGS.values())
    stray = sorted(k for k, v in (args or {}).items()
                   if k in known and k not in COMMAND_ARGS[command] | ALWAYS_ARGS
                   and str(v if v is not None else "").strip() not in ("", "[]"))
    if stray:
        owners = {k: sorted(c for c, a in COMMAND_ARGS.items() if k in a) for k in stray}
        raise ConfigError("; ".join(f"{k} is for command={'/'.join(owners[k])}" for k in stray)
                          + f", not {command}")


def _split(value):
    if value is None:
        return []
    items = value if isinstance(value, list) else str(value).split(",")
    return [str(i).strip() for i in items if str(i).strip()]


def _yes(value):
    return str(value or "").strip().lower() == "yes"


COMMANDS = {"status": status, "shadow": shadow, "set": set_value, "job": job, "owner": owner,
            "emergency": emergency}


def main():
    args = demisto.args()
    name = str(args.get("command") or "status").strip().lower()
    try:
        handler = COMMANDS.get(name)
        if not handler:
            raise ConfigError(f"unknown command {name}; use one of: " + ", ".join(COMMANDS))
        check_args(name, args)
        return_results(handler(args))
    except ConfigError as e:
        return_error(f"SOCFWConfig {name}: {e}")


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
