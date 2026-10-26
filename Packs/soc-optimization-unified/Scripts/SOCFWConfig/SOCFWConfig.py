"""Configure the SOC Framework on this tenant.

Writes go to SOCFWTenantConfig, the one list a customer's settings live in. It
is created on the tenant by this script, never shipped in a pack, so an upgrade
cannot overwrite it and shipped lists never need detaching.

Commands
  status   Which mutating actions are live or simulated, per actor, and what
           decided it: the tenant config or the shipped default.
  shadow   Take one action on or off shadow for named actors, or return it to
           the shipped default. Dry-run unless apply=yes.

Every command returns the same data twice: a War Room table for people and
SOCFWConfig.* context for the PoV harness. contract_version changes only when a
key is renamed or removed.

SOCCommandWrapper reads what this script writes: {"shadow": {action: {actor:
bool}}}, one entry per action per actor, checked before the shipped row.
"""

import json

CONTRACT_VERSION = 1

ACTIONS_LIST = "SOCFrameworkActions_V3"
TENANT_CONFIG_LIST = "SOCFWTenantConfig"
# Read only while SOCFWTenantConfig does not exist; its content seeds the new
# list on the first write so the customer's vendor values carry over.
LEGACY_TENANT_CONFIG_LIST = "SOCFrameworkTenantConfig_V3"

# The actors the framework passes to the wrapper. Status always shows these;
# any other actor named in the tenant config is shown as well.
ACTORS = ("analyst", "ai", "framework", "automation", "issue_emergency")

# Actions in these phases only read. They run live and are never shadowed.
READ_ONLY_PHASES = ("enrichment", "investigation")

VALUES = {"on": True, "off": False, "default": None}


class ConfigError(Exception):
    pass


# ── Lists ────────────────────────────────────────────────────────────────────

def _read_list(name):
    """(exists, parsed). parsed is None when the content is not a JSON object."""
    res = demisto.executeCommand("getList", {"listName": name})
    raw = res[0].get("Contents") if res and isinstance(res, list) else None
    if not raw or raw == "Item not found":
        return False, None
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
    """(config, source). source names the list read, or None if neither exists.

    A SOCFWTenantConfig that exists but is not a JSON object is an error rather
    than an empty config: writing over it would destroy whatever is in it.
    """
    exists, cfg = _read_list(TENANT_CONFIG_LIST)
    if exists:
        if cfg is None:
            raise ConfigError(f"{TENANT_CONFIG_LIST} is not a JSON object; fix or empty it "
                              "in Settings > Lists before running SOCFWConfig")
        return cfg, TENANT_CONFIG_LIST
    exists, cfg = _read_list(LEGACY_TENANT_CONFIG_LIST)
    if exists and cfg is not None:
        return cfg, LEGACY_TENANT_CONFIG_LIST
    return {}, None


def write_tenant_config(cfg, source):
    """Write, then read back: a write that did not land is reported, not assumed."""
    data = json.dumps(cfg, indent=2, sort_keys=True)
    command = "setList" if source == TENANT_CONFIG_LIST else "createList"
    res = demisto.executeCommand(command, {"listName": TENANT_CONFIG_LIST, "listData": data})
    if _is_error(res):
        raise ConfigError(f"could not write {TENANT_CONFIG_LIST} ({command}): {_error_text(res)}")
    exists, written = _read_list(TENANT_CONFIG_LIST)
    if not exists or written != cfg:
        raise ConfigError(f"wrote {TENANT_CONFIG_LIST} but reading it back did not return "
                          "the change; check the list in Settings > Lists")


def _is_error(res):
    return any(isinstance(e, dict) and e.get("Type") == 4 for e in (res or []))


def _error_text(res):
    return "; ".join(str(e.get("Contents")) for e in (res or [])
                     if isinstance(e, dict) and e.get("Type") == 4)


# ── Resolution — the same rules SOCCommandWrapper applies ───────────────────

def _as_bool(value):
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    return text == "true" if text in ("true", "false") else None


def is_read_only(row):
    return str(row.get("phase") or "").lower() in READ_ONLY_PHASES


def tenant_value(cfg, action, actor):
    section = cfg.get("shadow") if isinstance(cfg, dict) else None
    per_action = section.get(action) if isinstance(section, dict) else None
    if not isinstance(per_action, dict) or actor not in per_action:
        return None
    return _as_bool(per_action[actor])


def shipped_value(row, actor):
    by_actor = row.get("shadow_mode_by_actor")
    if isinstance(by_actor, dict) and actor in by_actor:
        value = _as_bool(by_actor[actor])
        if value is not None:
            return value
    return bool(_as_bool(row.get("shadow_mode", False)))


def effective(cfg, action, row, actor):
    """(shadow, decided_by)."""
    override = tenant_value(cfg, action, actor)
    if override is not None:
        return override, "tenant_config"
    return shipped_value(row, actor), "shipped_default"


def _state(shadow):
    return "shadow" if shadow else "live"


# ── status ───────────────────────────────────────────────────────────────────

def status(args):
    actions = load_actions()
    cfg, source = load_tenant_config()

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
                named |= {str(a).lower() for a in per_action}
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
            shadow, decided_by = effective(cfg, name, row, actor)
            rows.append({"action": name, "actor": actor, "shadow": shadow,
                         "state": _state(shadow), "decided_by": decided_by,
                         "read_only": ro})
            cells.append(_state(shadow) + (" ✱" if decided_by == "tenant_config" else ""))
        table.append([name] + cells)

    outputs = {"contract_version": CONTRACT_VERSION, "command": "status",
               "tenant_config_list": source, "actors": actors, "rows": rows}

    md = ["### SOC Framework — live or simulated, by actor", "",
          "| Action | " + " | ".join(actors) + " |",
          "|---|" + "---|" * len(actors)]
    md += ["| " + " | ".join(r) + " |" for r in table]
    md += ["", "✱ set in the tenant config; everything else is the shipped default."]
    if not wanted:
        md.append(f"{read_only} read-only actions (enrichment, investigation) always run "
                  "live and are not listed.")
    md.append("To change one: `!SOCFWConfig command=shadow action=<action> actor=<actor> "
              "value=on|off|default` — add `apply=yes` to write.")
    return CommandResults(readable_output="\n".join(md), outputs_prefix="SOCFWConfig.Status",
                          outputs=outputs)


# ── shadow ───────────────────────────────────────────────────────────────────

def shadow(args):
    actions = load_actions()
    action = str(args.get("action") or "").strip()
    actors = [a.lower() for a in _split(args.get("actor"))]
    value = str(args.get("value") or "").strip().lower()
    apply = str(args.get("apply") or "").strip().lower() == "yes"

    if not action:
        raise ConfigError("action is required, e.g. action=soc-star-case")
    if action not in actions:
        raise ConfigError(f"unknown action {action}; run !SOCFWConfig command=status to list them")
    if value not in VALUES:
        raise ConfigError("value must be on, off or default")
    if not actors:
        raise ConfigError("actor is required: one or more of " + ", ".join(ACTORS))
    valid_actors = set(ACTORS)
    for r in actions.values():
        valid_actors |= {str(a).lower() for a in (r.get("shadow_mode_by_actor") or {})}
    unknown = [a for a in actors if a not in valid_actors]
    if unknown:
        raise ConfigError(f"unknown actor {', '.join(unknown)}; use one or more of "
                          + ", ".join(ACTORS))

    row = actions[action]
    outputs = {"contract_version": CONTRACT_VERSION, "command": "shadow",
               "dry_run": not apply, "applied": False, "action": action, "value": value,
               "changes": [], "refused": [], "tenant_config_list": TENANT_CONFIG_LIST,
               "creates_list": False, "carried_over_from": None,
               "apply_command": (f"!SOCFWConfig command=shadow action={action} "
                                 f"actor={','.join(actors)} value={value} apply=yes")}

    if is_read_only(row):
        outputs["refused"].append({
            "action": action,
            "reason": f"read-only action (phase {row.get('phase')}); it always runs live "
                      "and is never shadowed"})
        return _shadow_result(outputs)

    cfg, source = load_tenant_config()
    new_cfg = json.loads(json.dumps(cfg))
    section = new_cfg.setdefault("shadow", {})
    if not isinstance(section, dict):
        raise ConfigError(f"'shadow' in {source} is not an object; fix it in Settings > Lists")
    per_action = section.setdefault(action, {})
    if not isinstance(per_action, dict):
        raise ConfigError(f"'shadow.{action}' in {source} is not an object; fix it in "
                          "Settings > Lists")

    for actor in actors:
        before, before_by = effective(cfg, action, row, actor)
        if VALUES[value] is None:
            per_action.pop(actor, None)
        else:
            per_action[actor] = VALUES[value]
        after, after_by = effective(new_cfg, action, row, actor)
        outputs["changes"].append({
            "actor": actor, "from": _state(before), "to": _state(after),
            "decided_by_before": before_by, "decided_by_after": after_by,
            "changed": (before, before_by) != (after, after_by)})

    if not per_action:
        section.pop(action, None)
    if not section:
        new_cfg.pop("shadow", None)

    if not any(c["changed"] for c in outputs["changes"]):
        return _shadow_result(outputs)

    if source != TENANT_CONFIG_LIST:
        outputs["creates_list"] = True
        outputs["carried_over_from"] = source
    if apply:
        write_tenant_config(new_cfg, source)
        outputs["applied"] = True
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
            md.append(f"| {c['actor']} | {c['from']} | {after} | "
                      f"{c['decided_by_after'].replace('_', ' ')} |")
    if o["creates_list"]:
        carried = (f", carrying over the values in {o['carried_over_from']}"
                   if o["carried_over_from"] else "")
        md += ["", ("Created " if o["applied"] else "Will create ")
               + f"{o['tenant_config_list']}{carried}."]
    if o["dry_run"] and any(c["changed"] for c in o["changes"]):
        md += ["", f"To write it: `{o['apply_command']}`"]
    return CommandResults(readable_output="\n".join(md), outputs_prefix="SOCFWConfig.Shadow",
                          outputs=o)


# ── entry ────────────────────────────────────────────────────────────────────

def _split(value):
    if value is None:
        return []
    items = value if isinstance(value, list) else str(value).split(",")
    return [str(i).strip() for i in items if str(i).strip()]


COMMANDS = {"status": status, "shadow": shadow}


def main():
    args = demisto.args()
    name = str(args.get("command") or "status").strip().lower()
    try:
        handler = COMMANDS.get(name)
        if not handler:
            raise ConfigError(f"unknown command {name}; use one of: " + ", ".join(COMMANDS))
        return_results(handler(args))
    except ConfigError as e:
        return_error(f"SOCFWConfig {name}: {e}")


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
