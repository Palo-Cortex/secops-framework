"""
setValueTags — view and set the value of each SOC Framework action.

An action's value is the analyst minutes it saves (time_minutes) and its
category (action_category). SOCCommandWrapper writes both onto every row in
xsiam_socfw_ir_execution_raw, which the value dashboards add up.

Where values come from, in order:
  1. SOCFWTenantConfig -> "value" -> <action>   this tenant's values, written here
  2. SOCActionTimeMap_V3 -> <action>              the pack's shipped values
An action in neither records 0 minutes. SOCActionTimeMap_V3 is a pack list the
platform does not let a script change, so this script only ever writes 1; a
tenant value survives pack upgrades.

    !setValueTags action=list_all
    !setValueTags action=list_by_type category=containment
    !setValueTags action=list_by_tag_or_name tag=soc-star-case
    !setValueTags action=add tag=soc-star-case time=5 category=triage
    !setValueTags action=update tag=soc-isolate-endpoint time=20
    !setValueTags action=delete tag=soc-isolate-endpoint
"""
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

import json

SHIPPED_LIST = "SOCActionTimeMap_V3"
TENANT_CONFIG_LIST = "SOCFWTenantConfig"
SECTION = "value"
ACTIONS_LIST = "SOCFrameworkActions_V3"
CATEGORIES = ("comms", "containment", "enrichment", "eradication", "recovery", "triage")
ACTIONS = ("add", "update", "delete", "list_all", "list_by_type", "list_by_tag_or_name")
FORMATS = ("markdown", "table", "json")
# Arguments the lookup-table version took. Value is per action now, so they mean nothing.
RETIRED_ARGS = ("playbook_name", "playbookid", "scriptid", "product", "vendor", "type")


class ValueTagError(Exception):
    pass


def _read_list(name):
    """(exists, parsed). parsed is None when the content is not a JSON object."""
    res = demisto.executeCommand("getList", {"listName": name})
    entry = res[0] if res and isinstance(res, list) and isinstance(res[0], dict) else {}
    raw = entry.get("Contents")
    if not raw or "Item not found" in str(raw):
        return False, None
    if entry.get("Type") == 4:
        raise ValueTagError(f"could not read {name}: {raw}")
    if isinstance(raw, dict):
        return True, raw
    try:
        parsed = json.loads(raw)
    except ValueError:
        return True, None
    return True, parsed if isinstance(parsed, dict) else None


def load_shipped():
    exists, data = _read_list(SHIPPED_LIST)
    if not exists or data is None:
        raise ValueTagError(f"{SHIPPED_LIST} is missing or not a JSON object; reinstall soc-optimization-unified")
    return {k: v for k, v in data.items() if isinstance(v, dict)}


def load_tenant_config():
    """(config, exists). An existing list that is not a JSON object is never written over."""
    exists, cfg = _read_list(TENANT_CONFIG_LIST)
    if exists and cfg is None:
        raise ValueTagError(f"{TENANT_CONFIG_LIST} is not a JSON object; fix or empty it in Settings > Lists")
    return (cfg or {}), exists


def tenant_values(cfg):
    section = cfg.get(SECTION)
    if section is not None and not isinstance(section, dict):
        raise ValueTagError(f"{TENANT_CONFIG_LIST} '{SECTION}' must be an object of action -> value")
    return {k: v for k, v in (section or {}).items() if isinstance(v, dict)}


def _is_error(res):
    return any(isinstance(e, dict) and e.get("Type") == 4 for e in (res or []))


def _error_text(res):
    return "; ".join(str(e.get("Contents")) for e in (res or []) if isinstance(e, dict) and e.get("Type") == 4)


def write_tenant_config(cfg, exists):
    """Write, then read back: a write that did not land is reported, not assumed."""
    data = json.dumps(cfg, indent=2, sort_keys=True)
    if exists:
        how = "setList"
        res = demisto.executeCommand("setList", {"listName": TENANT_CONFIG_LIST, "listData": data})
    else:
        how = "core-api-post /xsoar/public/v1/lists/save"
        res = demisto.executeCommand("core-api-post", {
            "uri": "/xsoar/public/v1/lists/save",
            "body": json.dumps({"name": TENANT_CONFIG_LIST, "data": data, "type": "json"})})
    back_exists, back = _read_list(TENANT_CONFIG_LIST)
    if not back_exists or back != cfg:
        hint = "" if exists else "; creating it needs the Core REST API integration"
        raise ValueTagError(f"could not write {TENANT_CONFIG_LIST} ({how}: {_error_text(res) or 'no error returned'}){hint}")


def framework_actions():
    """Action names in SOCFrameworkActions_V3, or None if it cannot be read."""
    try:
        exists, data = _read_list(ACTIONS_LIST)
    except ValueTagError:
        return None
    if not exists or data is None:
        return None
    return {k for k, v in data.items() if isinstance(v, dict)}


def _minutes(value):
    try:
        n = int(str(value).strip())
    except ValueError:
        raise ValueTagError(f"time is whole minutes, got {value}")
    if n < 0:
        raise ValueTagError("time cannot be negative")
    return n


def _category(value):
    c = str(value).strip().lower()
    if c not in CATEGORIES:
        raise ValueTagError(f"category is one of: {', '.join(CATEGORIES)}")
    return c


def _usable_minutes(entry):
    try:
        n = int(str((entry or {}).get("time_minutes")).strip())
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def effective(shipped, tenant, action):
    """What SOCCommandWrapper will record: the same rules as resolve_action_value."""
    s, t = shipped.get(action) or {}, tenant.get(action) or {}
    minutes, source = _usable_minutes(t), "tenant"
    if minutes is None:
        minutes, source = _usable_minutes(s), "shipped"
    if minutes is None:
        minutes, source = 0, "none"
    category = str(t.get("action_category") or s.get("action_category") or "")
    if source != "tenant" and t.get("action_category"):
        source = "tenant"
    return {"Action": action, "Minutes": minutes, "Category": category, "From": source}


def _rows(shipped, tenant, names):
    return [effective(shipped, tenant, n) for n in names]


def _show(title, rows, output_format, extra=""):
    if output_format == "json":
        return CommandResults(readable_output=json.dumps(rows, indent=2), outputs_prefix="SOCValueTags", outputs=rows)
    md = (tableToMarkdown(title, rows, headers=["Action", "Minutes", "Category", "From"]) if rows
          else f"### {title}\nNo entries found.")
    return CommandResults(readable_output=md + extra, outputs_prefix="SOCValueTags", outputs=rows)


def _result(text, rows):
    return CommandResults(readable_output=text, outputs_prefix="SOCValueTags", outputs=rows)


def main_logic(args):
    action = str(args.get("action") or "list_all").strip().lower()
    tag = str(args.get("tag") or "").strip()
    time_arg = str(args.get("time") or "").strip()
    category = str(args.get("category") or "").strip()
    output_format = str(args.get("output_format") or "markdown").strip().lower()

    if action not in ACTIONS:
        raise ValueTagError(f"action is one of: {', '.join(ACTIONS)}")
    if output_format not in FORMATS:
        raise ValueTagError(f"output_format is one of: {', '.join(FORMATS)}")
    retired = [a for a in RETIRED_ARGS if str(args.get(a) or "").strip()]
    if retired:
        raise ValueTagError(f"{', '.join(retired)} no longer used: value is set per action with "
                            "tag=<action> time=<minutes> category=<category>")

    shipped = load_shipped()
    cfg, exists = load_tenant_config()
    tenant = tenant_values(cfg)
    known = sorted(set(shipped) | set(tenant))

    if action == "list_all":
        extra = ""
        fw = framework_actions()
        if fw is not None:
            missing = sorted(a for a in fw if a not in shipped and a not in tenant)
            if missing:
                extra = (f"\n\n**{len(missing)} actions have no value and record 0 minutes:** "
                         + ", ".join(f"`{m}`" for m in missing)
                         + "\n\nAdd one: `!setValueTags action=add tag=<action> time=<minutes> category=<category>`")
        extra += (f"\n\nFrom: `tenant` = set on this tenant ({TENANT_CONFIG_LIST}), `shipped` = the pack "
                  f"({SHIPPED_LIST}).")
        return _show("Value per action", _rows(shipped, tenant, known), output_format, extra)

    if action == "list_by_type":
        if not category:
            raise ValueTagError("list_by_type needs category")
        c = _category(category)
        rows = [r for r in _rows(shipped, tenant, known) if r["Category"] == c]
        return _show(f"Value per action: {c}", rows, output_format)

    if action == "list_by_tag_or_name":
        if not tag:
            raise ValueTagError("list_by_tag_or_name needs tag (all or part of an action name)")
        return _show(f"Value per action matching {tag}",
                     _rows(shipped, tenant, [n for n in known if tag.lower() in n.lower()]), output_format)

    if not tag:
        raise ValueTagError(f"{action} needs tag, the action name (for example soc-star-case)")
    before = effective(shipped, tenant, tag)

    if action == "add":
        if tag in shipped or tag in tenant:
            raise ValueTagError(f"{tag} already has a value ({before['Minutes']} minutes, {before['From']}); "
                                "use action=update")
        if not time_arg or not category:
            raise ValueTagError("add needs time and category")
        new = {"time_minutes": _minutes(time_arg), "action_category": _category(category)}
        fw = framework_actions()
        note = ("" if fw is None or tag in fw
                else f"\n\nNote: {tag} is not in {ACTIONS_LIST}; it only counts if something records that action name.")
        cfg.setdefault(SECTION, {})[tag] = new
        write_tenant_config(cfg, exists)
        return _result(f"Added {tag}: {new['time_minutes']} minutes, {new['action_category']}, set on this tenant."
                       + note, [effective(shipped, tenant_values(cfg), tag)])

    if tag not in shipped and tag not in tenant:
        raise ValueTagError(f"{tag} has no value" + ("; use action=add" if action == "update" else ""))

    if action == "update":
        if not time_arg and not category:
            raise ValueTagError("update needs time, category or both")
        entry = dict(tenant.get(tag) or {})
        if time_arg:
            entry["time_minutes"] = _minutes(time_arg)
        if category:
            entry["action_category"] = _category(category)
        after = effective(shipped, dict(tenant, **{tag: entry}), tag)
        if tag in tenant and entry == tenant[tag]:
            return _result(f"No change: {tag} is already {before['Minutes']} minutes, {before['Category']}.", [before])
        cfg.setdefault(SECTION, {})[tag] = entry
        write_tenant_config(cfg, exists)
        return _result(f"Updated {tag}: {before['Minutes']} -> {after['Minutes']} minutes, "
                       f"{before['Category']} -> {after['Category']}, set on this tenant.", [after])

    # delete: removes this tenant's value. The shipped value cannot be removed.
    if tag not in tenant:
        raise ValueTagError(f"{tag} has only the shipped value ({before['Minutes']} minutes), which cannot be removed; "
                            f"to stop it counting: !setValueTags action=update tag={tag} time=0")
    cfg[SECTION].pop(tag)
    if not cfg[SECTION]:
        cfg.pop(SECTION)
    write_tenant_config(cfg, exists)
    after = effective(shipped, tenant_values(cfg), tag)
    back = (f"back to the shipped {after['Minutes']} minutes, {after['Category']}" if after["From"] == "shipped"
            else "it now records 0 minutes")
    return _result(f"Removed this tenant's value for {tag}; {back}.", [after])


def main():
    try:
        return_results(main_logic(demisto.args()))
    except ValueTagError as e:
        return_error(f"setValueTags: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
