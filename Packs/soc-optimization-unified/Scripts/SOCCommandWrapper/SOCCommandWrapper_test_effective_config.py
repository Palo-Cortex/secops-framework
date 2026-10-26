"""
SOCCommandWrapper_test_effective_config.py

Characterisation snapshot of what the shipped lists make the wrapper do. It is
the safety net for changing how the wrapper reads its configuration: a change
that is meant to preserve behaviour must leave the snapshot identical, and a
change that is meant to alter behaviour must alter only the rows it intends to.

Captured, from the lists exactly as they ship:
  shadow   - action x caller -> simulated or live
  routing  - action x data source, no tenant config -> per dispatch: vendor,
             command, resolved arguments, or the skip and its reason
  routing_configured - the same with every declared required_arg filled,
             kept only where it differs from routing

Routing runs every action with shadow forced on, so no vendor command is
called; the wrapper resolves vendor and arguments before shadow decides.
Running both tenant configs pins the "not configured" skips and the
configured path.

Compared with test_data/effective_config_snapshot.json. After an intended
behaviour change, regenerate and review the diff before committing it:
  SOCFW_UPDATE_SNAPSHOT=1 pytest Scripts/SOCCommandWrapper/SOCCommandWrapper_test_effective_config.py

Run: pytest Scripts/SOCCommandWrapper/SOCCommandWrapper_test_effective_config.py -v
"""

import copy
import json
import os
import re

from SOCCommandWrapper_test import load_script

HERE = os.path.dirname(__file__)
LISTS = os.path.join(HERE, "..", "..", "Lists")
SNAPSHOT = os.path.join(HERE, "test_data", "effective_config_snapshot.json")


def _list(name):
    return json.load(open(os.path.join(LISTS, name, name + "_data.json")))


ACTIONS = {k: v for k, v in _list("SOCFrameworkActions_V3").items()
           if isinstance(v, dict) and "responses" in v}
SOURCES = {k: v for k, v in _list("SOCProductCategoryMap_V3").items()
           if isinstance(v, dict) and "category" in v}
CLASS_MAP = _list("SOCActionClassMap_V3")

TEMPLATE = re.compile(r"\$\{([^}]+)\}")
TENANT_CONFIG_LIST = "SOCFWTenantConfig"


def _callers():
    named = set()
    for row in ACTIONS.values():
        named |= set((row.get("shadow_mode_by_actor") or {}).keys())
    # "automation" is the playbook default; "" and an unknown name pin the fallback.
    return sorted(named | {"automation", "", "unknown-caller"})


def _artifact_context():
    """Every context path an action reads, each holding a value naming its path."""
    paths = set()
    for row in ACTIONS.values():
        paths |= set(TEMPLATE.findall(json.dumps(row.get("responses"))))
    ctx = {}
    for path in sorted(paths):
        node = ctx
        parts = path.split(".")
        for part in parts[:-1]:
            nxt = node.get(part)
            if not isinstance(nxt, dict):
                nxt = node[part] = {}
            node = nxt
        if not isinstance(node.get(parts[-1]), dict):
            node[parts[-1]] = "v:" + path
    return ctx


def _full_tenant_config():
    cfg = {}
    for row in ACTIONS.values():
        for vendor, binding in (row.get("responses") or {}).items():
            for arg in binding.get("required_args") or []:
                cfg.setdefault(vendor, {})[arg] = "cfg:" + arg
    return cfg


ARTIFACTS = _artifact_context()
TENANT_CONFIGS = {"none": None, "full": _full_tenant_config()}

RECORD_FIELDS = ("vendor", "command", "args", "target", "skipped", "skip_reason")


def _shadow_table(overlay=None):
    script, _ = load_script()
    return {name: {caller: script.resolve_shadow_mode(
                row, caller, script.tenant_shadow_override(overlay, name, caller))
                for caller in _callers()}
            for name, row in sorted(ACTIONS.items())}


def _route(action, source_key, tenant):
    row = copy.deepcopy(ACTIONS[action])
    row["shadow_mode"] = True
    row["shadow_mode_by_actor"] = {}
    src = SOURCES[source_key]

    script, demisto = load_script()
    demisto._args = {"action": action, "list_name": "SOCFrameworkActions_V3",
                     "output_key": "UCSnap.Executions", "Action_Actor": "automation"}
    ctx = copy.deepcopy(ARTIFACTS)
    ctx.setdefault("SOCFramework", {}).update({
        "RunID": "snapshot",
        "Product": {"key": source_key, "category": src.get("category"),
                    "type": src.get("type"), "response": src.get("response"),
                    "responses": src.get("responses")}})
    demisto._context = ctx

    def _get_list(args):
        name = (args or {}).get("listName")
        if name == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps({action: row})}]
        if name == "SOCActionClassMap_V3":
            return [{"Contents": json.dumps(CLASS_MAP)}]
        if name == TENANT_CONFIG_LIST and tenant is not None:
            return [{"Contents": json.dumps(tenant)}]
        return [{"Contents": "Item not found"}]

    demisto._command_responses = {
        "getList": _get_list,
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }
    try:
        script.main()
        error = None
    except BaseException as e:  # return_error and friends end the script
        error = type(e).__name__ + ": " + str(e)[:200]

    records = ((demisto._context.get("UCSnap") or {}).get("Executions")) or []
    if isinstance(records, dict):
        records = [records]
    out = [{k: r[k] for k in RECORD_FIELDS if k in r} for r in records]
    return {"dispatches": out, "error": error} if error else {"dispatches": out}


def _with_overlay(tenant, overlay):
    if not overlay:
        return tenant
    merged = copy.deepcopy(tenant) if tenant else {}
    merged.update(copy.deepcopy(overlay))
    return merged


def _routing_tables(overlay=None):
    none_cfg = _with_overlay(TENANT_CONFIGS["none"], overlay)
    full_cfg = _with_overlay(TENANT_CONFIGS["full"], overlay)
    plain, configured = {}, {}
    for action in sorted(ACTIONS):
        for source_key in sorted(SOURCES):
            key = "{} | {}".format(action, source_key)
            plain[key] = _route(action, source_key, none_cfg)
            with_cfg = _route(action, source_key, full_cfg)
            if with_cfg != plain[key]:
                configured[key] = with_cfg
    return plain, configured


def build_snapshot(overlay=None):
    """overlay: extra tenant config merged into every run, e.g. a shadow override."""
    plain, configured = _routing_tables(overlay)
    return {"shadow": _shadow_table(overlay), "routing": plain,
            "routing_configured": configured}


def _dump(snapshot):
    """One row per line, so a behaviour change reads as a small diff."""
    sections = []
    for name in sorted(snapshot):
        rows = ",\n".join(" {}: {}".format(json.dumps(k), json.dumps(v, sort_keys=True))
                          for k, v in sorted(snapshot[name].items()))
        sections.append("{}: {{\n{}\n}}".format(json.dumps(name), rows))
    return "{\n" + ",\n".join(sections) + "\n}\n"


def _diff(old, new, limit=40):
    lines = []
    for section in ("shadow", "routing", "routing_configured"):
        a, b = old.get(section, {}), new.get(section, {})
        for key in sorted(set(a) | set(b)):
            if a.get(key) != b.get(key):
                lines.append("{} [{}]\n  was: {}\n  now: {}".format(
                    section, key, json.dumps(a.get(key)), json.dumps(b.get(key))))
    more = len(lines) - limit
    return "\n".join(lines[:limit]) + ("\n... {} more".format(more) if more > 0 else "")


SECTIONS = ("shadow", "routing", "routing_configured")


def _load_snapshot():
    """The snapshot's own sections only. check_contribution's normalizer adds
    id/name/fromVersion to JSON under a pack, which are not configuration."""
    raw = json.load(open(SNAPSHOT))
    return {k: raw[k] for k in SECTIONS if k in raw}


def test_effective_configuration_matches_snapshot():
    current = build_snapshot()
    if os.environ.get("SOCFW_UPDATE_SNAPSHOT") or not os.path.exists(SNAPSHOT):
        os.makedirs(os.path.dirname(SNAPSHOT), exist_ok=True)
        with open(SNAPSHOT, "w") as f:
            f.write(_dump(current))
    expected = _load_snapshot()
    assert current == expected, "effective configuration changed:\n" + _diff(expected, current)


def test_snapshot_covers_every_action_source_and_caller():
    snap = _load_snapshot() if os.path.exists(SNAPSHOT) else build_snapshot()
    assert set(snap["shadow"]) == set(ACTIONS)
    assert len(snap["routing"]) == len(ACTIONS) * len(SOURCES)
    assert set(snap["routing_configured"]) <= set(snap["routing"])
    for row in snap["shadow"].values():
        assert set(row) == set(_callers())


# A customer taking starring off shadow for the assessment and the framework,
# the way SOCFWConfig writes it.
STAR_LIVE_FOR_AI_AND_FRAMEWORK = {"shadow": {"soc-star-case": {"ai": False, "framework": False}}}


def test_tenant_shadow_override_moves_only_the_rows_it_names():
    expected = _load_snapshot()
    flipped = build_snapshot(STAR_LIVE_FOR_AI_AND_FRAMEWORK)
    moved = []
    for section in SECTIONS:
        for key in sorted(set(expected[section]) | set(flipped[section])):
            a, b = expected[section].get(key), flipped[section].get(key)
            if section == "shadow":
                moved += [(section, key, c, a[c], b[c]) for c in sorted(a) if a[c] != b[c]]
            elif a != b:
                moved.append((section, key))
    assert moved == [("shadow", "soc-star-case", "ai", True, False),
                     ("shadow", "soc-star-case", "framework", True, False)]
