"""
SOCCommandWrapper_test_tenant_config.py

Reading the tenant config list, SOCFWTenantConfig, and the shadow overrides in it.

Run: pytest Scripts/SOCCommandWrapper/SOCCommandWrapper_test_tenant_config.py -v
"""

import copy

import pytest
import json
import os

from SOCCommandWrapper_test import load_script

_LISTS = os.path.join(os.path.dirname(__file__), "..", "..", "Lists")
ACTIONS = json.load(open(os.path.join(
    _LISTS, "SOCFrameworkActions_V3", "SOCFrameworkActions_V3_data.json")))
PRODUCT_MAP = json.load(open(os.path.join(
    _LISTS, "SOCProductCategoryMap_V3", "SOCProductCategoryMap_V3_data.json")))
CLASS_MAP = json.load(open(os.path.join(
    _LISTS, "SOCActionClassMap_V3", "SOCActionClassMap_V3_data.json")))

NEW = "SOCFWTenantConfig"
OLD = "SOCFrameworkTenantConfig_V3"  # removed name; must never be read


def _lists(**by_name):
    """getList mock: name -> Contents. A name not given does not exist."""
    def _get(args):
        name = (args or {}).get("listName")
        if name in by_name:
            value = by_name[name]
            return [{"Contents": value if isinstance(value, str) else json.dumps(value)}]
        # What getList returns inside a script for a missing list (deathstar, 26 Oct 2026).
        return [{"Type": 4, "Contents": f" - Item not found (8) on list [{name}] (2609)"}]
    return _get


def _load(**by_name):
    script, demisto = load_script()
    demisto._command_responses = {"getList": _lists(**by_name)}
    return script.load_tenant_config()


def test_reads_new_name():
    assert _load(**{NEW: {"Zscaler": {"category-id": "new"}}}) == {"Zscaler": {"category-id": "new"}}


def test_old_list_name_is_never_read():
    assert _load(**{OLD: {"Zscaler": {"category-id": "old"}}}) == {}


def test_malformed_list_means_nothing_configured():
    assert _load(**{NEW: "not json"}) == {}


def test_neither_list_means_nothing_configured():
    assert _load() == {}


def _zia_block(**by_name):
    action = "soc-block-network-indicator"
    row = copy.deepcopy(ACTIONS[action])
    row["shadow_mode"] = True
    row["shadow_mode_by_actor"] = {}
    zia = PRODUCT_MAP["ds_zscaler_zia"]
    script, demisto = load_script()
    demisto._args = {"action": action, "list_name": "SOCFrameworkActions_V3",
                     "output_key": "UCTest.Executions", "Action_Actor": "analyst"}
    demisto._context = {"SOCFramework": {
        "Product": {"key": "ds_zscaler_zia", "category": zia["category"],
                    "response": zia.get("response"), "responses": zia.get("responses")},
        "Artifacts": {"Network": {"Destination": {"IP": "203.0.113.7"}}},
        "RunID": "run-1"}}
    getlist = _lists(**by_name)

    def _get(args):
        name = (args or {}).get("listName")
        if name == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps({action: row})}]
        if name == "SOCActionClassMap_V3":
            return [{"Contents": json.dumps(CLASS_MAP)}]
        return getlist(args)

    demisto._command_responses = {
        "getList": _get,
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }
    script.main()
    rec = demisto._context["UCTest"]["Executions"]
    return rec[0] if isinstance(rec, list) else rec


def test_customer_value_from_new_list_reaches_the_dispatch():
    rec = _zia_block(**{NEW: {"Zscaler": {"category-id": "cat-new"}}})
    assert not rec.get("skipped"), rec.get("skip_reason")
    assert rec["args"]["category-id"] == "cat-new"


# ── Shadow overrides from the tenant config ───────────────────────────────────
# {"shadow": {action: {actor: bool}}}, written by SOCFWConfig. A named pair
# decides; anything not named falls through to the shipped action row.

STAR = ACTIONS["soc-star-case"]  # shadow true; analyst false, ai true
STAR_LIVE = {"shadow": {"soc-star-case": {"ai": False, "automation": False}}}


def _shadow(tenant, actor, action="soc-star-case"):
    script, _ = load_script()
    return script.resolve_shadow_mode(
        ACTIONS[action], actor, script.tenant_shadow_override(tenant, action, actor))


def test_override_takes_named_actor_off_shadow():
    assert _shadow(None, "ai") is True
    assert _shadow(STAR_LIVE, "ai") is False
    assert _shadow(STAR_LIVE, "automation") is False


def test_override_leaves_other_actors_on_the_shipped_row():
    assert _shadow(STAR_LIVE, "analyst") is False          # shipped by_actor
    assert _shadow(STAR_LIVE, "") is True


def test_override_can_put_an_actor_back_on_shadow():
    assert _shadow({"shadow": {"soc-star-case": {"analyst": True}}}, "analyst") is True


def test_override_is_per_action():
    assert _shadow(STAR_LIVE, "ai", action="soc-close-issue") is True


def test_string_booleans_accepted_other_values_ignored():
    assert _shadow({"shadow": {"soc-star-case": {"ai": "false"}}}, "ai") is False
    assert _shadow({"shadow": {"soc-star-case": {"ai": "off"}}}, "ai") is True
    assert _shadow({"shadow": "nonsense"}, "ai") is True


def test_actor_match_ignores_case_and_spaces():
    assert _shadow(STAR_LIVE, " AI ") is False


def _star(actor, **lists):
    script, demisto = load_script()
    demisto._args = {"action": "soc-star-case", "list_name": "SOCFrameworkActions_V3",
                     "output_key": "UCTest.Executions", "Action_Actor": actor}
    demisto._context = {"SOCFramework": {"RunID": "run-1", "Product": {}}}
    getlist = _lists(**lists)

    def _get(args):
        name = (args or {}).get("listName")
        if name == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps({"soc-star-case": STAR})}]
        return getlist(args)

    demisto._command_responses = {
        "getList": _get,
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "setParentIncidentFields": [{"Type": 1, "Contents": "ok"}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }
    script.main()
    return [c for c, _ in demisto._commands]


def test_star_case_is_simulated_for_ai_without_override():
    assert "setParentIncidentFields" not in _star("ai")


def test_star_case_runs_for_ai_with_override_in_new_list():
    assert "setParentIncidentFields" in _star("ai", **{NEW: STAR_LIVE})


def test_star_case_old_playbook_passing_framework_follows_automation():
    assert "setParentIncidentFields" in _star("framework", **{NEW: STAR_LIVE})


def test_shadow_hint_names_the_socfwconfig_command():
    script, _ = load_script()
    cmd = "!SOCFWConfig command=shadow action=soc-star-case actor=ai value=off apply=yes"
    assert script.shadow_go_live_command("soc-star-case", "AI") == cmd
    assert cmd in script.shadow_footer("soc-star-case", "ai")
    assert "actor=<actor>" in script.shadow_go_live_command("soc-star-case", "")


# ── framework is read as automation for one release ───────────────────────────

def test_framework_reads_the_automation_setting():
    assert _shadow(None, "framework") is True
    assert _shadow(STAR_LIVE, "framework") is False


def test_framework_named_explicitly_is_still_honoured():
    # A list or tenant config edited before the rename keeps meaning what it said.
    row = dict(STAR, shadow_mode_by_actor={"analyst": False, "framework": False})
    script, _ = load_script()
    assert script.resolve_shadow_mode(row, "framework") is False
    assert script.resolve_shadow_mode(row, "automation") is True
    cfg = {"shadow": {"soc-star-case": {"framework": False, "automation": True}}}
    assert _shadow(cfg, "framework") is False


def test_shipped_star_row_no_longer_names_framework():
    assert "framework" not in STAR["shadow_mode_by_actor"]


# ── fail closed: anything that can change something defaults to shadow ──────

def _resolve(row, actor="automation"):
    script, _ = load_script()
    return script.resolve_shadow_mode(row, actor)


MUTATING = {"responses": {}, "phase": "containment"}
READ_ONLY = {"responses": {}, "phase": "enrichment"}


@pytest.mark.parametrize("value", ["__missing__", "yes", 1, "", None, "off", "TRUE "])
def test_mutating_action_without_a_plain_setting_is_simulated(value):
    row = dict(MUTATING)
    if value != "__missing__":
        row["shadow_mode"] = value
    expected = True  # "TRUE " is plainly true; everything else is unreadable -> shadow
    assert _resolve(row) is expected


def test_mutating_action_runs_only_on_a_deliberate_false():
    assert _resolve(dict(MUTATING, shadow_mode=False)) is False
    assert _resolve(dict(MUTATING, shadow_mode="false")) is False


def test_read_only_action_without_a_setting_still_runs():
    assert _resolve(dict(READ_ONLY)) is False


def test_garbled_actor_value_falls_back_to_the_action_default():
    row = dict(MUTATING, shadow_mode=True, shadow_mode_by_actor={"analyst": "no"})
    assert _resolve(row, "analyst") is True
    row = dict(MUTATING, shadow_mode=True, shadow_mode_by_actor={"analyst": False})
    assert _resolve(row, "analyst") is False


def test_every_shipped_action_with_its_shadow_fields_removed():
    script, _ = load_script()
    for name, row in ACTIONS.items():
        if not (isinstance(row, dict) and "responses" in row):
            continue
        bare = {k: v for k, v in row.items() if k not in ("shadow_mode", "shadow_mode_by_actor")}
        for actor in ("analyst", "ai", "automation", "issue_emergency", "layout", ""):
            assert script.resolve_shadow_mode(bare, actor) is (not script.is_read_only(row)), (name, actor)


def test_star_case_with_shadow_fields_removed_is_not_executed():
    bare = {k: v for k, v in STAR.items() if k not in ("shadow_mode", "shadow_mode_by_actor")}
    script, demisto = load_script()
    demisto._args = {"action": "soc-star-case", "list_name": "SOCFrameworkActions_V3",
                     "output_key": "UCTest.Executions", "Action_Actor": "ai"}
    demisto._context = {"SOCFramework": {"RunID": "run-1", "Product": {}}}
    getlist = _lists()

    def _get(args):
        if (args or {}).get("listName") == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps({"soc-star-case": bare})}]
        return getlist(args)

    demisto._command_responses = {"getList": _get,
                                  "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
                                  "setParentIncidentFields": [{"Type": 1, "Contents": "ok"}],
                                  "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}]}
    script.main()
    assert "setParentIncidentFields" not in [c for c, _ in demisto._commands]


# ── the shipped list follows the either/or shape ─────────────────────────────

ACTOR_NAMES = {"analyst", "ai", "automation", "issue_emergency"}


def test_shipped_rows_use_one_shape_or_the_other_never_both():
    both = [k for k, v in ACTIONS.items() if isinstance(v, dict)
            and "shadow_mode" in v and "shadow_mode_by_actor" in v]
    assert both == []


def test_shipped_per_actor_rows_name_every_actor_that_calls_them():
    """analyst, ai and automation on every per-actor row; issue_emergency on containment rows.

    issue_emergency is the issue-level containment caller and nothing else, so a
    triage row it never calls (the contained close, the severity raise) leaves it out.
    """
    for name, row in ACTIONS.items():
        if isinstance(row, dict) and "shadow_mode_by_actor" in row:
            named = set(row["shadow_mode_by_actor"])
            assert named <= ACTOR_NAMES, name
            assert ACTOR_NAMES - {"issue_emergency"} <= named, name
            if row.get("phase") == "containment":
                assert "issue_emergency" in named, name
            assert all(isinstance(v, bool) for v in row["shadow_mode_by_actor"].values()), name


def test_every_shipped_action_says_it_plainly():
    for name, row in ACTIONS.items():
        if isinstance(row, dict) and "responses" in row:
            assert isinstance(row.get("shadow_mode"), bool) or "shadow_mode_by_actor" in row, name


def test_action_actor_dropdown_offers_only_real_callers():
    """The wrapper's Action_Actor dropdown offers what callers pass, and each is kept as itself."""
    import yaml
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "SOCCommandWrapper.yml")) as f:
        spec = yaml.safe_load(f)
    arg = next(a for a in spec["args"] if a["name"] == "Action_Actor")
    assert arg["predefined"] == ["analyst", "ai", "automation", "issue_emergency", "layout"]
    assert arg["defaultValue"] == "analyst"
    script, _ = load_script()
    for actor in arg["predefined"]:
        assert script.normalize_action_actor(actor, False) == actor
