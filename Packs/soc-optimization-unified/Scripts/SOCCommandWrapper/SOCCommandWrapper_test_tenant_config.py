"""
SOCCommandWrapper_test_tenant_config.py

Which tenant config list the wrapper reads. SOCFWTenantConfig is the name; the
list shipped as SOCFrameworkTenantConfig_V3 and is read only when the new list
does not exist, for one release.

Run: pytest Scripts/SOCCommandWrapper/SOCCommandWrapper_test_tenant_config.py -v
"""

import copy
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
OLD = "SOCFrameworkTenantConfig_V3"


def _lists(**by_name):
    """getList mock: name -> Contents. A name not given does not exist."""
    def _get(args):
        name = (args or {}).get("listName")
        if name in by_name:
            value = by_name[name]
            return [{"Contents": value if isinstance(value, str) else json.dumps(value)}]
        return [{"Contents": "Item not found"}]
    return _get


def _load(**by_name):
    script, demisto = load_script()
    demisto._command_responses = {"getList": _lists(**by_name)}
    return script.load_tenant_config()


def test_reads_new_name():
    assert _load(**{NEW: {"Zscaler": {"category-id": "new"}}}) == {"Zscaler": {"category-id": "new"}}


def test_falls_back_to_legacy_name_when_new_list_missing():
    assert _load(**{OLD: {"Zscaler": {"category-id": "old"}}}) == {"Zscaler": {"category-id": "old"}}


def test_new_list_wins_over_legacy():
    cfg = _load(**{NEW: {"Zscaler": {"category-id": "new"}},
                   OLD: {"Zscaler": {"category-id": "old"}}})
    assert cfg == {"Zscaler": {"category-id": "new"}}


def test_malformed_new_list_does_not_fall_back():
    # Stale values from the old list would be worse than a skip naming the value.
    assert _load(**{NEW: "not json", OLD: {"Zscaler": {"category-id": "old"}}}) == {}


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

STAR = ACTIONS["soc-star-case"]  # shadow true; analyst false, ai true, framework true
STAR_LIVE = {"shadow": {"soc-star-case": {"ai": False, "framework": False}}}


def _shadow(tenant, actor, action="soc-star-case"):
    script, _ = load_script()
    return script.resolve_shadow_mode(
        ACTIONS[action], actor, script.tenant_shadow_override(tenant, action, actor))


def test_override_takes_named_actor_off_shadow():
    assert _shadow(None, "ai") is True
    assert _shadow(STAR_LIVE, "ai") is False
    assert _shadow(STAR_LIVE, "framework") is False


def test_override_leaves_other_actors_on_the_shipped_row():
    assert _shadow(STAR_LIVE, "analyst") is False      # shipped by_actor
    assert _shadow(STAR_LIVE, "automation") is True    # shipped default
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


def test_star_case_override_read_from_legacy_list_when_new_missing():
    assert "setParentIncidentFields" in _star("framework", **{OLD: STAR_LIVE})


def test_shadow_hint_names_the_socfwconfig_command():
    script, _ = load_script()
    cmd = "!SOCFWConfig command=shadow action=soc-star-case actor=ai value=off apply=yes"
    assert script.shadow_go_live_command("soc-star-case", "AI") == cmd
    assert cmd in script.shadow_footer("soc-star-case", "ai")
    assert "actor=<actor>" in script.shadow_go_live_command("soc-star-case", "")
