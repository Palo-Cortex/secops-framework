"""
SOCFWConfig_test.py

status, shadow and set against the shipped SOCFrameworkActions_V3, with an
in-memory tenant standing in for lists, the REST call that creates a JSON list,
and the dataset writer. One test checks that status reports what
SOCCommandWrapper would actually do, for every action and actor.

Run: pytest Scripts/SOCFWConfig/SOCFWConfig_test.py -v
"""

import builtins
import importlib
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)
ACTIONS = json.load(open(os.path.join(
    HERE, "..", "..", "Lists", "SOCFrameworkActions_V3", "SOCFrameworkActions_V3_data.json")))
NEW = "SOCFWTenantConfig"
OLD = "SOCFrameworkTenantConfig_V3"  # removed name; must never be read or written


class Tenant:
    """Lists by name with their type, every command run, and dataset rows."""

    def __init__(self, core_api=True, **lists):
        self.lists = {"SOCFrameworkActions_V3": json.dumps(ACTIONS)}
        self.types = {"SOCFrameworkActions_V3": "json"}
        for k, v in lists.items():
            self.lists[k] = v if isinstance(v, str) else json.dumps(v)
            self.types[k] = "json"
        self.commands, self.rows = [], []
        self.dataset_down = False
        self.core_api = core_api

    def execute(self, command, args):
        self.commands.append((command, args))
        name = args.get("listName")
        if command == "getList":
            if name not in self.lists:
                # What getList returns inside a script for a missing list (deathstar, 26 Oct 2026).
                return [{"Type": 4, "Contents": f" - Item not found (8) on list [{name}] (2609)"}]
            return [{"Type": 1, "Contents": self.lists[name]}]
        if command == "setList":
            if name not in self.lists:
                return [{"Type": 4, "Contents": "Item not found"}]
            self.lists[name] = args["listData"]
            return [{"Type": 1, "Contents": "Done"}]
        if command == "createList":
            # The built-in: always plain text (deathstar, 27 Oct 2026).
            self.lists[name] = args["listData"]
            self.types[name] = "plain_text"
            return [{"Type": 1, "Contents": "Done"}]
        if command == "core-api-post":
            if not self.core_api:
                return [{"Type": 4, "Contents": "Unsupported Command: core-api-post"}]
            assert args["uri"] == "/xsoar/public/v1/lists/save"
            body = json.loads(args["body"])
            self.lists[body["name"]] = body["data"]
            self.types[body["name"]] = body.get("type", "plain_text")
            return [{"Type": 1, "Contents": {"response": {"id": body["name"]}}}]
        if command == "socfw-post-to-dataset":
            self.rows.append(json.loads(args["JSON"]))
            return ([{"Type": 4, "Contents": "writer down"}] if self.dataset_down
                    else [{"Type": 1, "Contents": "ok"}])
        return []

    def config(self, name=NEW):
        return json.loads(self.lists[name]) if name in self.lists else None

    def writes(self):
        return [c for c, _ in self.commands if c in ("setList", "createList", "core-api-post")]


class Results:
    def __init__(self, readable_output=None, outputs_prefix=None, outputs=None, **kw):
        self.readable_output, self.outputs_prefix, self.outputs = (
            readable_output, outputs_prefix, outputs)


def run(tenant, **args):
    out = []
    demisto = types.SimpleNamespace(args=lambda: args, executeCommand=lambda c, a: tenant.execute(c, a),
                                    debug=lambda *a: None)

    def return_error(msg):
        raise RuntimeError(msg)

    for name, value in (("demisto", demisto), ("CommandResults", Results),
                        ("return_results", out.append), ("return_error", return_error)):
        setattr(builtins, name, value)
    sys.path.insert(0, HERE)
    module = importlib.import_module("SOCFWConfig")
    importlib.reload(module)
    module.main()
    return out[0]


def cell(result, action, actor):
    return next(r for r in result.outputs["rows"]
                if r["action"] == action and r["actor"] == actor)


# ── status ───────────────────────────────────────────────────────────────────

def test_status_names_the_exact_field_behind_each_cell():
    t = Tenant(**{NEW: {"shadow": {"soc-star-case": {"automation": False}}}})
    r = run(t, command="status", action="soc-star-case")
    assert r.outputs["contract_version"] == 2
    assert (cell(r, "soc-star-case", "analyst")["field"]
            == "SOCFrameworkActions_V3 soc-star-case.shadow_mode_by_actor.analyst")
    assert cell(r, "soc-star-case", "analyst")["decided_by"] == "action_actor"
    assert cell(r, "soc-star-case", "automation")["field"] == "SOCFWTenantConfig shadow.soc-star-case.automation"
    assert cell(r, "soc-star-case", "automation")["decided_by"] == "tenant_config"
    assert cell(r, "soc-star-case", "issue_emergency")["field"] == "SOCFrameworkActions_V3 soc-star-case.shadow_mode"
    assert cell(r, "soc-star-case", "issue_emergency")["decided_by"] == "action_default"
    assert "| soc-star-case | live | shadow | live ✱ | shadow † |" in r.readable_output


def test_status_lists_mutating_actions_only_by_default():
    r = run(Tenant(), command="status")
    listed = {row["action"] for row in r.outputs["rows"]}
    assert "soc-enrich-domain" not in listed and "soc-isolate-endpoint" in listed
    assert "read-only actions" in r.readable_output


def test_status_shows_customer_values_and_what_is_missing():
    t = Tenant(**{NEW: {"Zscaler": {"category-id": "CAT-1"}}})
    r = run(t, command="status")
    values = {(v["vendor"], v["arg"]): v for v in r.outputs["values"]}
    assert set(values) == {("Zscaler", "category-id"), ("Zscaler", "using"), ("ThreatStopv2", "list_id")}
    assert values[("Zscaler", "category-id")]["value"] == "CAT-1"
    assert values[("ThreatStopv2", "list_id")]["set"] is False
    assert values[("ThreatStopv2", "list_id")]["required"] is True
    assert values[("Zscaler", "using")]["required"] is False
    assert "**missing** — required" in r.readable_output


def test_status_never_reads_the_removed_list_name():
    t = Tenant(**{OLD: {"shadow": {"soc-star-case": {"ai": False}}, "Zscaler": {"category-id": "x"}}})
    r = run(t, command="status")
    assert cell(r, "soc-star-case", "ai")["state"] == "shadow"
    assert r.outputs["tenant_config_exists"] is False
    assert all(a.get("listName") != OLD for _, a in t.commands)


def test_status_agrees_with_the_wrapper_for_every_action_and_actor():
    sys.path.insert(0, os.path.join(HERE, "..", "SOCCommandWrapper"))
    from SOCCommandWrapper_test import load_script
    all_actions = ",".join(k for k, v in ACTIONS.items() if isinstance(v, dict) and "responses" in v)
    for cfg in (None,
                {"shadow": {"soc-star-case": {"ai": False, "automation": False},
                            "soc-isolate-endpoint": {"analyst": False}}},
                {"shadow": {"soc-star-case": {"framework": False, "automation": True}}}):
        r = run(Tenant(**({NEW: cfg} if cfg else {})), command="status", action=all_actions)
        wrapper, _ = load_script()
        for row in r.outputs["rows"]:
            expected = wrapper.resolve_shadow_mode(
                ACTIONS[row["action"]], row["actor"],
                wrapper.tenant_shadow_override(cfg, row["action"], row["actor"]))
            assert row["shadow"] == expected, (cfg, row)
        # framework is not shown, but must resolve the same way in both
        import SOCFWConfig as cfgmod
        for name, action_row in ACTIONS.items():
            if isinstance(action_row, dict) and "responses" in action_row:
                mine = cfgmod.effective(cfg or {}, name, action_row, "framework")[0]
                theirs = wrapper.resolve_shadow_mode(
                    action_row, "framework", wrapper.tenant_shadow_override(cfg, name, "framework"))
                assert mine == theirs, (cfg, name)


# ── shadow ───────────────────────────────────────────────────────────────────

def test_shadow_dry_run_by_default_writes_nothing():
    t = Tenant()
    r = run(t, command="shadow", action="soc-star-case", actor="ai,automation", value="off")
    assert r.outputs["dry_run"] and not r.outputs["applied"]
    assert [(c["actor"], c["from"], c["to"]) for c in r.outputs["changes"]] == [
        ("ai", "shadow", "live"), ("automation", "shadow", "live")]
    assert t.writes() == [] and t.rows == []
    assert r.outputs["creates_list"] is True
    assert "Will create SOCFWTenantConfig as a JSON list." in r.readable_output


def test_first_write_creates_a_json_list_through_the_rest_api():
    t = Tenant()
    r = run(t, command="shadow", action="soc-star-case", actor="ai,automation",
            value="off", apply="yes")
    assert r.outputs["applied"]
    assert t.writes() == ["core-api-post"]          # never the plain-text createList
    assert t.types[NEW] == "json"
    assert t.config() == {"shadow": {"soc-star-case": {"ai": False, "automation": False}}}
    assert OLD not in t.lists


def test_first_write_without_core_rest_api_names_the_integration():
    t = Tenant(core_api=False)
    with pytest.raises(RuntimeError, match="Core REST API integration"):
        run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert NEW not in t.lists


def test_existing_list_is_updated_in_place_and_keeps_its_type():
    t = Tenant(**{NEW: {"Zscaler": {"category-id": "cat-1"}}})
    run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert t.writes() == ["setList"] and t.types[NEW] == "json"
    assert t.config() == {"Zscaler": {"category-id": "cat-1"},
                          "shadow": {"soc-star-case": {"ai": False}}}


def test_default_removes_the_setting_and_reverses_the_change():
    t = Tenant(**{NEW: {"Zscaler": {"category-id": "cat-1"},
                        "shadow": {"soc-star-case": {"ai": False, "automation": False}}}})
    r = run(t, command="shadow", action="soc-star-case", actor="ai,automation",
            value="default", apply="yes")
    assert [(c["from"], c["to"]) for c in r.outputs["changes"]] == [
        ("live", "shadow"), ("live", "shadow")]
    assert t.config() == {"Zscaler": {"category-id": "cat-1"}}


def test_repeat_apply_is_a_no_op():
    t = Tenant(**{NEW: {"shadow": {"soc-star-case": {"ai": False}}}})
    r = run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert t.writes() == [] and t.rows == [] and not r.outputs["applied"]
    assert "nothing to change" in r.readable_output


def test_read_only_action_is_refused_and_not_written():
    t = Tenant()
    r = run(t, command="shadow", action="soc-enrich-domain", actor="ai", value="on", apply="yes")
    assert r.outputs["refused"] and "read-only" in r.outputs["refused"][0]["reason"]
    assert t.writes() == []


@pytest.mark.parametrize("args, message", [
    ({"action": "soc-star-case", "actor": "ai"}, "value must be"),
    ({"action": "soc-star-case", "value": "off"}, "actor is required"),
    ({"actor": "ai", "value": "off"}, "action is required"),
    ({"action": "soc-nope", "actor": "ai", "value": "off"}, "unknown action"),
    ({"action": "soc-star-case", "actor": "robot", "value": "off"}, "unknown actor"),
    ({"action": "soc-star-case", "actor": "framework", "value": "off"}, "framework is now automation"),
])
def test_shadow_bad_arguments_name_the_fix(args, message):
    t = Tenant()
    with pytest.raises(RuntimeError, match=message):
        run(t, command="shadow", **args)
    assert t.writes() == []


def test_shadow_records_one_row_per_changed_actor_outside_any_incident():
    t = Tenant(**{NEW: {"shadow": {"soc-star-case": {"ai": False}}}})
    r = run(t, command="shadow", action="soc-star-case", actor="ai,automation",
            value="off", apply="yes")
    assert r.outputs["recorded"] is True
    assert [{k: v for k, v in row.items() if k != "timestamp"} for row in t.rows] == [
        {"event_type": "config_change", "universal_command": "soc-star-case",
         "action_actor": "automation", "shadow_mode_state": "live",
         "action_status": "set off", "action_taken": "shadow -> live"}]
    assert all("incident_id" not in row and "phase" not in row for row in t.rows)


def test_failed_record_does_not_fail_the_change():
    t = Tenant(**{NEW: {}})
    t.dataset_down = True
    r = run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert r.outputs["applied"] is True and r.outputs["recorded"] is False
    assert t.config() == {"shadow": {"soc-star-case": {"ai": False}}}
    assert "record in the execution dataset was not" in r.readable_output


def test_malformed_tenant_list_is_never_overwritten():
    t = Tenant(**{NEW: "not json"})
    with pytest.raises(RuntimeError, match="not a JSON object"):
        run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert t.lists[NEW] == "not json"


def test_write_that_does_not_land_is_reported():
    t = Tenant(**{NEW: {}})
    real = t.execute

    def silent_set(command, args):
        if command == "setList":
            t.commands.append((command, args))
            return [{"Type": 1, "Contents": "Done"}]  # claims success, changes nothing
        return real(command, args)

    t.execute = silent_set
    with pytest.raises(RuntimeError, match="could not write SOCFWTenantConfig"):
        run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")


# ── set ──────────────────────────────────────────────────────────────────────

def test_set_dry_run_shows_the_change_and_writes_nothing():
    t = Tenant(**{NEW: {"Zscaler": {"category-id": "OLD-1"}}})
    r = run(t, command="set", vendor="Zscaler", arg="category-id", value="NEW-2")
    assert (r.outputs["from"], r.outputs["to"], r.outputs["dry_run"]) == ("OLD-1", "NEW-2", True)
    assert r.outputs["used_by"] == ["soc-block-domain", "soc-block-network-indicator"]
    assert t.writes() == []


def test_set_apply_writes_only_that_value_and_records_it():
    t = Tenant(**{NEW: {"Zscaler": {"category-id": "OLD-1", "using": "zia_1"},
                        "shadow": {"soc-star-case": {"automation": False}}}})
    r = run(t, command="set", vendor="zscaler", arg="Category-ID", value="NEW-2", apply="yes")
    assert r.outputs["applied"] and r.outputs["recorded"]
    assert t.config() == {"Zscaler": {"category-id": "NEW-2", "using": "zia_1"},
                          "shadow": {"soc-star-case": {"automation": False}}}
    assert [{k: v for k, v in row.items() if k != "timestamp"} for row in t.rows] == [
        {"event_type": "config_change", "vendor": "Zscaler", "action_status": "set category-id",
         "action_taken": "category-id: OLD-1 -> NEW-2"}]


def test_set_on_a_new_tenant_creates_a_json_list():
    t = Tenant()
    run(t, command="set", vendor="ThreatStopv2", arg="list_id", value="L-9", apply="yes")
    assert t.writes() == ["core-api-post"] and t.types[NEW] == "json"
    assert t.config() == {"ThreatStopv2": {"list_id": "L-9"}}


def test_set_default_removes_the_value_and_warns_when_required():
    t = Tenant(**{NEW: {"ThreatStopv2": {"list_id": "L-9"}, "Zscaler": {"category-id": "C"}}})
    r = run(t, command="set", vendor="ThreatStopv2", arg="list_id", value="default", apply="yes")
    assert t.config() == {"Zscaler": {"category-id": "C"}}
    assert r.outputs["to"] is None and "not configured" in r.readable_output


def test_set_optional_using_is_settable():
    t = Tenant(**{NEW: {}})
    run(t, command="set", vendor="Zscaler", arg="using", value="Zscaler_prod", apply="yes")
    assert t.config() == {"Zscaler": {"using": "Zscaler_prod"}}


def test_set_repeat_is_a_no_op():
    t = Tenant(**{NEW: {"Zscaler": {"category-id": "C"}}})
    r = run(t, command="set", vendor="Zscaler", arg="category-id", value="C", apply="yes")
    assert t.writes() == [] and t.rows == [] and "nothing to change" in r.readable_output


@pytest.mark.parametrize("args, message", [
    ({"vendor": "Zscaler", "arg": "url", "value": "x"}, "not a customer value any action uses"),
    ({"vendor": "Okta", "arg": "list_id", "value": "x"}, "not a customer value any action uses"),
    ({"vendor": "Zscaler", "value": "x"}, "vendor and arg are required"),
    ({"vendor": "Zscaler", "arg": "category-id"}, "value is required"),
])
def test_set_bad_arguments_name_the_fix(args, message):
    t = Tenant()
    with pytest.raises(RuntimeError, match=message):
        run(t, command="set", **args)
    assert t.writes() == []


def test_unknown_command():
    with pytest.raises(RuntimeError, match="unknown command"):
        run(Tenant(), command="pov")


# ── fail closed, reported the same way the wrapper decides it ────────────────

def _mangled_actions():
    mangled = json.loads(json.dumps(ACTIONS))
    mangled["soc-isolate-endpoint"].pop("shadow_mode")
    mangled["soc-close-issue"]["shadow_mode"] = "yes"
    mangled["soc-kill-process"]["shadow_mode_by_actor"]["analyst"] = "no"
    mangled["soc-enrich-domain"].pop("shadow_mode")
    return mangled


def test_status_reports_missing_or_garbled_settings_as_simulated():
    t = Tenant()
    t.lists["SOCFrameworkActions_V3"] = json.dumps(_mangled_actions())
    r = run(t, command="status", action="soc-isolate-endpoint,soc-close-issue,soc-kill-process,soc-enrich-domain")
    for actor in ("analyst", "ai", "automation", "issue_emergency"):
        assert cell(r, "soc-close-issue", actor)["state"] == "shadow"
        assert cell(r, "soc-kill-process", actor)["state"] == "shadow"
    assert cell(r, "soc-isolate-endpoint", "automation")["field"].endswith("(missing or unreadable)")
    assert cell(r, "soc-enrich-domain", "automation")["state"] == "live"


def test_status_agrees_with_the_wrapper_on_a_mangled_list():
    sys.path.insert(0, os.path.join(HERE, "..", "SOCCommandWrapper"))
    from SOCCommandWrapper_test import load_script
    mangled = _mangled_actions()
    t = Tenant()
    t.lists["SOCFrameworkActions_V3"] = json.dumps(mangled)
    names = [k for k, v in mangled.items() if isinstance(v, dict) and "responses" in v]
    r = run(t, command="status", action=",".join(names))
    wrapper, _ = load_script()
    for row in r.outputs["rows"]:
        assert row["shadow"] == wrapper.resolve_shadow_mode(mangled[row["action"]], row["actor"]), row
