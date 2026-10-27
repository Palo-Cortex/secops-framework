"""
SOCFWConfig_test.py

status and shadow against the shipped SOCFrameworkActions_V3, with an in-memory
list store standing in for the tenant. One test checks that status reports what
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
OLD = "SOCFrameworkTenantConfig_V3"


class Tenant:
    """Lists by name, and every command the script ran."""

    def __init__(self, **lists):
        self.lists = {"SOCFrameworkActions_V3": json.dumps(ACTIONS)}
        self.lists.update({k: v if isinstance(v, str) else json.dumps(v) for k, v in lists.items()})
        self.commands = []
        self.rows = []
        self.dataset_down = False

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
        if command == "socfw-post-to-dataset":
            self.rows.append(json.loads(args["JSON"]))
            return [{"Type": 4, "Contents": "writer down"}] if self.dataset_down else \
                [{"Type": 1, "Contents": "ok"}]
        if command == "createList":
            if name in self.lists:
                return [{"Type": 4, "Contents": "already exists"}]
            self.lists[name] = args["listData"]
            return [{"Type": 1, "Contents": "Done"}]
        return []

    def config(self, name=NEW):
        return json.loads(self.lists[name]) if name in self.lists else None

    def writes(self):
        return [c for c, _ in self.commands if c in ("setList", "createList")]


class Results:
    def __init__(self, readable_output=None, outputs_prefix=None, outputs=None, **kw):
        self.readable_output, self.outputs_prefix, self.outputs = (
            readable_output, outputs_prefix, outputs)


def run(tenant, **args):
    out = []
    demisto = types.SimpleNamespace(args=lambda: args, executeCommand=tenant.execute,
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


def status_of(result, action, actor):
    return next(r for r in result.outputs["rows"]
                if r["action"] == action and r["actor"] == actor)


# ── status ───────────────────────────────────────────────────────────────────

def test_status_shipped_defaults_for_starring():
    r = run(Tenant(), command="status")
    assert status_of(r, "soc-star-case", "analyst")["state"] == "live"
    assert status_of(r, "soc-star-case", "ai")["state"] == "shadow"
    assert status_of(r, "soc-star-case", "automation")["decided_by"] == "shipped_default"
    assert r.outputs["contract_version"] == 1
    assert r.outputs["tenant_config_list"] is None


def test_status_lists_mutating_actions_only_by_default():
    r = run(Tenant(), command="status")
    listed = {row["action"] for row in r.outputs["rows"]}
    assert "soc-enrich-domain" not in listed and "soc-isolate-endpoint" in listed
    assert "read-only actions" in r.readable_output


def test_status_marks_tenant_settings():
    t = Tenant(**{NEW: {"shadow": {"soc-star-case": {"ai": False}}}})
    r = run(t, command="status", action="soc-star-case")
    row = status_of(r, "soc-star-case", "ai")
    assert (row["state"], row["decided_by"]) == ("live", "tenant_config")
    assert "live ✱" in r.readable_output


def test_status_reads_legacy_list_when_new_missing():
    t = Tenant(**{OLD: {"shadow": {"soc-star-case": {"ai": False}}}})
    r = run(t, command="status")
    assert r.outputs["tenant_config_list"] == OLD
    assert status_of(r, "soc-star-case", "ai")["state"] == "live"


def test_status_agrees_with_the_wrapper_for_every_action_and_actor():
    wrapper_dir = os.path.join(HERE, "..", "SOCCommandWrapper")
    sys.path.insert(0, wrapper_dir)
    from SOCCommandWrapper_test import load_script
    flip = {"shadow": {"soc-star-case": {"ai": False, "automation": False},
                       "soc-isolate-endpoint": {"analyst": False}}}
    for cfg in (None, flip):
        r = run(Tenant(**({NEW: cfg} if cfg else {})), command="status",
                action=",".join(k for k, v in ACTIONS.items()
                                if isinstance(v, dict) and "responses" in v))
        wrapper, _ = load_script()
        for row in r.outputs["rows"]:
            expected = wrapper.resolve_shadow_mode(
                ACTIONS[row["action"]], row["actor"],
                wrapper.tenant_shadow_override(cfg, row["action"], row["actor"]))
            assert row["shadow"] == expected, (cfg, row)


# ── shadow ───────────────────────────────────────────────────────────────────

def test_shadow_dry_run_by_default_writes_nothing():
    t = Tenant()
    r = run(t, command="shadow", action="soc-star-case", actor="ai,automation", value="off")
    assert r.outputs["dry_run"] and not r.outputs["applied"]
    assert [(c["actor"], c["from"], c["to"]) for c in r.outputs["changes"]] == [
        ("ai", "shadow", "live"), ("automation", "shadow", "live")]
    assert t.writes() == []
    assert r.outputs["apply_command"].endswith("value=off apply=yes")
    assert r.outputs["creates_list"] is True


def test_shadow_apply_creates_the_list_and_writes_only_the_named_pairs():
    t = Tenant()
    r = run(t, command="shadow", action="soc-star-case", actor="ai,automation",
            value="off", apply="yes")
    assert r.outputs["applied"]
    assert t.writes() == ["createList"]
    assert t.config() == {"shadow": {"soc-star-case": {"ai": False, "automation": False}}}


def test_first_write_carries_over_the_legacy_list():
    legacy = {"Zscaler": {"category-id": "cat-1"}, "ThreatStopv2": {"list_id": "7"}}
    t = Tenant(**{OLD: legacy})
    r = run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert r.outputs["carried_over_from"] == OLD
    assert t.config() == dict(legacy, shadow={"soc-star-case": {"ai": False}})
    assert t.config(OLD) == legacy  # the old list is left alone


def test_existing_list_is_updated_in_place():
    t = Tenant(**{NEW: {"Zscaler": {"category-id": "cat-1"}}})
    run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert t.writes() == ["setList"]
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
    assert t.writes() == [] and not r.outputs["applied"]
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
])
def test_bad_arguments_name_the_fix(args, message):
    t = Tenant()
    with pytest.raises(RuntimeError, match=message):
        run(t, command="shadow", **args)
    assert t.writes() == []


def test_malformed_tenant_list_is_never_overwritten():
    t = Tenant(**{NEW: "not json"})
    with pytest.raises(RuntimeError, match="not a JSON object"):
        run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert t.lists[NEW] == "not json"


def test_write_that_does_not_land_is_reported():
    t = Tenant(**{NEW: {}})
    t.execute_orig = t.execute

    def silent_set(command, args):
        if command == "setList":
            t.commands.append((command, args))
            return [{"Type": 1, "Contents": "Done"}]  # claims success, changes nothing
        return t.execute_orig(command, args)

    t.execute = silent_set
    with pytest.raises(RuntimeError, match="reading it back"):
        run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")


def test_unknown_command():
    with pytest.raises(RuntimeError, match="unknown command"):
        run(Tenant(), command="pov")


def test_framework_is_rejected_with_its_new_name():
    t = Tenant()
    with pytest.raises(RuntimeError, match="framework is now automation"):
        run(t, command="shadow", action="soc-star-case", actor="framework", value="off")
    assert t.writes() == []


def test_status_and_wrapper_agree_on_framework_alias():
    wrapper_dir = os.path.join(HERE, "..", "SOCCommandWrapper")
    sys.path.insert(0, wrapper_dir)
    from SOCCommandWrapper_test import load_script
    run(Tenant(), command="status")   # loads SOCFWConfig with mocks
    import SOCFWConfig as cfgmod
    wrapper, _ = load_script()
    for cfg in (None, {"shadow": {"soc-star-case": {"automation": False}}},
                {"shadow": {"soc-star-case": {"framework": False, "automation": True}}}):
        for name, row in ACTIONS.items():
            if not (isinstance(row, dict) and "responses" in row):
                continue
            mine = cfgmod.effective(cfg or {}, name, row, "framework")[0]
            theirs = wrapper.resolve_shadow_mode(
                row, "framework", wrapper.tenant_shadow_override(cfg, name, "framework"))
            assert mine == theirs, (cfg, name)


# ── execution dataset record ──────────────────────────────────────────────────

def test_apply_records_one_row_per_changed_actor_outside_any_incident():
    t = Tenant(**{NEW: {"shadow": {"soc-star-case": {"ai": False}}}})
    r = run(t, command="shadow", action="soc-star-case", actor="ai,automation",
            value="off", apply="yes")
    assert r.outputs["recorded"] is True
    assert t.rows == [{"event_type": "config_change", "timestamp": t.rows[0]["timestamp"],
                       "universal_command": "soc-star-case", "action_actor": "automation",
                       "shadow_mode_state": "live", "action_status": "set off",
                       "action_taken": "shadow -> live"}]
    # The value dashboards group by incident and select by phase; neither may be set.
    assert all("incident_id" not in row and "phase" not in row for row in t.rows)


def test_dry_run_and_no_op_record_nothing():
    t = Tenant()
    run(t, command="shadow", action="soc-star-case", actor="ai", value="off")
    t2 = Tenant(**{NEW: {"shadow": {"soc-star-case": {"ai": False}}}})
    run(t2, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert t.rows == [] and t2.rows == []


def test_failed_record_does_not_fail_the_change():
    t = Tenant()
    t.dataset_down = True
    r = run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert r.outputs["applied"] is True and r.outputs["recorded"] is False
    assert t.config() == {"shadow": {"soc-star-case": {"ai": False}}}
    assert "record in the execution dataset was not" in r.readable_output
