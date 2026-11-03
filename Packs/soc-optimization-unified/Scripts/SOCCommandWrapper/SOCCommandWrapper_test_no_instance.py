"""
SOCCommandWrapper_test_no_instance.py

Shadow rows must not credit time to an integration the tenant doesn't have.
command_served asks getAllSupportedCommands by exact command name:

  served        -> simulated, time credited          (happy path, unchanged)
  not served    -> no_instance, 0 minutes, row kept   (the fix)
  registry down -> simulated, time credited          (fail open)
  live path     -> never consults the registry        (unchanged)

Run: pytest Scripts/SOCCommandWrapper/SOCCommandWrapper_test_no_instance.py -v
"""

import json

from SOCCommandWrapper_test import load_script
from SOCCommandWrapper_test_dispatch import (
    BLOCK_DOMAIN_TWO_VENDORS, _args, _ctx, _commands_named)


def _lists(action_map, minutes=15):
    """Action list + a time map that credits every action `minutes`."""
    def _route(args):
        name = (args or {}).get("listName")
        if name == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps(action_map)}]
        if name == "SOCActionTimeMap_V3":
            return [{"Contents": json.dumps(
                {a: {"time_minutes": minutes, "action_category": "containment"}
                 for a in action_map})}]
        return [{"Contents": "Item not found"}]
    return _route


def _shadow_map():
    action_map = json.loads(json.dumps(BLOCK_DOMAIN_TWO_VENDORS))
    action_map["soc-block-domain"]["shadow_mode"] = True
    return action_map


def _dataset_rows(demisto):
    return [json.loads(args["JSON"]) for _, args in _commands_named(demisto, "socfw-post-to-dataset")]


def _run_shadow(supported):
    script, demisto = load_script()
    demisto._args = _args()
    demisto._context = _ctx("evil.example")
    demisto._supported_commands = supported
    demisto._command_responses = {
        "getList": _lists(_shadow_map()),
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }
    script.main()
    return demisto


def test_served_command_is_simulated_and_credited():
    demisto = _run_shadow({"ThreatStop_instance_1": [{"name": "threatstop-block"}],
                           "Zscaler_instance_1": [{"name": "zscaler-block"}]})
    rows = {r["vendor"]: r for r in _dataset_rows(demisto)}
    assert set(rows) == {"ThreatStop", "Zscaler"}
    for r in rows.values():
        assert r["action_status"] == "simulated"
        assert r["execution_mode"] == "shadow"
        assert r["action_time_minutes"] == 15
    assert not _commands_named(demisto, "threatstop-block")
    assert not _commands_named(demisto, "zscaler-block")


def test_unserved_command_is_no_instance_with_zero_minutes():
    # Only ThreatStop is installed; Zscaler is in the ladder but not on the tenant.
    demisto = _run_shadow({"ThreatStop_instance_1": [{"name": "threatstop-block"}]})
    rows = {r["vendor"]: r for r in _dataset_rows(demisto)}
    assert rows["ThreatStop"]["action_status"] == "simulated"
    assert rows["ThreatStop"]["action_time_minutes"] == 15
    assert rows["Zscaler"]["action_status"] == "no_instance"
    assert rows["Zscaler"]["action_time_minutes"] == 0
    assert rows["Zscaler"]["execution_mode"] == "shadow"
    assert rows["Zscaler"]["has_error"] is False
    # the context record says why, and nothing was dispatched
    recs = demisto.get(demisto._context, "UCTest.Executions")
    assert [r for r in recs if r["vendor"] == "Zscaler"][0]["no_instance"] is True
    assert not _commands_named(demisto, "zscaler-block")


def test_registry_unavailable_fails_open_to_simulated():
    demisto = _run_shadow(None)  # mock raises -> command_served returns None
    rows = _dataset_rows(demisto)
    assert len(rows) == 2
    assert all(r["action_status"] == "simulated" for r in rows)
    assert all(r["action_time_minutes"] == 15 for r in rows)


def test_empty_registry_is_unknown_not_absent():
    demisto = _run_shadow({})
    assert all(r["action_status"] == "simulated" for r in _dataset_rows(demisto))


def test_live_path_ignores_registry():
    # Live, with the registry saying nothing is served: the platform answers,
    # not the registry. The command must still be dispatched.
    script, demisto = load_script()
    demisto._args = _args()
    demisto._context = _ctx("evil.example")
    demisto._supported_commands = {"other": [{"name": "unrelated"}]}
    demisto._command_responses = {
        "getList": _lists(json.loads(json.dumps(BLOCK_DOMAIN_TWO_VENDORS))),
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
        "threatstop-block": [{"Type": 1, "Contents": "ok"}],
        "zscaler-block": [{"Type": 1, "Contents": "ok"}],
    }
    script.main()
    assert _commands_named(demisto, "threatstop-block")
    assert _commands_named(demisto, "zscaler-block")
    assert all(r["action_status"] == "success" for r in _dataset_rows(demisto))
