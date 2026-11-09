"""
SOCCommandWrapper_test_once.py

A containment or eradication action runs once per target per case, whichever
path asks: the case keeps a ledger at SOCFramework.Performed, and a second
request for the same action on the same target records a duplicate row with
no time instead of dispatching.

Run: pytest Scripts/SOCCommandWrapper/SOCCommandWrapper_test_once.py -v
"""

import json

from SOCCommandWrapper_test import load_script
from SOCCommandWrapper_test_dispatch import BLOCK_DOMAIN_TWO_VENDORS, _commands_named

ISOLATE = {
    "soc-isolate-endpoint": {
        "phase": "containment", "entity_scope": "host", "shadow_mode": True,
        "reversed_by": "soc-deisolate-endpoint",
        "responses": {"EDR": {"command": "edr-isolate",
                              "inline_args": {"id": "${SOCFramework.Artifacts.Endpoint.AgentID}"}}},
    },
    "soc-deisolate-endpoint": {
        "phase": "recovery", "entity_scope": "host", "shadow_mode": True,
        "responses": {"EDR": {"command": "edr-release",
                              "inline_args": {"id": "${SOCFramework.Artifacts.Endpoint.AgentID}"}}},
    },
    "soc-enrich-endpoint": {
        "phase": "enrichment", "shadow_mode": False,
        "responses": {"EDR": {"command": "edr-get",
                              "inline_args": {"id": "${SOCFramework.Artifacts.Endpoint.AgentID}"}}},
    },
}


class Case:
    """The parent case's context, shared by every issue that writes to it."""

    def __init__(self):
        self.ledger = []

    def get_context(self, args):
        return [{"Type": 1, "Contents": json.dumps(
            {"context": {"SOCFramework": {"Performed": list(self.ledger)}}})}]

    def set_parent(self, args):
        assert args["key"] == "SOCFramework.Performed"
        self.ledger.append(args["value"])
        return [{"Type": 1, "Contents": "ok"}]


def _lists(action_map):
    def _route(args):
        name = (args or {}).get("listName")
        if name == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps(action_map)}]
        if name == "SOCActionTimeMap_V3":
            return [{"Contents": json.dumps({a: {"time_minutes": 15, "action_category": "c"}
                                             for a in action_map})}]
        return [{"Contents": "Item not found"}]
    return _route


def run(action, case, agent="agent-1", actor="automation", action_map=None, live=None,
        issue="100", parent="INCIDENT-7", ctx=None):
    action_map = json.loads(json.dumps(action_map or ISOLATE))
    if live:
        for name in live:
            action_map[name]["shadow_mode"] = False
    script, demisto = load_script()
    demisto._args = {"action": action, "list_name": "SOCFrameworkActions_V3",
                     "output_key": "UCTest.Executions", "Action_Actor": actor}
    demisto._context = ctx or {"SOCFramework": {
        "Artifacts": {"Endpoint": {"AgentID": agent}},
        "Product": {"response": "EDR", "category": "Endpoint"}, "RunID": "run-1"}}
    issue_row = {"id": issue}
    if parent:
        issue_row["parentXDRIncident"] = parent
    demisto._command_responses = {
        "getList": _lists(action_map),
        "getIssues": [{"Contents": {"data": [issue_row]}}],
        "getContext": case.get_context,
        "setParentIncidentContext": case.set_parent,
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
        "edr-isolate": [{"Type": 1, "Contents": "ok"}],
        "edr-release": [{"Type": 1, "Contents": "ok"}],
        "edr-get": [{"Type": 1, "Contents": "ok"}],
        "threatstop-block": [{"Type": 1, "Contents": "ok"}],
        "zscaler-block": [{"Type": 1, "Contents": "ok"}],
    }
    demisto._supported_commands = {"edr": [{"name": c} for c in (
        "edr-isolate", "edr-release", "edr-get", "threatstop-block", "zscaler-block")]}
    script.main()
    return demisto


def rows(demisto):
    return [json.loads(a["JSON"]) for _, a in _commands_named(demisto, "socfw-post-to-dataset")]


def test_first_request_runs_and_is_recorded_on_the_case():
    case = Case()
    d = run("soc-isolate-endpoint", case, actor="issue_emergency")
    r = rows(d)[0]
    assert r["action_status"] == "simulated" and r["action_time_minutes"] == 15
    assert r["action_target"] == "agent-1"
    entry = json.loads(case.ledger[0])
    assert entry["a"] == "soc-isolate-endpoint" and entry["t"] == "agent-1" and entry["m"] == "shadow"


def test_same_target_from_another_issue_and_path_is_a_duplicate_with_no_time():
    case = Case()
    run("soc-isolate-endpoint", case, actor="issue_emergency", issue="100")
    d = run("soc-isolate-endpoint", case, actor="automation", issue="101")
    r = rows(d)[0]
    assert r["action_status"] == "duplicate" and r["action_time_minutes"] == 0
    assert "already simulated by" in r["error_message"]
    assert len(case.ledger) == 1


def test_another_target_in_the_same_case_still_runs():
    case = Case()
    run("soc-isolate-endpoint", case, agent="agent-1")
    d = run("soc-isolate-endpoint", case, agent="agent-2")
    assert rows(d)[0]["action_status"] == "simulated"
    assert len(case.ledger) == 2


def test_a_simulation_never_blocks_a_real_action():
    case = Case()
    run("soc-isolate-endpoint", case)
    d = run("soc-isolate-endpoint", case, live=["soc-isolate-endpoint"])
    assert _commands_named(d, "edr-isolate")
    assert rows(d)[0]["action_status"] == "success"
    assert json.loads(case.ledger[-1])["m"] == "live"


def test_a_real_action_blocks_the_next_real_one():
    case = Case()
    run("soc-isolate-endpoint", case, live=["soc-isolate-endpoint"])
    d = run("soc-isolate-endpoint", case, live=["soc-isolate-endpoint"], actor="analyst")
    assert not _commands_named(d, "edr-isolate")
    assert rows(d)[0]["action_status"] == "duplicate"


def test_a_reversal_reopens_the_action_it_undoes():
    case = Case()
    run("soc-isolate-endpoint", case)
    run("soc-deisolate-endpoint", case)
    assert json.loads(case.ledger[-1]) == dict(json.loads(case.ledger[-1]), a="soc-isolate-endpoint",
                                                t="agent-1", reversed=True)
    d = run("soc-isolate-endpoint", case)
    assert rows(d)[0]["action_status"] == "simulated"


def test_recovery_itself_is_not_limited():
    case = Case()
    run("soc-deisolate-endpoint", case)
    d = run("soc-deisolate-endpoint", case)
    assert rows(d)[0]["action_status"] == "simulated"


def test_read_only_actions_never_touch_the_ledger():
    case = Case()
    run("soc-enrich-endpoint", case)
    d = run("soc-enrich-endpoint", case)
    assert len(_commands_named(d, "edr-get")) == 1 and case.ledger == []


def test_fan_out_counts_each_enforcement_point_separately():
    case = Case()
    block = json.loads(json.dumps(BLOCK_DOMAIN_TWO_VENDORS))
    block["soc-block-domain"].update(phase="containment", shadow_mode=True)
    ctx = {"SOCFramework": {"Artifacts": {"Network": {"Domain": "evil.example"}}, "RunID": "r"}}
    d = run("soc-block-domain", case, action_map=block, ctx=ctx)
    assert {r["action_status"] for r in rows(d)} == {"simulated"} and len(rows(d)) == 2
    d = run("soc-block-domain", case, action_map=block, ctx=ctx, issue="101")
    assert {r["action_status"] for r in rows(d)} == {"duplicate"} and len(rows(d)) == 2


def test_an_issue_without_a_case_keeps_its_own_ledger():
    case = Case()
    d = run("soc-isolate-endpoint", case, parent=None)
    assert rows(d)[0]["action_status"] == "simulated"
    assert case.ledger == []
    assert any(c == "Set" and a.get("key") == "SOCFramework.Performed" for c, a in d._commands)


def test_an_unreadable_ledger_does_not_stop_the_response():
    case = Case()

    def boom(args):
        raise RuntimeError("getContext down")
    case.get_context = boom
    d = run("soc-isolate-endpoint", case)
    assert rows(d)[0]["action_status"] == "simulated"
