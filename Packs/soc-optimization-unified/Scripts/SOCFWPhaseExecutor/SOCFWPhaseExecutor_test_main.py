"""
SOCFWPhaseExecutor_test_main.py

Characterisation tests for main(): the verdict on every step of a plan, each
wrapper dispatch and what it returned, the dataset row for each step that did
not run, and the War Room output, in order, compared with a golden file
captured from the code before decide() was restructured. The scenarios reach
every branch of decide.

The lists are defined here, not read from the pack, so a shipped-list change
does not move the golden file.

Regenerate the golden file only for an intended behaviour change, never to make
a refactor pass:

    SOCFW_UPDATE_GOLDEN=1 pytest SOCFWPhaseExecutor_test_main.py
"""

import copy
import json
import os
import types
from pathlib import Path

import pytest

from SOCFWPhaseExecutor_test import WRAPPER_SAYS, ex

GOLDEN = Path(__file__).parent / "test_data" / "main_golden.json"
UPDATE = os.environ.get("SOCFW_UPDATE_GOLDEN") == "1"
NOW = "2026-11-23T12:00:00Z"

AGENT = "${SOCFramework.Artifacts.Endpoint.AgentID}"
EDR = {"EDR": {"command": "edr-act", "inline_args": {"id": AGENT}},
       "EDR2": {"command": "edr2-act", "inline_args": {"id": AGENT}}}

ACTIONS = {
    "isolate": {"phase": "containment", "entity_scope": "host", "capability": "Isolate host",
                "sequence_rank": 20, "responses": EDR},
    "kill-process": {"phase": "eradication", "entity_scope": "host", "destroys_evidence": True,
                     "sequence_rank": 30, "responses": EDR},
    "collect": {"phase": "investigation", "entity_scope": "host", "sequence_rank": 10, "responses": EDR},
    "restore": {"phase": "recovery", "entity_scope": "host", "responses": EDR},
    "notify": {"phase": "notification", "entity_scope": "host", "responses": EDR},
    "block-hash": {"phase": "containment",
                   "responses": {"FW": {"command": "fw-block",
                                        "inline_args": {"hash": "${SOCFramework.Artifacts.Hash}"}}}},
    "disable-user": {"phase": "containment", "entity_scope": "identity", "responses": {
        "AD": {"command": "ad-disable", "inline_args": {"mail": "${SOCFramework.Artifacts.Identity.User.Email}"}},
        "Graph": {"command": "graph-disable", "inline_args": {"upn": "${SOCFramework.Artifacts.Identity.User.UPN}"}}}},
    "needs-alert": {"phase": "containment", "entity_scope": "host",
                    "responses": {"EDR": {"command": "edr-act", "inline_args": {"id": "${Alert.Host.ID}"}}}},
    "no-bindings": {"phase": "containment", "entity_scope": "host", "responses": {}},
}

POLICY = {"phases": {
    "containment": {"enabled": True, "mode": "execute",
                    "authority_by_scope": {"host": "approve", "identity": "auto", "artifact": "auto"}},
    "eradication": {"enabled": True, "mode": "execute", "authority_by_scope": {"host": "auto"}},
    "investigation": {"enabled": True, "mode": "execute", "authority_by_scope": {"host": "recommend_only"}},
    "recovery": {"enabled": True, "mode": "recommend", "authority_by_scope": {"host": "auto"}},
    "modeless": {"enabled": True, "authority_by_scope": {"host": "auto"}},
    "notification": {"enabled": False, "mode": "execute"},
}}

ENV = {
    "entries": [
        {"name": "dcs", "entity_type": "host", "match": "^dc", "tier": "tier0",
         "deny_actions": ["isolate", "kill-process"], "note": "never touch a DC"},
        {"name": "ad-servers", "entity_type": "host", "match": "^ad", "tier": "tier0",
         "deny_actions": ["isolate"]},
        {"name": "broken", "entity_type": "host", "match": "(", "tier": "lab"},
        {"name": "servers", "entity_type": "host", "match": "^srv", "tier": "tier1",
         "require_approval_actions": ["kill-process"], "note": "change window"},
        {"name": "labs", "entity_type": "host", "match": "^lab", "tier": "lab"},
        {"name": "kiosks", "entity_type": "host", "match": "^kiosk", "tier": "kiosk"},
        {"name": "vips", "entity_type": "identity", "match": "^ceo@", "tier": "vip"},
    ],
    "tiers": {"lab": {"authority": "auto"}, "kiosk": {"authority": "recommend_only"},
              "vip": {"authority": "approve"}, "tier1": {"authority": "auto"}},
    "defaults": {"unmatched_tier": "standard"},
}

LIVE = {"shadow": {name: {"automation": False} for name in ACTIONS}}

CTX = {"SOCFramework": {"Artifacts": {
    "Endpoint": {"AgentID": "a1"}, "Hash": "h1",
    "Identity": {"User": {"Email": "u@example.com", "UPN": "u@example.com"}}}}}
CTX_UPN_ONLY = {"SOCFramework": {"Artifacts": {"Identity": {"User": {"UPN": "u@example.com"}}}}}
CTX_EMPTY: dict = {}


def step(action: str, entity: str = "ws-01", **extra: object) -> dict:
    """One plan step on a host unless told otherwise."""
    return dict({"action": action, "entity_type": "host", "entity_value": entity}, **extra)


def s(plan: list, **spec: object) -> dict:
    """A scenario: a plan, run live on every action, all vendors reachable, the wrapper reporting success."""
    return dict({"plan": plan, "phase": "containment", "case_id": "7", "ctx": CTX, "brands": None,
                 "tenant_config": LIVE, "wrapper": "executed", "env": ENV, "policy": POLICY}, **spec)


SCENARIOS = {
    # Registry and ledger
    "unknown_action": s([step("not-in-registry")]),
    "same_step_twice_is_a_duplicate": s([step("block-hash", "h1", entity_type="artifact"),
                                         step("block-hash", "h1", entity_type="artifact"),
                                         step("block-hash", "h2", entity_type="artifact")]),
    "a_step_that_did_not_dispatch_is_not_a_duplicate": s([step("isolate"), step("isolate")]),
    "a_shadowed_step_enters_the_ledger": s([step("isolate"), step("isolate")], tenant_config={},
                                           wrapper="shadow"),
    # Environment
    "environment_deny_with_note": s([step("isolate", "dc01")]),
    "environment_deny_without_note": s([step("isolate", "ad01")]),
    "environment_deny_wins_in_shadow": s([step("isolate", "dc01")], tenant_config={}),
    "environment_deny_other_action_passes": s([step("restore", "ad01", phase="recovery")],
                                              tenant_config={}),
    "environment_requires_approval": s([step("kill-process", "srv01")], phase="eradication"),
    "environment_tier_auto": s([step("isolate", "lab01"), step("kill-process", "lab01")],
                               phase="eradication"),
    "environment_tier_recommend_only": s([step("kill-process", "kiosk01")], phase="eradication"),
    "environment_unmatched_tier": s([step("kill-process", "ws-01")], phase="eradication"),
    "environment_other_entity_type": s([step("disable-user", "ceo@example.com", entity_type="identity"),
                                        step("disable-user", "u@example.com", entity_type="identity")]),
    "environment_entity_type_from_scope": s([{"action": "disable-user", "entity_value": "ceo@example.com"},
                                             {"action": "kill-process", "entity_value": "dc01"}]),
    "environment_no_entries": s([step("kill-process")], phase="eradication", env={}),
    # Phase policy
    "phase_disabled": s([step("notify", phase="notification")]),
    "phase_not_in_policy": s([step("isolate", phase="triage")]),
    "phase_from_the_argument": s([step("kill-process")], phase="eradication"),
    "phase_on_the_step_wins": s([step("kill-process", phase="eradication")], phase="containment"),
    "no_policy": s([step("isolate")], policy={}),
    # Vendor, reachability, contract
    "no_bindings": s([step("no-bindings")]),
    "no_reachable_vendor": s([step("isolate"), step("disable-user", "u@example.com", entity_type="identity")],
                             brands=set()),
    "no_reachable_vendor_in_shadow": s([step("isolate")], brands=set(), tenant_config={}),
    "second_vendor_reachable": s([step("isolate", "lab01")], brands={"EDR2"}),
    "vendor_with_satisfiable_args_preferred": s([step("disable-user", "u@example.com", entity_type="identity")],
                                                ctx=CTX_UPN_ONLY),
    "contract_gap_on_first_reachable": s([step("disable-user", "u@example.com", entity_type="identity")],
                                         ctx=CTX_EMPTY),
    "contract_gap_outside_socframework": s([step("needs-alert")]),
    "contract_gap_in_shadow": s([step("isolate")], ctx=CTX_EMPTY, tenant_config={}),
    # Authority
    "scope_without_authority": s([step("block-hash", "h1", entity_type="artifact", phase="eradication")]),
    "requires_human_raises_auto": s([step("block-hash", "h1", entity_type="artifact", requires_human=True),
                                     step("block-hash", "h2", entity_type="artifact", requires_human="True"),
                                     step("block-hash", "h3", entity_type="artifact", requires_human="false")]),
    "requires_human_on_recommend_only": s([step("kill-process", "kiosk01", requires_human=True)],
                                          phase="eradication"),
    # Shadow and mode
    "shadow_host_step_needing_approval": s([step("isolate")], tenant_config={}, wrapper="shadow"),
    "shadow_in_a_directions_only_phase": s([step("restore", phase="recovery")], tenant_config={},
                                           wrapper="shadow"),
    "live_in_a_directions_only_phase": s([step("restore", phase="recovery")]),
    "live_phase_without_mode": s([step("restore", phase="modeless")]),
    "read_only_phase_is_live_by_default": s([step("collect", phase="investigation")], tenant_config={}),
    "shadow_override_for_another_actor": s([step("block-hash", "h1", entity_type="artifact")],
                                           tenant_config={"shadow": {"block-hash": {"framework": False}}},
                                           wrapper="shadow"),
    "shadow_mode_on_the_entry": s([step("block-hash", "h1", entity_type="artifact")], tenant_config={},
                                  actions={**ACTIONS, "block-hash": {**ACTIONS["block-hash"], "shadow_mode": False}}),
    # What the wrapper said
    "wrapper_failed": s([step("block-hash", "h1", entity_type="artifact")], wrapper="failed"),
    "wrapper_error": s([step("block-hash", "h1", entity_type="artifact")], wrapper="error"),
    "wrapper_skipped": s([step("block-hash", "h1", entity_type="artifact")], wrapper="skipped"),
    "wrapper_nothing": s([step("block-hash", "h1", entity_type="artifact")], wrapper="nothing"),
    "wrapper_duplicate": s([step("block-hash", "h1", entity_type="artifact")], wrapper="duplicate_live"),
    # Ordering and evidence
    "plan_order_kept": s([step("kill-process", "lab01", order=1), step("collect", "lab01", order=2),
                          step("isolate", "lab01", order=3)], tenant_config={}, wrapper="shadow"),
    "rank_order_when_any_order_missing": s([step("kill-process", "lab01", order=1),
                                            step("isolate", "lab01"), step("collect", "lab01")],
                                           tenant_config={}, wrapper="shadow"),
    # Plan source and run identity
    "plan_from_context": s(None, ctx={**CTX, "SOCFramework": {**CTX["SOCFramework"], "Phase": {
        "Proposed": [step("isolate", "lab01", rationale="contain the beacon")]}}}),
    "no_case_id": s([step("isolate", "kiosk01", rationale="kiosk is shared")], case_id=""),
    "empty_plan": s([]),
}


def _run(name: str) -> dict:
    """Run main() once for a scenario and record every tenant call, the verdicts and the War Room output."""
    spec = copy.deepcopy(SCENARIOS[name])
    calls: list = []
    lists = {ex.ACTIONS_LIST: spec.get("actions", ACTIONS), ex.ENV_LIST: spec["env"],
             ex.POLICY_LIST: spec["policy"], ex.TENANT_CONFIG_LIST: spec["tenant_config"]}

    def execute(command: str, args: dict) -> list:
        calls.append([command, json.loads(args["JSON"]) if command == "socfw-post-to-dataset" else args])
        if command == "SOCCommandWrapper":
            reply = json.dumps(WRAPPER_SAYS[spec["wrapper"]]).replace("soc-isolate-endpoint", args["action"])
            return json.loads(reply)
        return [{"Type": 1, "Contents": "ok"}]

    args = {"phase": spec["phase"], "case_id": spec["case_id"]}
    if spec["plan"] is not None:
        args["plan"] = json.dumps(spec["plan"])
    saved = (ex.demisto, ex.get_list, ex.active_brands, ex.utc_now)
    ex.demisto = types.SimpleNamespace(debug=lambda *a: None, executeCommand=execute,
                                       args=lambda: args, context=lambda: spec["ctx"])
    ex.get_list = lambda list_name: copy.deepcopy(lists.get(list_name, {}))
    ex.active_brands = lambda: spec["brands"]
    ex.utc_now = lambda: NOW
    try:
        results, phase, case_id = ex.main()
    finally:
        ex.demisto, ex.get_list, ex.active_brands, ex.utc_now = saved
    return {"results": results, "calls": calls, "war_room": ex.render(results, phase, case_id)}


def _golden() -> dict:
    """The recorded outcome of every scenario."""
    return json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_main_matches_golden(name: str) -> None:
    """
    Given a plan, the lists and a tenant in a known state
    When the phase executor runs it
    Then every verdict, wrapper dispatch, dataset row and War Room line matches the golden file
    """
    got = _run(name)
    if UPDATE:
        golden = _golden()
        golden[name] = got
        GOLDEN.write_text(json.dumps(golden, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
        return
    assert name in _golden(), f"no golden for {name}; generate it from main with SOCFW_UPDATE_GOLDEN=1"
    assert json.dumps(got, ensure_ascii=False, sort_keys=True) == \
        json.dumps(_golden()[name], ensure_ascii=False, sort_keys=True)


def test_golden_has_no_stale_scenarios() -> None:
    """
    Given the golden file
    When its scenario names are compared with this file's
    Then each golden entry still has a scenario that produces it
    """
    assert set(_golden()) <= set(SCENARIOS)
