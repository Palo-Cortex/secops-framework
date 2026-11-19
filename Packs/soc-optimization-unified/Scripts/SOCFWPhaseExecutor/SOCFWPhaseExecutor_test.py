"""Mode and authority gate a live run only; a simulated step reaches the wrapper.

would_simulate is held to SOCCommandWrapper.resolve_shadow_mode for every
shipped action, so the executor and the wrapper can never disagree about
whether a step would really run.
"""
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)
LISTS = os.path.join(HERE, "..", "..", "Lists")


def _load(name):
    return json.load(open(os.path.join(LISTS, name, name + "_data.json")))


ACTIONS = {k: v for k, v in _load("SOCFrameworkActions_V3").items() if isinstance(v, dict)}
POLICY = _load("SOCFrameworkPhasePolicy_V3")
ENV = _load("SOCFrameworkEnvironment_V3")

sys.modules.setdefault("demistomock", types.ModuleType("demistomock"))
csp = types.ModuleType("CommonServerPython")
csp.CommandResults = lambda **k: k
csp.return_results = lambda *a, **k: None
csp.return_error = lambda *a, **k: None
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWPhaseExecutor as ex  # noqa: E402

ex.demisto = types.SimpleNamespace(debug=lambda *a: None)

# Every binding resolves: the tests are about the gates, not the contract.
FULL_CTX = {"SOCFramework": {"Artifacts": {
    "EndPointID": "a1", "File": "h", "FilePath": "p", "Hash": "h",
    "Endpoint": {"AgentID": "a1"},
    "Identity": {"User": {"Email": "u@x", "Name": "u", "ID": "u", "UPN": "u@x"}},
    "Process": {"Name": "n", "PID": "1"}}}}
ALL_BRANDS = None  # registry unreadable: fail open, every vendor reachable

CONFIGS = [None,
           {"shadow": {"soc-isolate-endpoint": {"automation": False}}},
           {"shadow": {"soc-isolate-endpoint": {"framework": False}}},
           {"shadow": {"soc-isolate-endpoint": {"automation": "maybe"}}},
           {"shadow": {"soc-kill-process": {"automation": False, "framework": True}}}]


@pytest.mark.parametrize("cfg", CONFIGS)
def test_would_simulate_agrees_with_the_wrapper_for_every_action(cfg):
    sys.path.insert(0, os.path.join(HERE, "..", "SOCCommandWrapper"))
    from SOCCommandWrapper_test import load_script
    wrapper, _ = load_script()
    for name, row in ACTIONS.items():
        expected = wrapper.resolve_shadow_mode(
            row, "automation", wrapper.tenant_shadow_override(cfg, name, "automation"))
        assert ex.would_simulate(name, row, cfg) == expected, (cfg, name)


def decide(action, phase, cfg=None, entity_type="host", entity="ws-01", **step):
    plan = {"action": action, "phase": phase, "entity_type": entity_type,
            "entity_value": entity, **step}
    return ex.decide(plan, ACTIONS, {"entries": []}, POLICY, ALL_BRANDS, FULL_CTX, set(), cfg)


LIVE_ISOLATE = {"shadow": {"soc-isolate-endpoint": {"automation": False}}}
LIVE_DEISOLATE = {"shadow": {"soc-deisolate-endpoint": {"automation": False}}}


def test_shadowed_host_step_needing_approval_reaches_the_wrapper():
    d = decide("soc-isolate-endpoint", "containment")
    assert d["status"] == "dispatch" and d["shadow"] is True
    assert d["authority"] == "approve"  # still recorded: this is what live would need


def test_live_host_step_waits_for_approval():
    d = decide("soc-isolate-endpoint", "containment", LIVE_ISOLATE)
    assert d["status"] == "awaiting_approval" and "shadow" not in d


def test_shadowed_step_in_a_directions_only_phase_reaches_the_wrapper():
    d = decide("soc-deisolate-endpoint", "recovery")
    assert d["status"] == "dispatch" and d["shadow"] is True


def test_live_step_in_a_directions_only_phase_stays_a_direction():
    d = decide("soc-deisolate-endpoint", "recovery", LIVE_DEISOLATE)
    assert d["status"] == "direction"


def test_requires_human_waits_only_when_live():
    assert decide("soc-isolate-endpoint", "containment", requires_human=True)["status"] == "dispatch"
    d = decide("soc-isolate-endpoint", "containment", LIVE_ISOLATE, requires_human="true")
    assert d["status"] == "awaiting_approval"


def test_requires_human_raises_an_auto_step_to_approval_when_live():
    cfg = {"shadow": {"soc-quarantine-files": {"automation": False}}}
    assert decide("soc-quarantine-files", "containment", cfg, entity_type="artifact",
                  entity="h")["status"] == "dispatch"
    d = decide("soc-quarantine-files", "containment", cfg, entity_type="artifact", entity="h",
               requires_human=True)
    assert d["status"] == "awaiting_approval"


def test_a_contract_gap_is_still_reported_in_shadow():
    plan = {"action": "soc-delete-file", "phase": "eradication", "entity_type": "host",
            "entity_value": "ws-01"}
    ctx = {"SOCFramework": {"Artifacts": {"EndPointID": "a1"}}}
    d = ex.decide(plan, ACTIONS, {"entries": []}, POLICY, ALL_BRANDS, ctx, set(), None)
    assert d["status"] == "contract_gap"


def test_an_environment_deny_still_wins_in_shadow():
    env = {"entries": [{"name": "dcs", "entity_type": "host", "match": "^dc", "tier": "tier0",
                        "deny_actions": ["soc-isolate-endpoint"], "note": "never isolate a DC"}]}
    plan = {"action": "soc-isolate-endpoint", "phase": "containment", "entity_type": "host",
            "entity_value": "dc01"}
    d = ex.decide(plan, ACTIONS, env, POLICY, ALL_BRANDS, FULL_CTX, set(), None)
    assert d["status"] == "environment_denied"


def test_no_reachable_vendor_is_still_reported_in_shadow():
    d = ex.decide({"action": "soc-isolate-endpoint", "phase": "containment", "entity_type": "host",
                   "entity_value": "ws-01"}, ACTIONS, {"entries": []}, POLICY, set(), FULL_CTX, set(),
                  None)
    assert d["status"] == "integration_unavailable"


def test_a_disabled_phase_is_still_blocked_in_shadow():
    policy = json.loads(json.dumps(POLICY))
    policy["phases"]["containment"]["enabled"] = False
    plan = {"action": "soc-isolate-endpoint", "phase": "containment", "entity_type": "host",
            "entity_value": "ws-01"}
    d = ex.decide(plan, ACTIONS, {"entries": []}, policy, ALL_BRANDS, FULL_CTX, set(), None)
    assert d["status"] == "policy_blocked"


# ── What the wrapper said happened ───────────────────────────────────────────

REC = {"action": "soc-isolate-endpoint", "vendor": "CrowdStrikeFalconV2", "command": "x", "args": {}}
WRAPPER_SAYS = {
    "shadow": [{"Type": 1, "Contents": dict(REC, shadow_mode=True, success=False),
                "HumanReadable": "### SOC Framework - SHADOW MODE (Command Not Executed)"}],
    "executed": [{"Type": 1, "Contents": dict(REC, shadow_mode=False, success=True),
                  "HumanReadable": "### SOC Framework - Command Success"}],
    "failed": [{"Type": 1, "Contents": dict(REC, shadow_mode=False, success=False, error="401 Unauthorized"),
                "HumanReadable": "### SOC Framework - Command Failure"}],
    "error": [{"Type": 4, "Contents": "Failed to execute cs-falcon-contain-host: 429"}],
    "skipped": [{"Type": 1, "Contents": {"reason": "all context-derived command args resolved empty"},
                 "HumanReadable": "### SOC Framework - soc-isolate-endpoint: skipped (no artifact to act on)"}],
    "nothing": [],
}


def _wrapper_returns(entries):
    calls = []

    def execute(command, args):
        calls.append((command, dict(args)))
        if command == "SOCCommandWrapper":
            return entries
        return [{"Type": 1, "Contents": "ok"}]
    ex.demisto = types.SimpleNamespace(debug=lambda *a: None, executeCommand=execute)
    return calls


@pytest.mark.parametrize("said,status", [("shadow", "shadow"), ("executed", "executed"),
                                         ("failed", "failed"), ("error", "failed"),
                                         ("skipped", "skipped"), ("nothing", "failed")])
def test_the_step_status_is_what_the_wrapper_reported(said, status):
    calls = _wrapper_returns(WRAPPER_SAYS[said])
    got, why = ex.dispatch("soc-isolate-endpoint", "containment")
    assert got == status
    assert calls[0][1]["Action_Actor"] == "automation"
    if status == "failed":
        assert why


def test_a_shadowed_step_is_never_reported_as_done(monkeypatch):
    _wrapper_returns(WRAPPER_SAYS["shadow"])
    monkeypatch.setattr(ex, "get_list", lambda name: {"SOCFrameworkActions_V3": ACTIONS,
                                                      "SOCFrameworkPhasePolicy_V3": POLICY}.get(name, {}))
    monkeypatch.setattr(ex, "active_brands", lambda: ALL_BRANDS)
    ex.demisto.args = lambda: {"phase": "containment", "case_id": "7", "plan": json.dumps(
        [{"action": "soc-isolate-endpoint", "entity_type": "host", "entity_value": "ws-01"}])}
    ex.demisto.context = lambda: FULL_CTX
    results, _, _ = ex.main()
    assert [r["status"] for r in results] == ["shadow"]
    assert results[0]["reason"] == "simulated (shadow mode)"


@pytest.mark.parametrize("said", sorted(WRAPPER_SAYS))
def test_the_reader_matches_emergency_response(said):
    """The executor's copy of the wrapper reader never drifts from SOCFWEmergencyResponse's."""
    sys.path.insert(0, os.path.join(HERE, "..", "SOCFWEmergencyResponse"))
    import SOCFWEmergencyResponse as er
    action = "soc-isolate-endpoint"
    assert ex.outcome_of(action, ex.records_from(action, WRAPPER_SAYS[said])) == \
        er.outcome_of(action, er.records_from(action, WRAPPER_SAYS[said]))


@pytest.mark.parametrize("prior_mode,said", [("shadow", "already simulated by issue_emergency"),
                                             ("live", "already done by issue_emergency")])
def test_an_action_already_taken_on_the_target_is_a_duplicate_not_a_failure(prior_mode, said):
    rec = dict(REC, shadow_mode=True, success=False, duplicate=True,
               duplicate_of={"m": prior_mode, "by": "issue_emergency"})
    _wrapper_returns([{"Type": 1, "Contents": rec,
                       "HumanReadable": "### SOC Framework - soc-isolate-endpoint: not run (already ...)"}])
    assert ex.dispatch("soc-isolate-endpoint", "containment") == ("duplicate", said)
