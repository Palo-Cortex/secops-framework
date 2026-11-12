"""What the case response driver records per phase, with the executor stubbed.

The executor's own decisions are tested in SOCFWPhaseExecutor_test; here the
driver is held to what it does with them: which issue a step runs in, what
counts as done, what holds the next phase, and the declared contract it writes.
"""
import json
import os
import sys
import types

HERE = os.path.dirname(__file__)
LISTS = os.path.join(HERE, "..", "..", "Lists")
CONTRACT = json.load(open(os.path.join(LISTS, "SOCFrameworkPhaseContract_V3",
                                       "SOCFrameworkPhaseContract_V3_data.json")))
DECLARED = CONTRACT["writes_by_phase"]

demisto = types.ModuleType("demistomock")
demisto.debug = lambda *a: None
demisto.get = lambda obj, path: None
sys.modules["demistomock"] = demisto
csp = types.ModuleType("CommonServerPython")
csp.entryTypes = {"error": 4, "note": 1}
csp.DemistoException = Exception
csp.CommandResults = lambda **k: k
csp.return_results = lambda *a, **k: None
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWCaseResponse as cr  # noqa: E402

POLICY = {"phases": {"containment": {"enabled": True, "mode": "execute"},
                     "eradication": {"enabled": True, "mode": "directions_only"},
                     "recovery": {"enabled": True, "mode": "directions_only"}}}
ACTIONS = {"soc-isolate-endpoint": {"responses": {"X": {"inline_args": {"id": "${SOCFramework.Artifacts.EndPointID}"}}}},
           "soc-disable-user": {"responses": {"X": {"inline_args": {"u": "${SOCFramework.Artifacts.User}"}}}},
           "soc-deisolate-endpoint": {"responses": {"X": {"inline_args": {"id": "${SOCFramework.Artifacts.EndPointID}"}}}}}
SCOPE = [{"id": "h1", "type": "host", "name": "ws-01", "evidence_refs": ["11", "12"]},
         {"id": "u1", "type": "identity", "name": "bob", "evidence_refs": ["12"]}]
# Issue 11 names the host but not its agent id; issue 12 carries the agent id
# and the user; issue 13 is another host and another user in the same case.
CONTEXTS = {"11": {"SOCFramework": {"Artifacts": {"Endpoint": {"Hostname": "ws-01"}}}},
            "12": {"SOCFramework": {"Artifacts": {"EndPointID": "a1", "Endpoint": {"Hostname": "WS-01"},
                                                  "User": "SKT\\bob"}}},
            "13": {"SOCFramework": {"Artifacts": {"EndPointID": "a9", "Endpoint": {"Hostname": "dc-01"},
                                                  "Identity": {"User": {"UPN": "svc$@skt.local"}}}}}}


def contract(**plans):
    c = {"scope": SCOPE, "verify_by_human": [], "recorded": {}}
    for p in cr.PHASES:
        c[p] = plans.get(p, [])
    return c


def step(n, action, target, refs=("11",), requires_human=False):
    return {"step": n, "action": action, "target": target, "why": "w",
            "evidence_refs": list(refs), "requires_human": requires_human}


posted = []


def run(phase, plan, decisions, ledger=(set(), set()), prior=0, finished=None):
    """Run one phase; decisions maps action -> the executor's answer. Returns (rows, outstanding, sent)."""
    sent = []

    def fake_run_step(s, entity, ph, case_id, issue):
        sent.append((s["action"], issue))
        return dict(decisions[s["action"]])

    cr.run_step = fake_run_step
    cr.get_context = lambda inv: CONTEXTS.get(str(inv), {})
    cr.post_row = lambda payload: None
    done, no_instance = set(ledger[0]), set(ledger[1])
    c = contract(**{phase: plan})
    c["finished"] = {phase: dict(finished or {})}
    posted.clear()
    cr.post_row = lambda payload: posted.append(payload)
    rows, outstanding = cr.run_phase(phase, c, "500", (done, no_instance),
                                     POLICY, ACTIONS, None, ["11", "12", "13"], {}, prior)
    return rows, outstanding, sent


SHADOW = {"status": "dispatched", "shadow": True, "vendor": "X"}


def test_a_step_runs_in_the_issue_whose_contract_fills_the_binding():
    rows, _, sent = run("containment", [step(1, "soc-isolate-endpoint", "h1", refs=("11",))],
                        {"soc-isolate-endpoint": SHADOW})
    assert sent == [("soc-isolate-endpoint", "12")]
    assert rows[0]["issue"] == "12" and rows[0]["shadow"] is True


def test_shadowed_steps_never_hold_the_next_phase():
    _, outstanding, _ = run("containment", [step(1, "soc-isolate-endpoint", "h1", requires_human=True)],
                            {"soc-isolate-endpoint": SHADOW})
    assert outstanding == 0


def test_requires_human_is_handed_to_the_executor_not_decided_here():
    captured = {}

    def fake(s, entity, ph, case_id, issue):
        captured.update(s)
        return dict(SHADOW)

    cr.run_step = fake
    cr.get_context = lambda inv: CONTEXTS.get(str(inv), {})
    cr.post_row = lambda p: None
    cr.run_phase("containment", contract(containment=[step(1, "soc-isolate-endpoint", "h1", requires_human=True)]),
                 "500", (set(), set()), POLICY, ACTIONS, None, ["11", "12"], {}, 0)
    assert captured["requires_human"] is True


def test_a_live_step_awaiting_approval_holds_the_next_phase():
    _, outstanding, _ = run("containment", [step(1, "soc-isolate-endpoint", "h1")],
                            {"soc-isolate-endpoint": {"status": "awaiting_approval", "reason": "approve"}})
    assert outstanding == 1


def test_a_gap_is_reported_and_does_not_hold_the_next_phase():
    _, outstanding, _ = run("containment", [step(1, "soc-isolate-endpoint", "h1")],
                            {"soc-isolate-endpoint": {"status": "contract_gap", "reason": "x"}})
    assert outstanding == 0


def test_an_execute_phase_waits_while_the_one_before_awaits_a_person():
    rows, outstanding, sent = run("containment", [step(1, "soc-isolate-endpoint", "h1")],
                                  {"soc-isolate-endpoint": SHADOW}, prior=1)
    assert rows[0]["status"] == "waiting" and sent == []


def test_another_target_isolated_in_the_case_does_not_mark_this_one_done():
    # The ledger shows an isolate in issue 12 - of some host. This step's host
    # has not been isolated, so it is sent; the wrapper decides if it repeats.
    rows, _, sent = run("containment", [step(1, "soc-isolate-endpoint", "h1", refs=("11",))],
                        {"soc-isolate-endpoint": SHADOW},
                        ledger=({("12", "soc-isolate-endpoint")}, set()))
    assert sent == [("soc-isolate-endpoint", "12")] and rows[0]["status"] == "dispatched"


def test_a_step_finished_last_pass_for_its_own_target_is_not_sent_again():
    rows, _, sent = run("containment", [step(1, "soc-isolate-endpoint", "h1")],
                        {"soc-isolate-endpoint": SHADOW},
                        finished={("soc-isolate-endpoint", "ws-01", "12"): {"status": "dispatched"}})
    assert rows[0]["status"] == "done" and sent == []


def test_finished_for_a_different_target_does_not_count():
    rows, _, sent = run("containment", [step(1, "soc-isolate-endpoint", "h1")],
                        {"soc-isolate-endpoint": SHADOW},
                        finished={("soc-isolate-endpoint", "dc-01", "13"): {"status": "dispatched"}})
    assert sent and rows[0]["status"] == "dispatched"


def test_finished_in_another_issue_does_not_count_for_this_one():
    # Two files on one host live in two issues; the first one done is not the second.
    rows, _, sent = run("containment", [step(1, "soc-isolate-endpoint", "h1")],
                        {"soc-isolate-endpoint": SHADOW},
                        finished={("soc-isolate-endpoint", "ws-01", "11"): {"status": "dispatched"}})
    assert sent == [("soc-isolate-endpoint", "12")]


def test_a_step_never_runs_in_an_issue_about_someone_else():
    # bob's only evidence ref is issue 13, whose user is svc$: running there would
    # disable svc$. Issue 12 names bob, so it runs there instead.
    rows, _, sent = run("containment", [step(1, "soc-disable-user", "u1", refs=("13",))],
                        {"soc-disable-user": SHADOW})
    assert sent == [("soc-disable-user", "12")]


def test_no_issue_carrying_the_target_is_a_gap_not_a_run_elsewhere():
    scope = list(SCOPE)
    SCOPE.append({"id": "u2", "type": "identity", "name": "frieda@skt.local", "evidence_refs": ["13"]})
    try:
        rows, _, sent = run("containment", [step(1, "soc-disable-user", "u2", refs=("13",))],
                            {"soc-disable-user": SHADOW})
    finally:
        SCOPE[:] = scope
    assert sent == [] and rows[0]["status"] == "contract_gap"
    assert rows[0]["reason"] == "no issue in the case carries identity frieda@skt.local"


def test_a_skip_from_the_last_pass_is_reported_not_sent_or_posted_again():
    rows, _, sent = run("containment", [step(1, "soc-isolate-endpoint", "h1")],
                        {"soc-isolate-endpoint": SHADOW},
                        finished={("soc-isolate-endpoint", "ws-01", "12"):
                                  {"status": "skipped", "reason": "no implementation for source vendor"}})
    assert sent == [] and posted == []
    assert rows[0]["status"] == "skipped" and rows[0]["reason"] == "no implementation for source vendor"


def test_name_forms_match_short_and_qualified_names():
    assert cr.name_forms("frieda@skt.local") & cr.name_forms("SKT\\frieda")
    assert cr.name_forms("bannik.skt.local") & cr.name_forms("BANNIK")
    assert not cr.name_forms("frieda@skt.local") & cr.name_forms("bannik$@skt.local")
    assert cr.name_forms("10.20.10.9") == {"10.20.10.9"}


def test_a_duplicate_answer_from_the_wrapper_counts_as_done():
    ctx = {"SOCFramework": {"Phase": {"Dispatch": [
        {"action": "soc-isolate-endpoint", "timestamp": "2026-11-09T10:00:00Z", "duplicate": True,
         "duplicate_of": {"m": "shadow", "by": "issue_emergency"}}]}}}
    cr.demisto.get = lambda obj, path: ((obj.get("SOCFramework") or {}).get("Phase") or {}).get("Dispatch")
    out = cr.dispatch_outcome(ctx, "soc-isolate-endpoint")
    cr.demisto.get = lambda obj, path: None
    assert out == {"status": "done", "reason": "already simulated by issue_emergency"}


def test_no_instance_is_reported_once_and_not_sent_again():
    rows, _, sent = run("recovery", [step(1, "soc-deisolate-endpoint", "h1")],
                        {"soc-deisolate-endpoint": SHADOW},
                        ledger=(set(), {("12", "soc-deisolate-endpoint")}))
    assert rows[0]["status"] == "integration_unavailable" and sent == []


def test_containment_writes_exactly_the_declared_targets():
    rows, out, _ = run("containment", [step(1, "soc-isolate-endpoint", "h1"),
                                       step(2, "soc-disable-user", "u1", refs=("12",))],
                       {"soc-isolate-endpoint": SHADOW, "soc-disable-user": SHADOW})
    values = cr.phase_targets("containment", rows, cr.phase_state(rows, out), contract(),
                              DECLARED["containment"])
    declared = {w["target"].split(".", 1)[1] for w in DECLARED["containment"]}
    assert set(values) == declared
    assert values["isolated_hosts"] == ["ws-01"] and values["disabled_users"] == ["bob"]
    assert values["status"] == "complete" and values["required"] is True
    assert all("simulated" in line for line in values["story"])


def test_eradication_and_recovery_write_their_declared_targets():
    for phase in ("eradication", "recovery"):
        declared = {w["target"].split(".", 1)[1] for w in DECLARED[phase]}
        values = cr.phase_targets(phase, [], "nothing_to_do", contract(), DECLARED[phase])
        assert set(values) == declared, phase


def test_report_lists_what_was_eradicated_and_what_to_monitor():
    c = contract()
    rows = [{"step": 1, "action": "soc-isolate-endpoint", "target": "ws-01", "status": "dispatched", "shadow": True},
            {"step": 2, "action": "soc-disable-user", "target": "bob", "status": "contract_gap",
             "reason": "unresolved arguments: X"}]
    eradicated, monitor, tel = cr.artifact_report(c, rows, "Endpoint: CrowdStrike Falcon (EDR)")
    assert eradicated == [{"type": "host", "value": "ws-01", "action": "soc-isolate-endpoint",
                           "status": "simulated"}]
    # The gap comes first with its reason; the rest of scope follows; nothing twice.
    assert monitor[0] == {"type": "identity", "value": "bob", "why": "not eradicated: unresolved arguments: X"}
    assert [m["value"] for m in monitor] == ["bob", "ws-01"]
    assert monitor[1]["why"].startswith("in scope")


def test_eradication_and_recovery_carry_the_report_in_their_declared_targets():
    report = ([{"type": "host", "value": "ws-01", "action": "a", "status": "simulated"}],
              [{"type": "identity", "value": "bob", "why": "in scope (victim)"}],
              "Endpoint: CrowdStrike Falcon (EDR)")
    e = cr.phase_targets("eradication", [], "nothing_to_do", contract(), DECLARED["eradication"], report)
    r = cr.phase_targets("recovery", [], "nothing_to_do", contract(), DECLARED["recovery"], report)
    assert e["artifacts"] == report[0]
    assert r["monitor"] == report[1] and r["telemetry"] == report[2]
    assert r["monitoring_required"] is True and r["monitoring_scope"] == "identity bob"


def test_telemetry_names_each_source_once():
    ctxs = {"1": {"SOCFramework": {"Product": {"category": "Endpoint", "response": "CrowdStrike Falcon", "type": "EDR"}}},
            "2": {"SOCFramework": {"Product": {"category": "Endpoint", "response": "CrowdStrike Falcon", "type": "EDR"}}},
            "3": {"SOCFramework": {"Product": {"category": "Email", "response": "Proofpoint TAP"}}},
            "4": {}}
    cr.demisto.get = lambda obj, path: (((obj or {}).get("SOCFramework") or {}).get("Product"))
    assert cr.case_telemetry(["1", "2", "3", "4"], ctxs) == \
        "Endpoint: CrowdStrike Falcon (EDR); Email: Proofpoint TAP"
    assert cr.case_telemetry(["4"], ctxs).startswith("unknown")
    cr.demisto.get = lambda obj, path: None


def test_dataset_flattening_is_one_readable_string():
    assert cr.flat([{"type": "file", "value": "abc", "action": "soc-delete-file", "status": "simulated"}],
                   ("action", "status")) == "file:abc (soc-delete-file, simulated)"


def test_ledger_splits_done_from_no_instance():
    done, no_instance = cr.ledger_index([
        {"incident_id": "1", "universal_command": "a", "action_status": "shadow"},
        {"incident_id": "2", "universal_command": "b", "action_status": "no_instance"},
        {"incident_id": "3", "universal_command": "c", "action_status": "failed"}])
    assert done == {("1", "a")} and no_instance == {("2", "b")}


def test_a_later_analysis_pass_is_the_one_read():
    assert cr.as_obj(['[{"step": 1}]', '[{"step": 2}]']) == [{"step": 2}]


def test_the_story_says_simulated_only_for_steps_that_ran():
    story = cr.phase_story([
        {"step": 1, "action": "a", "target": "t", "status": "dispatched", "shadow": True},
        {"step": 2, "action": "b", "target": "t", "status": "contract_gap", "shadow": True,
         "reason": "unresolved arguments: X"}])
    assert story[0].endswith("(simulated - shadow mode)")
    assert story[1].endswith("(unresolved arguments: X)")


def test_resolved_cases_get_no_response():
    cr.api = lambda uri, body: {"reply": {"incidents": [
        {"incident_id": "1", "status": "new"}, {"incident_id": "2", "status": "resolved_other"},
        {"incident_id": "3", "status": "under_investigation"}]}}
    cr.demisto.get = lambda obj, path: obj["reply"]["incidents"]
    assert cr.open_cases(["1", "2", "3"]) == ["1", "3"]
    cr.demisto.get = lambda obj, path: None


def test_an_unreadable_status_keeps_every_case():
    def boom(uri, body):
        raise Exception("500")
    cr.api = boom
    assert cr.open_cases(["1", "2"]) == ["1", "2"]


def test_a_pass_that_ran_and_the_next_that_finds_it_done_read_the_same():
    first = [{"action": "a", "target": "t", "status": "dispatched", "issue": "12"}]
    second = [{"action": "a", "target": "t", "status": "done", "issue": "12"}]
    assert cr.step_signature(first) == cr.step_signature(second)


def test_a_missing_or_stale_step_record_counts_as_a_change():
    # The story can match while the record under it is missing: that phase
    # must be rewritten, or the next pass has nothing to know its steps by.
    rows = [{"action": "a", "target": "t", "status": "dispatched", "issue": "12"}]
    assert cr.step_signature(rows) != cr.step_signature([])
    assert cr.step_signature(rows) != cr.step_signature([dict(rows[0], issue=None)])


def _respond_once(recorded_story, recorded_steps):
    writes = []
    contract_ = {"verdict": "tp", "response_recommended": "true", "scope": SCOPE, "verify_by_human": [],
                 "recorded": {"containment": recorded_story}, "recorded_steps": {"containment": recorded_steps},
                 "finished": {}, "containment": [step(1, "soc-isolate-endpoint", "h1", refs=("12",))],
                 "eradication": [], "recovery": []}
    cr.read_contract = lambda case_id: (contract_, None)
    cr.member_issues = lambda case_id: ["11", "12", "13"]
    cr.case_telemetry = lambda members, contexts: "EDR"
    cr.get_context = lambda inv: CONTEXTS.get(str(inv), {})
    cr.run_step = lambda s, e, ph, c, i: dict(SHADOW)
    cr.post_row = lambda payload: None
    cr.post_to_case = lambda case_id, md: None
    cr.write_phase = lambda case_id, issue, phase, values: writes.append(phase) or True
    out = cr.respond("500", [], POLICY, ACTIONS, DECLARED, None)
    return writes, out


def test_same_story_with_no_step_record_is_still_written():
    story = ["✅ 1. soc-isolate-endpoint -> ws-01 (simulated - shadow mode)"]
    writes, out = _respond_once(story, [])
    assert writes == ["containment"]


def test_same_story_and_same_steps_write_nothing():
    story = cr.phase_story([{"step": 1, "action": "soc-isolate-endpoint", "target": "ws-01",
                             "status": "dispatched", "shadow": True, "why": "w"}])
    steps = [("soc-isolate-endpoint", "ws-01", "ran", "12")]
    writes, out = _respond_once(story, steps)
    assert writes == [] and out.get("note") == "unchanged"
