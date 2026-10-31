import json
import sys
import types

if "demistomock" not in sys.modules:
    mock = types.ModuleType("demistomock")
    mock.args = lambda: {}
    mock.debug = lambda *a, **k: None
    mock.executeCommand = lambda *a, **k: []
    sys.modules["demistomock"] = mock
import demistomock  # noqa: E402

import SOCFWAnalystSelect as a  # noqa: E402

a.demisto = demistomock


def test_rank_least_loaded_then_email():
    assert a.rank({"b@x.com": 1, "a@x.com": 1, "c@x.com": 0}) == ["c@x.com", "a@x.com", "b@x.com"]


def test_run_spreads_cases_by_counting_up(monkeypatch):
    monkeypatch.setattr(a, "assign", lambda cid, email, actor: ("simulated", "shadow"))
    loads = {"a@x.com": 2, "b@x.com": 0}
    cases = [{"case_id": i} for i in range(4)]
    decisions, left = a.run(cases, loads, "automation", lambda cid: "")
    picks = [d["assignee"] for d in decisions]
    assert left == 0
    assert picks == ["b@x.com", "b@x.com", "a@x.com", "b@x.com"]
    assert loads == {"a@x.com": 3, "b@x.com": 3}


def test_run_leaves_a_case_that_gained_an_owner(monkeypatch):
    called = []
    monkeypatch.setattr(a, "assign", lambda *x: called.append(x) or ("assigned", ""))
    loads = {"a@x.com": 0}
    d, _ = a.run([{"case_id": 7}], loads, "automation", lambda cid: "someone@x.com")
    assert d[0]["status"] == "skipped" and called == [] and loads == {"a@x.com": 0}


def test_run_does_not_count_a_failed_assignment(monkeypatch):
    monkeypatch.setattr(a, "assign", lambda *x: ("failed", "bad email"))
    loads = {"a@x.com": 0}
    a.run([{"case_id": 1}], loads, "automation", lambda cid: "")
    assert loads == {"a@x.com": 0}


def test_assign_reads_shadow_and_success(monkeypatch):
    shadow = [{"HumanReadable": "### SOC Framework - SHADOW MODE (Command Not Executed)",
               "Contents": {"action": a.ACTION, "shadow_mode": True, "success": False}}]
    monkeypatch.setattr(a.demisto, "executeCommand", lambda *x, **k: shadow)
    assert a.assign(1, "a@x.com", "automation")[0] == "simulated"
    live = [{"HumanReadable": "### SOC Framework - Universal Command Resolved",
             "Contents": {"action": a.ACTION, "shadow_mode": False}},
            {"HumanReadable": "### SOC Framework - Command Success",
             "Contents": {"action": a.ACTION, "shadow_mode": False, "success": True}}]
    monkeypatch.setattr(a.demisto, "executeCommand", lambda *x, **k: live)
    assert a.assign(1, "a@x.com", "analyst")[0] == "assigned"


def test_assign_passes_the_body_as_one_json_object(monkeypatch):
    seen = {}
    monkeypatch.setattr(a.demisto, "executeCommand", lambda cmd, args: seen.update(args) or [])
    a.assign(51045, "a@x.com", "automation")
    body = json.loads(seen["target"])
    assert body["request_data"] == {"incident_id": "51045", "update_data": {"assigned_user_mail": "a@x.com"}}


def test_run_stops_at_the_budget_and_records_as_it_goes(monkeypatch):
    monkeypatch.setattr(a, "assign", lambda *x: ("simulated", ""))
    ticks = iter([0, 10, 20, 30])
    recorded = []
    decisions, left = a.run([{"case_id": i} for i in range(5)], {"a@x.com": 0}, "automation",
                            lambda cid: "", deadline=25, on_decision=recorded.append,
                            clock=lambda: next(ticks))
    assert [d["case_id"] for d in decisions] == [0, 1, 2]
    assert left == 2
    assert recorded == decisions


def test_domains_match_auto_triage_values():
    assert a.parse_domains(None) == ["Security"]
    assert a.parse_domains("security, posture") == ["Security", "Posture"]
    assert a.parse_domains("DOMAIN_SECURITY") == ["Security"]
    assert a.parse_domains(["posture", "Posture"]) == ["Posture"]
    assert a.parse_domains("security,all") is None


def test_unknown_domain_is_refused():
    import pytest
    with pytest.raises(a.SelectError, match="unknown domain"):
        a.parse_domains("secruity")


def test_open_filters_scope_by_domain_or_not():
    assert a.open_filters(["Posture"])[-1] == {"field": "case_domain", "operator": "in", "value": ["Posture"]}
    assert [f["field"] for f in a.open_filters(None)] == ["status_progress"]


def test_window_values():
    now = 1_000_000_000
    assert a.parse_window("24 hours", now) == (now - 86400) * 1000
    assert a.parse_window(None, now) == (now - 86400) * 1000
    assert a.parse_window("7 days", now) == (now - 7 * 86400) * 1000
    assert a.parse_window("3 months", now) == (now - 90 * 86400) * 1000
    assert a.parse_window("1 Day", now) == (now - 86400) * 1000
    assert a.parse_window("all", now) is None


def test_unknown_window_is_refused():
    import pytest
    for bad in ("forever", "0 days", "3 weeks"):
        with pytest.raises(a.SelectError, match="unknown window"):
            a.parse_window(bad)


def test_window_filters_the_unassigned_search_only(monkeypatch):
    seen = []
    monkeypatch.setattr(a, "search_cases", lambda filters, start=0, size=100: (seen.append(filters) or ([], 0)))
    a.unassigned_cases(["Security"], 5, since=123)
    assert {"field": "creation_time", "operator": "gte", "value": 123} in seen[0]
    seen.clear()
    a.unassigned_cases(["Security"], 5, case_id="9", since=123)
    assert all(f["field"] != "creation_time" for f in seen[0])


def test_online_users_reads_emails(monkeypatch):
    monkeypatch.setattr(a.demisto, "executeCommand",
                        lambda cmd, args: [{"Type": 1, "Contents": [{"email": "A@x.com"}, {"name": "no email"}]}])
    assert a.online_users() == {"a@x.com"}


def test_online_users_unreadable_is_none(monkeypatch):
    monkeypatch.setattr(a.demisto, "executeCommand", lambda cmd, args: [{"Type": 4, "Contents": "nope"}])
    assert a.online_users() is None


def test_loads_counted_in_one_paged_search(monkeypatch):
    pages = [[{"assigned_user_mail": "A@x.com"}] * 100, [{"assigned_user_mail": "b@x.com"}, {"assigned_user_mail": "z@x.com"}]]
    calls = []

    def fake(filters, start=0, size=100):
        calls.append((filters[-1]["value"], start))
        return pages[start // 100], None

    monkeypatch.setattr(a, "search_cases", fake)
    assert a.loads_of(["a@x.com", "b@x.com", "c@x.com"], ["Security"]) == {"a@x.com": 100, "b@x.com": 1, "c@x.com": 0}
    assert calls == [(["a@x.com", "b@x.com", "c@x.com"], 0), (["a@x.com", "b@x.com", "c@x.com"], 100)]


def test_cap_values():
    assert a.parse_cap("20") == 20
    assert a.parse_cap("unlimited") is None and a.parse_cap("0") is None
    assert a.parse_cap("") == 20 and a.parse_cap(None) == 20
    import pytest
    with pytest.raises(ValueError):
        a.parse_cap("twenty")


def test_cap_skips_full_analysts_and_stops_when_everyone_is_full(monkeypatch):
    monkeypatch.setattr(a, "assign", lambda *x: ("assigned", ""))
    loads = {"a@x.com": 1, "b@x.com": 2}
    decisions, _ = a.run([{"case_id": i} for i in range(5)], loads, "automation", lambda cid: "", cap=2)
    assert [d["assignee"] for d in decisions[:1]] == ["a@x.com"]
    assert decisions[-1]["status"] == "skipped" and "holds 2 or more" in decisions[-1]["note"]
    assert len(decisions) == 2 and loads == {"a@x.com": 2, "b@x.com": 2}


def test_unlimited_cap_assigns_everything(monkeypatch):
    monkeypatch.setattr(a, "assign", lambda *x: ("assigned", ""))
    decisions, _ = a.run([{"case_id": i} for i in range(25)], {"a@x.com": 0}, "automation", lambda cid: "")
    assert sum(d["status"] == "assigned" for d in decisions) == 25


def test_a_case_the_framework_assigned_recently_is_left_alone(monkeypatch):
    called = []
    monkeypatch.setattr(a, "assign", lambda cid, *x: called.append(cid) or ("assigned", ""))
    decisions, _ = a.run([{"case_id": 1}, {"case_id": 2}], {"a@x.com": 0}, "automation", lambda cid: "",
                         recently=lambda: {"1"})
    assert called == [2]
    assert decisions[0]["status"] == "skipped" and "last 15 minutes" in decisions[0]["note"]


def test_recent_assignments_polls_the_xql_api(monkeypatch):
    answers = [(True, {"reply": "qid-1"}),
               (True, {"reply": {"status": "PENDING"}}),
               (True, {"reply": {"status": "SUCCESS", "results": {"data": [
                   {"case_id": "51013"}, {"case_id": 51016}, {"case_id": None}]}}})]
    calls = []
    monkeypatch.setattr(a, "core_post", lambda uri, body: calls.append((uri, body)) or answers.pop(0))
    ids, why = a.recent_assignments(sleep=lambda s: None)
    assert ids == {"51013", "51016"} and why is None
    assert calls[0][1]["request_data"]["timeframe"] == {"relativeTime": 15 * 60 * 1000}
    assert calls[1][1]["request_data"]["query_id"] == "qid-1"


def test_recent_assignments_unreadable_is_reported(monkeypatch):
    monkeypatch.setattr(a, "core_post", lambda uri, body: (False, "403"))
    ids, why = a.recent_assignments(sleep=lambda s: None)
    assert ids == set() and "failed" in why
    pend = iter([(True, {"reply": "q"})] + [(True, {"reply": {"status": "PENDING"}})] * 100)
    monkeypatch.setattr(a, "core_post", lambda uri, body: next(pend))
    ids, why = a.recent_assignments(sleep=lambda s: None)
    assert ids == set() and "did not finish" in why
