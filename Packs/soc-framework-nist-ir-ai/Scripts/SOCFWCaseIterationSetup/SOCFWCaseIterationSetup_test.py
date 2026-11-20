"""
SOCFWCaseIterationSetup_test.py

Characterization tests: how one forEach iteration's case is pinned to scalar
context keys before the AI task. Every field becomes a string or scalar under
CaseIter, objects as compact JSON; the payload gains the action catalogue;
siblings travel comma-joined; the previous verdict rides along for reference;
Analysis.AI is cleared so each case reasons from scratch.

Run: pytest Scripts/SOCFWCaseIterationSetup/SOCFWCaseIterationSetup_test.py -v
"""
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)


class Stop(Exception):
    """return_error ends the script on the tenant; here it raises."""


demisto = types.ModuleType("demistomock")
sys.modules["demistomock"] = demisto
csp = types.ModuleType("CommonServerPython")
csp.CommandResults = lambda **k: k
csp.tableToMarkdown = lambda title, rows: json.dumps(rows)


def _return_error(msg):
    raise Stop(msg)


csp.return_error = _return_error
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWCaseIterationSetup as cis  # noqa: E402


def _get(obj, path):
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


ACTIONS = {
    "soc-isolate-endpoint": {"phase": "containment", "entity_scope": "endpoint", "reversed_by": "soc-release-endpoint"},
    "soc-delete-file": {"phase": "eradication", "entity_scope": "file", "destroys_evidence": True},
    "soc-enrich-ip": {"phase": "enrichment", "entity_scope": "ip"},
    "soc-reset-password": {"phase": "recovery"},
    "broken": "not a row",
}


class Tenant:
    def __init__(self):
        self.context = {}
        self.calls = []
        self.prior = {"verdict": "suspicious", "confidence": "low", "story": ["long"], "issue_count": 3}
        self.results = []

    def execute(self, cmd, args):
        self.calls.append((cmd, args))
        if cmd == "getList":
            return [{"Type": 1, "Contents": json.dumps(ACTIONS)}]
        if cmd == "core-api-post":
            return [{"Type": 1, "Contents": {"response": self.prior}}]
        return [{"Type": 1, "Contents": "ok"}]


@pytest.fixture
def t(monkeypatch):
    tn = Tenant()
    monkeypatch.setattr(demisto, "executeCommand", tn.execute, raising=False)
    monkeypatch.setattr(demisto, "get", _get, raising=False)
    monkeypatch.setattr(demisto, "debug", lambda *a: None, raising=False)
    monkeypatch.setattr(demisto, "setContext", lambda k, v: tn.context.__setitem__(k, v), raising=False)
    monkeypatch.setattr(cis, "return_results", tn.results.append, raising=False)
    return tn


CASE = {"ID": "42", "IssueCount": 4, "Categories": ["Email", "Endpoint"], "Window": "2026-11-20",
        "ShapeCoverage": {"kept": 2, "total": 3}, "Payload": json.dumps({"shapes": [{}, {}]}),
        "Siblings": ["43", 44]}


def run(t, monkeypatch, case):
    monkeypatch.setattr(demisto, "args", lambda: {"case": case}, raising=False)
    cis.main()
    return t.context


@pytest.mark.parametrize("raw,expected", [
    ({"ID": "1"}, {"ID": "1"}),
    ('{"ID": "1"}', {"ID": "1"}),
    ([{"ID": "1"}, {"ID": "2"}], {"ID": "2"}),
    ("not json", {}),
    ([], {}),
    (None, {}),
])
def test_this_iteration_is_the_last_case_in_an_accumulated_input(raw, expected):
    assert cis.current_case(raw) == expected


def test_every_field_is_pinned_to_a_scalar(t, monkeypatch):
    ctx = run(t, monkeypatch, CASE)
    assert ctx["CaseIter.ID"] == "42" and ctx["CaseIter.IssueCount"] == 4
    assert ctx["CaseIter.Categories"] == '["Email","Endpoint"]'
    assert ctx["CaseIter.ShapeCoverage"] == '{"kept":2,"total":3}'
    assert ctx["CaseIter.ContractCoverage"] == "" and ctx["CaseIter.ShapeContracts"] == ""
    for k, v in ctx.items():
        assert not isinstance(v, (dict, list)), k


def test_siblings_travel_comma_joined(t, monkeypatch):
    assert run(t, monkeypatch, CASE)["CaseIter.Siblings"] == "43,44"
    t.context.clear()
    assert run(t, monkeypatch, dict(CASE, Siblings="45"))["CaseIter.Siblings"] == "45"


def test_the_payload_carries_the_plan_phase_actions_only(t, monkeypatch):
    payload = json.loads(run(t, monkeypatch, CASE)["CaseIter.Payload"])
    assert payload["shapes"] == [{}, {}]
    assert payload["available_actions"] == [
        {"action": "soc-isolate-endpoint", "phase": "containment", "entity_scope": "endpoint",
         "reversed_by": "soc-release-endpoint"},
        {"action": "soc-delete-file", "phase": "eradication", "entity_scope": "file", "destroys_evidence": True},
        {"action": "soc-reset-password", "phase": "recovery", "entity_scope": ""},
    ]


def test_a_payload_that_is_not_an_object_is_left_as_it_came(t):
    assert cis.with_catalogue("[1,2]") == "[1,2]"
    assert cis.with_catalogue("not json") == "not json"


def test_the_prior_verdict_rides_along_without_its_story(t, monkeypatch):
    prior = json.loads(run(t, monkeypatch, CASE)["CaseIter.PriorVerdict"])
    assert prior == {"verdict": "suspicious", "confidence": "low", "issue_count": 3}
    uri = [a for c, a in t.calls if c == "core-api-post"][0]["uri"]
    assert uri == "/xsoar/public/v1/investigation/INCIDENT-42/context"


@pytest.mark.parametrize("prior", [{}, {"confidence": "high"}, [{"verdict": ""}]])
def test_no_verdict_on_the_case_means_no_prior(t, monkeypatch, prior):
    t.prior = prior
    assert run(t, monkeypatch, CASE)["CaseIter.PriorVerdict"] == ""


def test_the_previous_answer_is_cleared_every_iteration(t, monkeypatch):
    run(t, monkeypatch, CASE)
    assert ("DeleteContext", {"key": "Analysis.AI"}) in t.calls


def test_no_case_stops_rather_than_run_the_ai_on_nothing(t, monkeypatch):
    with pytest.raises(Stop, match="no case resolved"):
        run(t, monkeypatch, [])
    assert not t.context


def test_the_summary_counts_the_shapes(t, monkeypatch):
    run(t, monkeypatch, CASE)
    assert json.loads(t.results[-1]["readable_output"])[0]["shapes"] == 2


@pytest.mark.xfail(strict=True, reason=(
    "Known defect: a Payload that arrives as an object is pinned correctly but the "
    "summary json.loads()es the object, which raises, so it reports 0 shapes. The "
    "same dict-or-string trap SOCFWCaseVerdictReport already handles."))
def test_the_summary_counts_the_shapes_of_a_payload_object(t, monkeypatch):
    run(t, monkeypatch, dict(CASE, Payload={"shapes": [{}, {}]}))
    assert json.loads(t.results[-1]["readable_output"])[0]["shapes"] == 2
