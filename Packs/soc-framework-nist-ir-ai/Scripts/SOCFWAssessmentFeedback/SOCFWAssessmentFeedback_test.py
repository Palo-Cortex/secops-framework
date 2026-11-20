"""
SOCFWAssessmentFeedback_test.py

Characterization tests: how an analyst's judgement of the AI assessment becomes
one ai_feedback row. The feedback value is checked, the verdict being judged is
snapshotted onto the row, agreement is explicit (true, false, or none for
missing context), the analyst is the current user or else the issue owner, a
failed write stops with an error, and the War Room line asks for the comment
each kind of feedback needs.

Run: pytest Scripts/SOCFWAssessmentFeedback/SOCFWAssessmentFeedback_test.py -v
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


def _return_error(msg):
    raise Stop(msg)


def _is_error(res):
    return isinstance(res, list) and bool(res) and isinstance(res[0], dict) and res[0].get("Type") == 4


csp.return_error = _return_error
csp.isError = _is_error
csp.get_error = lambda res: res[0].get("Contents")
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWAssessmentFeedback as fb  # noqa: E402


def _get(obj, path):
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


ASSESSMENT = {"verdict": "malicious", "confidence": "high", "exposure": "contained",
              "escalate_recommended": True, "closure_recommended": False, "closure_reason": "",
              "primary_entity_name": "host1", "mitre_technique_id": "T1566"}


class Tenant:
    def __init__(self):
        self.context = {"Assessment": {"AI": dict(ASSESSMENT)},
                        "SOCFramework": {"Product": {"category": "Email", "key": "proofpoint_tap"}}}
        self.incident = {"id": 77, "name": "Phish delivered", "owner": "owner@x"}
        self.users = [{"Type": 1, "Contents": [{"username": "analyst@x", "id": "u1"}]}]
        self.post = [{"Type": 1, "Contents": "ok"}]
        self.calls = []
        self.results = []

    def execute(self, cmd, args):
        self.calls.append((cmd, args))
        if cmd == "getUsers":
            if isinstance(self.users, Exception):
                raise self.users
            return self.users
        if cmd == "socfw-post-to-dataset":
            if isinstance(self.post, Exception):
                raise self.post
            return self.post
        return [{"Type": 1, "Contents": None}]

    def row(self):
        posts = [a for c, a in self.calls if c == "socfw-post-to-dataset"]
        assert len(posts) == 1
        assert posts[0]["using"] == "socfw_ir_execution_writer"
        return json.loads(posts[0]["JSON"])


@pytest.fixture
def t(monkeypatch):
    tn = Tenant()
    monkeypatch.setattr(demisto, "executeCommand", tn.execute, raising=False)
    monkeypatch.setattr(demisto, "get", _get, raising=False)
    monkeypatch.setattr(demisto, "context", lambda: tn.context, raising=False)
    monkeypatch.setattr(demisto, "incident", lambda: tn.incident, raising=False)
    monkeypatch.setattr(fb, "return_results", tn.results.append, raising=False)
    return tn


def run(t, monkeypatch, **args):
    monkeypatch.setattr(demisto, "args", lambda: args, raising=False)
    fb.main()
    return t.results[-1]["readable_output"]


# ── input ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value", ["", "agree", None, "right"])
def test_an_unknown_feedback_value_stops_without_writing(t, monkeypatch, value):
    with pytest.raises(Stop, match="feedback must be one of correct, wrong, missing_context"):
        run(t, monkeypatch, feedback=value)
    assert not t.calls


def test_feedback_is_trimmed_and_lowercased(t, monkeypatch):
    run(t, monkeypatch, feedback="  Correct ")
    assert t.row()["feedback"] == "correct"


# ── the row ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("feedback,axis,agreement", [
    ("correct", "verdict", True),
    ("wrong", "verdict", False),
    ("missing_context", "evidence", None),
])
def test_agreement_is_explicit_and_missing_context_judges_the_evidence(t, monkeypatch, feedback, axis, agreement):
    run(t, monkeypatch, feedback=feedback)
    row = t.row()
    assert row["feedback_axis"] == axis and row["agreement"] is agreement


def test_the_row_snapshots_the_verdict_being_judged(t, monkeypatch):
    run(t, monkeypatch, feedback="wrong", note="benign admin tool")
    row = t.row()
    assert {k: row[k] for k in ASSESSMENT} == ASSESSMENT
    assert {k: row[k] for k in ("event_type", "phase", "lifecycle", "incident_id", "alert_name",
                                "alert_category", "product_key", "feedback_note", "analyst")} == {
        "event_type": "ai_feedback", "phase": "Assessment", "lifecycle": "NIST_IR", "incident_id": "77",
        "alert_name": "Phish delivered", "alert_category": "Email", "product_key": "proofpoint_tap",
        "feedback_note": "benign admin tool", "analyst": "analyst@x"}
    assert row["feedback_time"].endswith("+00:00")


@pytest.mark.parametrize("stored", [
    [dict(ASSESSMENT)],
    json.dumps(ASSESSMENT),
    [json.dumps(ASSESSMENT)],
])
def test_the_assessment_is_read_as_an_object_a_list_or_json_text(t, monkeypatch, stored):
    t.context["Assessment"]["AI"] = stored
    run(t, monkeypatch, feedback="correct")
    assert t.row()["verdict"] == "malicious"


@pytest.mark.parametrize("stored", [None, [], "not json", 5])
def test_no_readable_assessment_still_records_the_feedback(t, monkeypatch, stored):
    t.context["Assessment"]["AI"] = stored
    out = run(t, monkeypatch, feedback="correct")
    row = t.row()
    assert row["verdict"] == "" and row["escalate_recommended"] is None
    assert "AI said **no verdict recorded** / unknown confidence." in out


def test_a_bare_issue_writes_empty_strings_not_nulls(t, monkeypatch):
    t.context = {}
    t.incident = None
    run(t, monkeypatch, feedback="correct")
    row = t.row()
    assert row["incident_id"] == "" and row["alert_name"] == "" and row["alert_category"] == ""
    assert row["product_key"] == "" and row["feedback_note"] == ""


# ── who gave it ──────────────────────────────────────────────────────────────

def test_the_analyst_falls_back_to_the_user_id(t, monkeypatch):
    t.users = [{"Type": 1, "Contents": [{"id": "u1"}]}]
    run(t, monkeypatch, feedback="correct")
    assert t.row()["analyst"] == "u1"


@pytest.mark.parametrize("users", [
    [{"Type": 4, "Contents": "denied"}],
    [{"Type": 1, "Contents": []}],
    [{"Type": 1, "Contents": {"username": "a@x"}}],
    RuntimeError("no"),
])
def test_the_analyst_falls_back_to_the_issue_owner(t, monkeypatch, users):
    t.users = users
    run(t, monkeypatch, feedback="correct")
    assert t.row()["analyst"] == "owner@x"
    assert ("getUsers", {"current": "true"}) in t.calls


# ── writing ──────────────────────────────────────────────────────────────────

def test_a_rejected_write_stops_with_the_reason(t, monkeypatch):
    t.post = [{"Type": 4, "Contents": "dataset not found"}]
    with pytest.raises(Stop, match="Could not record feedback: dataset not found"):
        run(t, monkeypatch, feedback="correct")
    assert not t.results


def test_a_failed_write_stops_with_the_reason(t, monkeypatch):
    t.post = RuntimeError("instance down")
    with pytest.raises(Stop, match="Could not record feedback: instance down"):
        run(t, monkeypatch, feedback="correct")


# ── what the analyst sees ────────────────────────────────────────────────────

def test_confirming_needs_nothing_further(t, monkeypatch):
    out = run(t, monkeypatch, feedback="correct")
    assert out.splitlines()[0] == "🟢 Confirmed the assessment"
    assert "AI said **malicious** / high confidence." in out
    assert "Nothing further needed" in out


def test_wrong_asks_why_and_shows_the_note(t, monkeypatch):
    out = run(t, monkeypatch, feedback="wrong", note="benign admin tool")
    assert out.splitlines()[0] == "🔴 Marked the assessment wrong — benign admin tool"
    assert "Please comment on why it was wrong" in out


def test_missing_context_asks_what_was_missing(t, monkeypatch):
    out = run(t, monkeypatch, feedback="missing_context")
    assert out.splitlines()[0] == "🟠 Flagged missing context"
    assert "Please comment naming what was missing" in out
