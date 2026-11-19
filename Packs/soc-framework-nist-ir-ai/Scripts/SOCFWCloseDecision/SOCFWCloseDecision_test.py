"""Guard tests for decide().

Covers the two guards that changed on 17 Sep: the assigned-user test (which
replaced a status test that read every running lifecycle as human-owned), and
the truncation refusal (an unfinished reply whose blocker list never arrived).
"""
import sys
import types

# demistomock and CommonServerPython are provided by the SDK test harness; stub
# only what import time needs so the module imports standalone.
sys.modules.setdefault("demistomock", types.ModuleType("demistomock"))
if "CommonServerPython" not in sys.modules:
    csp = types.ModuleType("CommonServerPython")
    csp.CommandResults = object
    csp.return_results = lambda *a, **k: None
    csp.isError = lambda *a, **k: False
    sys.modules["CommonServerPython"] = csp

import SOCFWCloseDecision as scd  # noqa: E402
from SOCFWCloseDecision import decide  # noqa: E402

CLOSEABLE = {
    "verdict": "benign",
    "exposure": "none",
    "already_contained": True,
    "closure_recommended": True,
    "closure_confidence": "high",
    "closure_blockers": [],
}
POLICY = {"min_closure_confidence": "high", "require_no_blockers": True}


def test_closes_when_policy_satisfied():
    ok, reason = decide(dict(CLOSEABLE), {}, POLICY, "email")
    assert ok, reason


def test_assigned_user_blocks():
    ok, reason = decide(dict(CLOSEABLE), {"owner": "aanalyst"}, POLICY, "email")
    assert not ok
    assert reason == "assigned to an analyst"


def test_running_automation_does_not_block():
    """A status off New with no assignee is the framework working, not a person.

    This is the regression: the previous guard ORed owner with status and read
    every issue whose lifecycle had started as already being worked.
    """
    for status in ("2", "3", "In Progress", ""):
        ok, reason = decide(dict(CLOSEABLE), {"status": status}, POLICY, "email")
        assert ok, f"status={status!r} wrongly blocked: {reason}"


def test_starred_still_blocks():
    ok, reason = decide(dict(CLOSEABLE), {"starred": "true"}, POLICY, "email")
    assert not ok
    assert "starred" in reason


def test_truncated_blocks_even_with_empty_blockers():
    """closure_blockers is emitted late, so truncation empties it silently."""
    for flag in ("truncated", "_truncated"):
        a = dict(CLOSEABLE)
        a[flag] = True
        ok, reason = decide(a, {}, POLICY, "email")
        assert not ok, f"{flag} did not block closure"
        assert "truncated" in reason


def test_truncation_checked_before_the_verdict_guard():
    """A truncated malicious reply reports truncation, not the verdict guard."""
    a = dict(CLOSEABLE, verdict="malicious", truncated=True)
    ok, reason = decide(a, {}, POLICY, "email")
    assert not ok
    assert "truncated" in reason


def test_no_assessment():
    ok, reason = decide({}, {}, POLICY, "email")
    assert not ok
    assert reason == "no assessment"


# ── benign exemption from the exposure guard ────────────────────────────────

BENIGN_EXECUTED = dict(
    CLOSEABLE,
    verdict="benign",
    exposure="executed",
    already_contained=False,
)


def test_benign_that_executed_still_closes():
    """The shape of most real false positives: it ran, and it was fine.

    A legitimate admin tool is benign with exposure "executed" and nothing
    contained. Before the exemption the exposure guard blocked it, which made
    the entire false-positive population unclosable.
    """
    ok, reason = decide(dict(BENIGN_EXECUTED), {}, POLICY, "endpoint")
    assert ok, reason


def test_benign_delivered_still_closes():
    a = dict(BENIGN_EXECUTED, exposure="delivered")
    ok, reason = decide(a, {}, POLICY, "email")
    assert ok, reason


def test_non_benign_that_landed_is_still_blocked():
    """The exemption is scoped to benign and must not leak to the other verdicts."""
    for v in ("suspicious", "inconclusive"):
        a = dict(BENIGN_EXECUTED, verdict=v)
        ok, reason = decide(a, {}, POLICY, "endpoint")
        assert not ok, f"{v} + executed wrongly closed"
        assert "remediation is owed" in reason


def test_malicious_guard_still_wins_over_the_exemption():
    a = dict(BENIGN_EXECUTED, verdict="malicious")
    ok, reason = decide(a, {}, POLICY, "endpoint")
    assert not ok
    assert "true-positive" in reason


def test_benign_exemption_does_not_bypass_blockers():
    a = dict(BENIGN_EXECUTED, closure_blockers=["verify the change record"])
    ok, reason = decide(a, {}, POLICY, "endpoint")
    assert not ok
    assert "blocker" in reason


def test_benign_exemption_does_not_bypass_confidence():
    a = dict(BENIGN_EXECUTED, closure_confidence="low")
    ok, reason = decide(a, {}, POLICY, "endpoint")
    assert not ok
    assert "below" in reason


def test_reasoning_flattens_story_and_blockers():
    from SOCFWCloseDecision import reasoning
    a = {"story": ["WHAT FIRED: x", " ", "VERDICT: y"],
         "closure_blockers": ["retract the message", ""]}
    assert reasoning(a) == {"story": "WHAT FIRED: x | VERDICT: y",
                            "closure_blockers": "retract the message"}


def test_reasoning_writes_nothing_when_absent():
    from SOCFWCloseDecision import reasoning
    assert reasoning({}) == {}
    assert reasoning({"story": [], "closure_blockers": "not a list"}) == {}
    assert reasoning(None) == {}


# --- SOCFWClosurePolicy that cannot be read --------------------------------------

def test_unreadable_policy_blocks_a_closeable_issue():
    ok, reason = decide(dict(CLOSEABLE), {}, {}, "email", "not valid JSON: x")
    assert not ok
    assert "SOCFWClosurePolicy unreadable" in reason and "a person decides" in reason


def test_unreadable_policy_does_not_hide_a_guard_reason():
    ok, reason = decide(dict(CLOSEABLE), {"owner": "analyst"}, {}, "email", "boom")
    assert not ok and reason == "assigned to an analyst"


def _with_list(monkeypatch, result, error=False, raises=None):
    class D:
        @staticmethod
        def executeCommand(cmd, args):
            if raises:
                raise raises
            return result
    monkeypatch.setattr(scd, "demisto", D)
    monkeypatch.setattr(scd, "isError", lambda r: error)


def test_missing_policy_list_uses_the_defaults(monkeypatch):
    _with_list(monkeypatch, [{"Contents": "Item not found (8)"}], error=True)
    assert scd._policy() == ({}, None)


def test_empty_policy_list_uses_the_defaults(monkeypatch):
    _with_list(monkeypatch, [{"Contents": "  "}])
    assert scd._policy() == ({}, None)


def test_policy_list_read(monkeypatch):
    _with_list(monkeypatch, [{"Contents": '{"min_closure_confidence": "medium"}'}])
    assert scd._policy() == ({"min_closure_confidence": "medium"}, None)


def test_policy_list_already_parsed(monkeypatch):
    _with_list(monkeypatch, [{"Contents": {"require_no_blockers": False}}])
    assert scd._policy() == ({"require_no_blockers": False}, None)


def test_bad_json_is_a_problem(monkeypatch):
    _with_list(monkeypatch, [{"Contents": "{not json"}])
    policy, problem = scd._policy()
    assert policy == {} and problem.startswith("not valid JSON")


def test_json_that_is_not_an_object_is_a_problem(monkeypatch):
    _with_list(monkeypatch, [{"Contents": "[1, 2]"}])
    assert scd._policy() == ({}, "not a JSON object")


def test_getlist_error_is_a_problem(monkeypatch):
    _with_list(monkeypatch, [{"Contents": "permission denied"}], error=True)
    policy, problem = scd._policy()
    assert policy == {} and problem.startswith("getList failed")


def test_getlist_raising_is_a_problem(monkeypatch):
    _with_list(monkeypatch, None, raises=RuntimeError("down"))
    assert scd._policy() == ({}, "getList raised: down")
