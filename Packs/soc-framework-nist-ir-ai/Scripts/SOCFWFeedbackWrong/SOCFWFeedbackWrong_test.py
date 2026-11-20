"""
SOCFWFeedbackWrong_test.py

Characterization tests: the Wrong button records its feedback through
SOCFWAssessmentFeedback with the value baked in and the analyst's note carried with it, shows that
script's result, and stops with the reason when it fails.

Run: pytest Scripts/SOCFWFeedbackWrong/SOCFWFeedbackWrong_test.py -v
"""
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


def _return_error(msg):
    raise Stop(msg)


csp.return_error = _return_error
csp.isError = lambda res: isinstance(res, list) and bool(res) and res[0].get("Type") == 4
csp.get_error = lambda res: res[0].get("Contents")
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWFeedbackWrong as btn  # noqa: E402

OK = [{"Type": 1, "Contents": "recorded"}]


@pytest.fixture
def t(monkeypatch):
    state = {"calls": [], "reply": OK, "results": []}

    def execute(cmd, args):
        state["calls"].append((cmd, args))
        return state["reply"]
    monkeypatch.setattr(demisto, "executeCommand", execute, raising=False)
    monkeypatch.setattr(btn, "return_results", state["results"].append, raising=False)
    return state


def run(t, monkeypatch, args):
    monkeypatch.setattr(demisto, "args", lambda: args, raising=False)
    btn.main()


def test_the_feedback_value_is_baked_in(t, monkeypatch):
    run(t, monkeypatch, {"feedback": "something else"})
    assert t["calls"] == [("SOCFWAssessmentFeedback", {"feedback": "wrong", "note": ""})]


def test_the_note_travels_with_the_feedback(t, monkeypatch):
    run(t, monkeypatch, {"note": "no process lineage"})
    assert t["calls"][0][1] == {"feedback": "wrong", "note": "no process lineage"}


@pytest.mark.parametrize("args", [{}, {"note": None}, None])
def test_no_note_sends_an_empty_one(t, monkeypatch, args):
    run(t, monkeypatch, args)
    assert t["calls"][0][1] == {"feedback": "wrong", "note": ""}


def test_the_recorded_result_is_shown(t, monkeypatch):
    run(t, monkeypatch, {})
    assert t["results"] == [OK]


def test_a_failed_record_stops_with_the_reason(t, monkeypatch):
    t["reply"] = [{"Type": 4, "Contents": "dataset not found"}]
    with pytest.raises(Stop, match="Could not record feedback: dataset not found"):
        run(t, monkeypatch, {})
    assert t["results"] == []
