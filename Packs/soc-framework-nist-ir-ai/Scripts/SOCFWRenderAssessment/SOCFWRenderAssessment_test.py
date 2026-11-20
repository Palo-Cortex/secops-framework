"""
SOCFWRenderAssessment_test.py

Characterization tests: how the issue assessment becomes its War Room entry.
The answer arrives as a dict or as the aiTask's raw text, fenced or cut off;
the decision fields come first, so a cut-off reply still renders its verdict
and says it was cut off.

Run: pytest Scripts/SOCFWRenderAssessment/SOCFWRenderAssessment_test.py -v
"""
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)

demisto = types.ModuleType("demistomock")
sys.modules["demistomock"] = demisto
csp = types.ModuleType("CommonServerPython")
csp.CommandResults = lambda **k: k
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWRenderAssessment as ra  # noqa: E402

ANSWER = {"verdict": "malicious", "confidence": "high", "exposure": "executed", "already_contained": True,
          "escalate_recommended": True, "primary_entity_name": "host-1", "mitre_tactic": "Execution",
          "mitre_technique_id": "T1204", "story": ["WHAT FIRED: a macro ran", "WHY IT MATTERS: it called out"],
          "closure_blockers": ["host still online"]}


# -- reading the answer -------------------------------------------------------

@pytest.mark.parametrize("raw", [
    ANSWER,
    json.dumps(ANSWER),
    "Here is my assessment:\n```json\n" + json.dumps(ANSWER) + "\n```",
    [ANSWER],
])
def test_the_answer_is_read_from_any_shape_the_task_leaves(raw):
    assert ra._as_object(raw)["verdict"] == "malicious"


@pytest.mark.parametrize("raw", [None, "", "no json here", []])
def test_nothing_readable_is_none(raw):
    assert ra._as_object(raw) is None


def test_a_cut_off_reply_keeps_its_decision_and_is_marked():
    cut = '{"verdict": "suspicious", "confidence": "medium", "story": ["WHAT FIRED: a lo'
    obj = ra._as_object(cut)
    assert obj["verdict"] == "suspicious" and obj["confidence"] == "medium"
    assert obj["truncated"] is True and obj["_truncated"] is True
    assert "story" not in obj


def test_a_cut_off_reply_with_prose_before_it_is_still_read():
    obj = ra._as_object('Sure. {"verdict": "benign", "confidence": "low", "story": "x')
    assert obj["verdict"] == "benign" and obj["truncated"]


def test_a_reply_with_no_complete_pair_cannot_be_salvaged():
    assert ra._as_object('{"verdict": "mal') is None


# -- the entry ----------------------------------------------------------------

def test_the_decision_sits_on_the_first_lines():
    lines = ra.render(ANSWER).split("\n")
    assert lines[0] == "🔴 **ASSESSMENT** — MALICIOUS   ●●● high"
    assert lines[2] == "  action        escalate to an analyst"
    assert lines[3] == "  exposure      executed on the asset   ·  already contained"


@pytest.mark.parametrize("obj,action", [
    ({"closure_recommended": True, "closure_reason": "benign graymail"}, "close — benign graymail"),
    ({"closure_recommended": True}, "close — no reason given"),
    ({"closure_recommended": True, "escalate_recommended": True, "closure_reason": "x"}, "close — x"),
    ({}, "no action recommended"),
])
def test_closure_outranks_escalation_in_the_action_line(obj, action):
    assert f"  action        {action}" in ra.render(obj)


def test_story_labels_are_dropped_and_the_list_numbers_it():
    out = ra.render(ANSWER)
    assert "  1. a macro ran" in out and "  2. it called out" in out
    assert ra._strip_label("Not a label: keep it") == "Not a label: keep it"


def test_the_story_and_blockers_are_cut_to_their_line_budgets():
    obj = dict(ANSWER, story=[f"s{i}" for i in range(9)], closure_blockers=[f"b{i}" for i in range(9)])
    out = ra.render(obj, max_blockers=2)
    assert f"  … {9 - ra.MAX_STORY_LINES} further step(s) omitted" in out
    assert "  · b1" in out and "  · b2" not in out and "  · … and 7 more" in out


def test_an_empty_answer_says_to_check_the_inputs():
    out = ra.render({})
    assert out.startswith("⚪ **ASSESSMENT** — INCONCLUSIVE   ○○○ unknown")
    assert "No reasoning returned" in out


def test_a_cut_off_answer_says_so():
    assert "cut off by the output-token limit" in ra.render(dict(ANSWER, truncated=True))
    assert "cut off by the output-token limit" in ra.render(dict(ANSWER, _truncated=True))


# -- main ---------------------------------------------------------------------

def run_main(monkeypatch, ctx, args=None):
    out = []
    monkeypatch.setattr(demisto, "args", lambda: args or {}, raising=False)
    monkeypatch.setattr(demisto, "context", lambda: ctx, raising=False)
    monkeypatch.setattr(demisto, "dt", lambda c, key: c.get(key), raising=False)
    monkeypatch.setattr(ra, "return_results", out.append, raising=False)
    ra.main()
    return out[-1]["readable_output"]


def test_main_reads_the_source_key_it_is_given(monkeypatch):
    out = run_main(monkeypatch, {"Other.AI": json.dumps(ANSWER)}, {"source_key": "Other.AI"})
    assert out.startswith("🔴 **ASSESSMENT** — MALICIOUS")


def test_main_says_what_was_empty(monkeypatch):
    out = run_main(monkeypatch, {})
    assert out == "⚪ **ASSESSMENT** — none\n\n  `Assessment.AI` was empty or could not be parsed."


def test_a_bad_blocker_limit_falls_back_to_the_default(monkeypatch):
    obj = dict(ANSWER, closure_blockers=[f"b{i}" for i in range(9)])
    out = run_main(monkeypatch, {"Assessment.AI": obj}, {"max_blockers": "lots"})
    assert f"  · … and {9 - ra.MAX_BLOCKER_LINES} more" in out
