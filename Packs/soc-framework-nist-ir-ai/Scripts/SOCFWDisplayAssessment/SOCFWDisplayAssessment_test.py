"""
SOCFWDisplayAssessment_test.py

Characterization tests: the layout's Assessment section. It prefers the whole
Assessment.AI object over the promoted flat fields, shows the case verdict
beside the issue's, and tells "no playbook ran" apart from "no verdict yet".

Run: pytest Scripts/SOCFWDisplayAssessment/SOCFWDisplayAssessment_test.py -v
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
csp.formats = {"html": "html"}
csp.entryTypes = {"note": 1}
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWDisplayAssessment as da  # noqa: E402


def _get(obj, path):
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


def render(monkeypatch, ctx):
    out = []
    monkeypatch.setattr(demisto, "context", lambda: ctx, raising=False)
    monkeypatch.setattr(demisto, "get", _get, raising=False)
    monkeypatch.setattr(demisto, "results", out.append, raising=False)
    da.main()
    assert out[-1]["ContentsFormat"] == "html"
    return out[-1]["Contents"]


ANSWER = {"verdict": "malicious", "confidence": "high", "exposure": "executed",
          "story": ["first step", "second step"], "closure_blockers": ["host online", "user unknown"],
          "primary_entity_name": "host-1", "mitre_tactic": "Execution", "mitre_technique_id": "T1204"}


def test_an_issue_no_playbook_touched_says_so(monkeypatch):
    assert render(monkeypatch, {}) == da.NOT_RUN


def test_the_framework_namespace_alone_is_not_a_run(monkeypatch):
    assert render(monkeypatch, {"SOCFramework": {"RunID": "x"}}) == da.NOT_RUN


def test_a_running_lifecycle_with_no_verdict_says_so(monkeypatch):
    assert render(monkeypatch, {"SOCFramework": {"lifecycle": "NIST_IR"}}) == da.NO_VERDICT_YET


@pytest.mark.parametrize("ai", [ANSWER, json.dumps(ANSWER), [ANSWER]])
def test_the_whole_object_keeps_every_story_line_and_blocker(monkeypatch, ai):
    html = render(monkeypatch, {"Assessment": {"AI": ai}})
    assert "MALICIOUS" in html and "Confidence: high" in html and "executed on the asset" in html
    assert "first step" in html and "second step" in html
    assert "host online" in html and "user unknown" in html
    assert "<b>Entity:</b> host-1" in html and "<b>MITRE:</b> Execution T1204" in html


def test_flat_fields_fill_in_when_there_is_no_object(monkeypatch):
    html = render(monkeypatch, {"Assessment": {"verdict": ["suspicious"], "story": "one line"}})
    assert "SUSPICIOUS" in html and "one line" in html


def test_a_closure_shows_its_reason_and_hides_the_blockers(monkeypatch):
    ai = dict(ANSWER, closure_recommended=True, closure_reason="graymail", closure_confidence="high")
    html = render(monkeypatch, {"Assessment": {"AI": ai}})
    assert "graymail</b> (high confidence)" in html
    assert "Before this can close" not in html


def test_the_case_verdict_shows_beside_the_issues(monkeypatch):
    ctx = {"Assessment": {"AI": ANSWER},
           "SOCFramework": {"Analysis": {"AI": {"verdict": "benign", "story": ["case first", "case second"]}}}}
    html = render(monkeypatch, ctx)
    assert "BENIGN" in html and "case first" in html and "case second" not in html
    assert "act on this one" in html


def test_a_case_verdict_alone_still_renders(monkeypatch):
    html = render(monkeypatch, {"Analysis": {"verdict": "suspicious"}})
    assert "SUSPICIOUS" in html and "Case verdict" in html


def test_a_cut_off_answer_says_so(monkeypatch):
    html = render(monkeypatch, {"Assessment": {"AI": dict(ANSWER, truncated=True)}})
    assert "cut off by the output token limit" in html


@pytest.mark.xfail(strict=True, reason=(
    "Known defect: the model's story and blocker text go into the layout HTML unescaped, "
    "so a subject or URL carrying < or & renders wrong (and markup in it is rendered)."))
def test_model_text_is_escaped_in_the_layout(monkeypatch):
    ai = dict(ANSWER, story=["subject was <b>Invoice</b> & more"])
    html = render(monkeypatch, {"Assessment": {"AI": ai}})
    assert "&lt;b&gt;Invoice&lt;/b&gt; &amp; more" in html
