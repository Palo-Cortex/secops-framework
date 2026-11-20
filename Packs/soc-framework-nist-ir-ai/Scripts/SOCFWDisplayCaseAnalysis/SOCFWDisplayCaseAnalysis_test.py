"""
SOCFWDisplayCaseAnalysis_test.py

Characterization tests: the case layout's analysis section. It reads the same
SOCFramework.Analysis.AI contract containment acts on, tells "not run" apart
from "ran, no verdict", and escapes every contract value before it reaches the
layout.

Run: pytest Scripts/SOCFWDisplayCaseAnalysis/SOCFWDisplayCaseAnalysis_test.py -v
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
import SOCFWDisplayCaseAnalysis as dca  # noqa: E402


def render(monkeypatch, ai=None):
    out = []
    ctx = {} if ai is None else {"SOCFramework": {"Analysis": {"AI": ai}}}
    monkeypatch.setattr(demisto, "context", lambda: ctx, raising=False)
    monkeypatch.setattr(dca, "return_results", out.append, raising=False)
    dca.main()
    assert out[-1]["ContentsFormat"] == "html"
    return out[-1]["Contents"]


AI = {"verdict": "malicious", "confidence": "high", "compromise_level": "host", "spread_level": "single",
      "primary_entity_name": "host-1", "primary_entity_type": "endpoint", "mitre_tactic": "Execution",
      "mitre_tactic_id": "TA0002", "mitre_technique": "User Execution", "mitre_technique_id": "T1204",
      "response_recommended": "true", "story": ["one", "two"], "closure_blockers": ["host online"],
      "analysed_at": "2026-11-20T19:00:00Z"}


def test_a_case_never_analysed_says_so(monkeypatch):
    assert render(monkeypatch) == dca.NOT_RUN


@pytest.mark.parametrize("ai", ["not json", 7])
def test_an_unreadable_contract_reads_as_not_run(monkeypatch, ai):
    assert render(monkeypatch, ai) == dca.NOT_RUN


def test_a_contract_with_no_verdict_says_analysis_produced_none(monkeypatch):
    assert render(monkeypatch, {"verdict": "  ", "story": []}) == dca.NO_VERDICT


@pytest.mark.parametrize("ai", [AI, json.dumps(AI), [{"verdict": "old"}, AI]])
def test_the_latest_contract_renders_whatever_its_shape(monkeypatch, ai):
    html = render(monkeypatch, ai)
    assert ">malicious</span>" in html and "●●● high confidence" in html
    assert "Execution TA0002 / User Execution T1204" in html
    assert "host-1 (endpoint)" in html and ">yes</td>" in html
    assert "<li style='margin:0 0 7px 0;line-height:1.45;'>one</li>" in html
    assert "host online" in html


def test_empty_facts_are_left_out(monkeypatch):
    html = render(monkeypatch, {"verdict": "benign"})
    assert "Compromise" not in html and "MITRE" not in html
    # Characterised as is: the entity row always shows, even when unknown.
    assert "unknown (?)" in html


def test_story_and_blockers_arrive_as_json_strings_too(monkeypatch):
    html = render(monkeypatch, dict(AI, story='["s1","s2"]', closure_blockers='["b1"]'))
    assert ">s1</li>" in html and ">s2</li>" in html and ">b1</li>" in html


@pytest.mark.parametrize("recommended,text", [(True, "No outstanding checks recorded."),
                                              ("false", "None recorded.")])
def test_an_empty_blocker_list_is_still_shown(monkeypatch, recommended, text):
    html = render(monkeypatch, dict(AI, closure_blockers=[], closure_recommended=recommended))
    assert "Before closing" in html and text in html


def test_attacker_text_in_the_contract_is_escaped(monkeypatch):
    html = render(monkeypatch, dict(AI, story=["ran <script>x</script> & left"],
                                    primary_entity_name="<b>host</b>"))
    assert "ran &lt;script&gt;x&lt;/script&gt; &amp; left" in html
    assert "&lt;b&gt;host&lt;/b&gt;" in html and "<script>" not in html
