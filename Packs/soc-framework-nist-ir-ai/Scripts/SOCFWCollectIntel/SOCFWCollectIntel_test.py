"""
SOCFWCollectIntel_test.py

Characterization tests: how reputation and threat-intel roots are gathered into
one context key for the assessment prompt. Roots come from the argument, else
the CaseIntelRoots config, else the shipped defaults; empty roots are left out;
when the result is over budget whole roots are dropped, largest first, and the
payload says what was dropped; nothing found writes "no content".

Run: pytest Scripts/SOCFWCollectIntel/SOCFWCollectIntel_test.py -v
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
import SOCFWCollectIntel as ci  # noqa: E402


def _dt(obj, path):
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


class Tenant:
    def __init__(self):
        self.context = {"DBotScore": [{"Indicator": "1.2.3.4", "Score": 3}], "IP": {"Address": "1.2.3.4"},
                        "File": {}, "URL": "", "Whois": {"big": "x"}}
        self.set = {}
        self.results = []


@pytest.fixture
def t(monkeypatch):
    tn = Tenant()
    monkeypatch.setattr(demisto, "dt", _dt, raising=False)
    monkeypatch.setattr(demisto, "context", lambda: tn.context, raising=False)
    monkeypatch.setattr(demisto, "setContext", lambda k, v: tn.set.__setitem__(k, v), raising=False)
    monkeypatch.setattr(ci, "return_results", tn.results.append, raising=False)
    return tn


def run(t, monkeypatch, **args):
    monkeypatch.setattr(demisto, "args", lambda: args, raising=False)
    ci.main()
    return t.results[-1]["readable_output"]


def test_resolved_roots_are_collected_and_empty_ones_left_out(t, monkeypatch):
    out = run(t, monkeypatch)
    assert json.loads(t.set["Assessment.Intel"]) == {
        "DBotScore": [{"Indicator": "1.2.3.4", "Score": 3}], "IP": {"Address": "1.2.3.4"}}
    assert out == "### Intel collected\n- 2 intel root(s): DBotScore, IP"


def test_whitespace_and_blank_roots_are_ignored(t):
    assert ci.collect({"IP": 1, "File": 2}, [" IP ", "", " ", "File"]) == {"IP": 1, "File": 2}


def test_the_roots_argument_wins_and_the_output_key_is_configurable(t, monkeypatch):
    t.context["SOCFramework"] = {"Case": {"Config": {"CaseIntelRoots": "IP"}}}
    run(t, monkeypatch, roots="Whois", output_key="Case.Intel")
    assert json.loads(t.set["Case.Intel"]) == {"Whois": {"big": "x"}}


@pytest.mark.parametrize("configured", ["IP", ["IP"]])
def test_the_config_list_is_used_when_no_roots_are_given(t, monkeypatch, configured):
    t.context["SOCFramework"] = {"Case": {"Config": {"CaseIntelRoots": configured}}}
    run(t, monkeypatch)
    assert list(json.loads(t.set["Assessment.Intel"])) == ["IP"]


def test_a_roots_list_argument_is_accepted(t, monkeypatch):
    run(t, monkeypatch, roots=["DBotScore", "Whois"])
    assert set(json.loads(t.set["Assessment.Intel"])) == {"DBotScore", "Whois"}


def test_nothing_resolved_writes_no_content(t, monkeypatch):
    t.context = {}
    out = run(t, monkeypatch)
    assert t.set["Assessment.Intel"] == "no content"
    assert "no reputation or threat intel resolved for this issue" in out


def test_over_budget_drops_the_largest_whole_roots_and_says_so(t, monkeypatch):
    t.context = {"A": "x" * 100, "B": "y" * 60, "C": "z" * 10}
    out = run(t, monkeypatch, roots="A,B,C", max_chars="80")
    payload = json.loads(t.set["Assessment.Intel"])
    assert payload == {"C": "z" * 10, "coverage_note": "Dropped for size, not absent: A, B"}
    assert out == "### Intel collected\n- 1 intel root(s): C — dropped for size: A, B"


@pytest.mark.parametrize("bad", ["lots", "", None])
def test_an_unreadable_budget_uses_the_default(t, monkeypatch, bad):
    t.context = {"A": "x" * 15000}
    run(t, monkeypatch, roots="A", max_chars=bad)
    assert "A" in json.loads(t.set["Assessment.Intel"])


def test_values_that_are_not_json_are_written_as_text(t, monkeypatch):
    class Odd:
        def __str__(self):
            return "odd"
    t.context = {"A": {"when": Odd()}}
    monkeypatch.setattr(ci, "_trim", lambda obj, n: (obj, []))
    run(t, monkeypatch, roots="A")
    assert json.loads(t.set["Assessment.Intel"]) == {"A": {"when": "odd"}}


def test_intel_dropped_entirely_for_size_is_not_reported_as_absent(t, monkeypatch):
    t.context = {"A": "x" * 100}
    run(t, monkeypatch, roots="A", max_chars="50")
    assert t.set["Assessment.Intel"] != "no content"


def test_a_trimmed_payload_fits_the_budget(t, monkeypatch):
    t.context = {"A": "x" * 100, "C": "z" * 60}
    run(t, monkeypatch, roots="A,C", max_chars="80")
    assert len(t.set["Assessment.Intel"]) <= 80
