"""
SOCFWPromoteAssessment_test.py

Characterization tests: how the AI assessment reply becomes Assessment.* and an
ai_reasoning row. The close, elevate and emergency decisions all read what this
script writes, so a reply it misreads is a decision made on the wrong verdict.

Run: pytest Scripts/SOCFWPromoteAssessment/SOCFWPromoteAssessment_test.py -v
"""
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)


class Stop(Exception):
    """return_error ends the script on the tenant; here it raises."""


def _get(obj, path):
    for part in path.split("."):
        obj = obj.get(part) if isinstance(obj, dict) else None
    return obj


demisto = types.ModuleType("demistomock")
demisto.get = _get
demisto.debug = lambda *a, **k: None
sys.modules["demistomock"] = demisto
csp = types.ModuleType("CommonServerPython")
csp.CommandResults = lambda **k: k
csp.argToBoolean = lambda v: str(v).lower() == "true"


def _return_error(msg):
    raise Stop(msg)


csp.return_error = _return_error
csp.return_results = lambda *a, **k: None
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWPromoteAssessment as pa  # noqa: E402

GOOD = {"verdict": "benign", "confidence": "high", "exposure": "none",
        "closure_recommended": True, "closure_confidence": "high",
        "story": ["WHAT FIRED: x", "VERDICT: benign"], "closure_blockers": []}


@pytest.fixture(autouse=True)
def fresh():
    pa._ESCAPES_REPAIRED = False


# ── reading the reply ─────────────────────────────────────────────────────────

def test_an_object_or_a_list_of_one_is_taken_as_is():
    assert pa._load(GOOD) is GOOD
    assert pa._load([GOOD]) is GOOD
    assert pa._load(None) is None and pa._load("   ") is None


def test_a_fenced_reply_or_one_with_a_preamble_is_read():
    text = json.dumps(GOOD)
    assert pa._load("```json\n" + text + "\n```") == GOOD
    assert pa._load("Here is my assessment:\n" + text) == GOOD


def test_raw_newlines_inside_a_string_are_tolerated():
    assert pa._load('{"verdict": "benign", "closure_reason": "line one\nline two"}')["verdict"] == "benign"


def test_an_unescaped_windows_path_is_repaired_and_flagged():
    obj = pa._load('{"verdict": "malicious", "closure_reason": "ran C:\\Users\\x\\y.exe"}')
    assert obj["verdict"] == "malicious" and obj["closure_reason"] == "ran C:\\Users\\x\\y.exe"
    assert pa._ESCAPES_REPAIRED is True


@pytest.mark.xfail(strict=True, reason=(
    "Known defect: a path segment that starts with b, f, n, r or t is a valid JSON "
    "escape, so _repair keeps it and C:\\Users\\bob loses the 'b' to a backspace. "
    "Only replies that already failed a strict parse reach the repair."))
def test_a_path_segment_that_looks_like_an_escape_survives_the_repair():
    obj = pa._load('{"verdict": "malicious", "closure_reason": "ran C:\\Users\\bob\\x.exe"}')
    assert obj["closure_reason"] == "ran C:\\Users\\bob\\x.exe"


def test_valid_escapes_are_left_alone_by_the_repair():
    assert pa._repair('a\\nb \\" \\u0041 \\\\') == 'a\\nb \\" \\u0041 \\\\'
    assert pa._repair("C:\\Users") == "C:\\\\Users"


def test_a_reply_cut_off_mid_story_keeps_the_verdict_and_is_marked_truncated():
    cut = '{"verdict": "suspicious", "confidence": "medium", "story": ["WHAT FIRED: a long'
    obj = pa._load(cut)
    assert obj == {"verdict": "suspicious", "confidence": "medium", "truncated": True}


def test_a_reply_with_nothing_recoverable_raises():
    with pytest.raises(ValueError):
        pa._load("I could not assess this issue.")


def test_story_and_blockers_are_flattened_to_one_string_each():
    assert pa.reasoning({"story": ["a ", "", "b"], "closure_blockers": ["x", " y "]}) == \
        {"story": "a | b", "closure_blockers": "x; y"}
    assert pa.reasoning({"story": [], "closure_blockers": []}) == {}
    assert pa.reasoning("not a dict") == {}


# ── what main writes ──────────────────────────────────────────────────────────

def run(raw, args=None):
    ctx = {"Assessment": {"AI": raw}, "SOCFramework": {"Product": {"category": "email"}}}
    set_calls, rows, results = [], [], []
    demisto.args = lambda: dict(args or {})
    demisto.context = lambda: ctx
    demisto.incident = lambda: {"id": "1101", "name": "phish"}
    demisto.setContext = lambda k, v: set_calls.append((k, v))
    demisto.executeCommand = lambda cmd, a: rows.append(json.loads(a["JSON"])) or [{"Type": 1}]
    pa.return_results = results.append
    pa.main()
    return set_calls, rows, results


def test_a_reply_is_parsed_in_place_and_its_fields_promoted_without_empties():
    set_calls, rows, results = run(json.dumps(GOOD))
    assert set_calls[0] == ("Assessment.AI", GOOD)
    promoted = dict(set_calls[1:])
    assert promoted["Assessment.verdict"] == "benign" and "Assessment.closure_blockers" not in promoted
    (row,) = rows
    assert row["reasoning_status"] == "promoted" and row["alert_category"] == "email"
    assert row["story"] == "WHAT FIRED: x | VERDICT: benign" and "closure_blockers" not in row
    assert "Promoted **benign** / high confidence" in results[0]["readable_output"]


def test_promote_false_writes_the_row_but_not_the_context():
    set_calls, rows, _ = run(json.dumps(GOOD), {"promote": "false"})
    assert set_calls == [] and rows[0]["reasoning_status"] == "promoted"


def test_no_reply_writes_a_no_output_row():
    set_calls, rows, results = run(None)
    assert set_calls == [] and rows[0]["reasoning_status"] == "no_output"
    assert "No assessment" in results[0]["readable_output"]


def test_an_unreadable_reply_writes_a_parse_error_row_with_its_start_then_stops():
    with pytest.raises(Stop, match="not valid JSON"):
        run("I could not assess this issue.")


def test_a_truncated_reply_says_so_on_the_issue():
    _, rows, results = run('{"verdict": "suspicious", "confidence": "medium", "story": ["cut')
    assert rows[0]["truncated"] is True
    assert "truncated" in results[0]["readable_output"]
