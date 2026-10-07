import sys
import types

import pytest

# The script is authored the way XSIAM runs it, importing demistomock and
# CommonServerPython. Neither is guaranteed present outside the SDK container,
# and the functions under test are pure, so stub both before import rather than
# making the test depend on the SDK being installed.
if "demistomock" not in sys.modules:
    mock = types.ModuleType("demistomock")
    mock.args = lambda: {}
    mock.context = lambda: {}
    mock.incident = lambda: {}
    mock.debug = lambda *a, **k: None

    def _get(data, path, default=None):
        """Dotted-path lookup, matching demisto.get semantics."""
        if data is None or path in (None, ""):
            return default
        cur = data
        for part in str(path).split("."):
            if isinstance(cur, dict):
                cur = cur.get(part, default)
            else:
                return default
        return cur

    mock.get = _get
    mock.executeCommand = lambda *a, **k: []
    mock.setContext = lambda *a, **k: None
    sys.modules["demistomock"] = mock
if "CommonServerPython" not in sys.modules:
    csp = types.ModuleType("CommonServerPython")
    csp.isError = lambda *a, **k: False
    csp.return_results = lambda *a, **k: None
    csp.return_error = lambda *a, **k: None
    csp.CommandResults = object
    csp.formats = {}
    csp.entryTypes = {}
    csp.argToBoolean = bool
    sys.modules["CommonServerPython"] = csp

sys.path.insert(0, __import__("os").path.dirname(__file__))

from SOCFWStarCase import evaluate, resolve_case_id  # noqa: E402

MALICIOUS = {"name": "malicious_verdict", "field": "verdict", "op": "in",
             "values": ["malicious"], "reason": "Assessment returned a malicious verdict"}
ANALYST = {"name": "analyst_needed", "field": "escalate_recommended", "op": "eq",
           "value": True, "reason": "Assessment asked for an analyst"}


def test_malicious_verdict_matches():
    assert evaluate(MALICIOUS, {"verdict": "malicious"})[0] is True


def test_verdict_is_case_and_space_insensitive():
    assert evaluate(MALICIOUS, {"verdict": "  Malicious "})[0] is True


def test_benign_verdict_does_not_match():
    assert evaluate(MALICIOUS, {"verdict": "benign"})[0] is False


def test_escalate_recommended_true_matches():
    assert evaluate(ANALYST, {"escalate_recommended": True})[0] is True


def test_escalate_recommended_false_does_not_match():
    assert evaluate(ANALYST, {"escalate_recommended": False})[0] is False


@pytest.mark.parametrize("assessment", [{}, {"verdict": None}, {"verdict": ""}])
def test_absent_field_never_matches(assessment):
    """An absent field means the assessment did not answer, not that it said no."""
    matched, detail = evaluate(MALICIOUS, assessment)
    assert matched is False
    assert "absent" in detail


def test_unknown_operator_never_matches():
    rule = dict(MALICIOUS, op="regex")
    matched, detail = evaluate(rule, {"verdict": "malicious"})
    assert matched is False
    assert "unknown operator" in detail


def test_in_with_no_values_never_matches():
    matched, detail = evaluate({"name": "x", "field": "verdict", "op": "in"}, {"verdict": "malicious"})
    assert matched is False
    assert "no values" in detail


def test_rule_without_field_never_matches():
    matched, detail = evaluate({"name": "x", "op": "eq", "value": True}, {"verdict": "malicious"})
    assert matched is False
    assert "names no field" in detail


def test_gte_on_confidence():
    rule = {"name": "c", "field": "confidence", "op": "gte", "value": "medium"}
    assert evaluate(rule, {"confidence": "high"})[0] is True
    assert evaluate(rule, {"confidence": "medium"})[0] is True
    assert evaluate(rule, {"confidence": "low"})[0] is False


def test_gte_unrecognised_value_never_ranks_high():
    """An unknown enum value must not satisfy gte."""
    rule = {"name": "c", "field": "confidence", "op": "gte", "value": "medium"}
    assert evaluate(rule, {"confidence": "extremely-high"})[0] is False


def test_gte_on_field_without_ordered_enum():
    rule = {"name": "v", "field": "verdict", "op": "gte", "value": "malicious"}
    matched, detail = evaluate(rule, {"verdict": "malicious"})
    assert matched is False
    assert "no ordered enum" in detail


def test_case_id_prefers_explicit_argument():
    cid, src = resolve_case_id({"case_id": "50183"}, {}, {"parent_xdr_incident": "999"})
    assert (cid, src) == ("50183", "case_id argument")


def test_case_id_from_incident_parent():
    cid, src = resolve_case_id({}, {}, {"parent_xdr_incident": 50183})
    assert cid == "50183"
    assert src == "parent_xdr_incident"


def test_case_id_from_context():
    cid, src = resolve_case_id({}, {"SOCFramework": {"Case": {"id": "777"}}}, {})
    assert (cid, src) == ("777", "SOCFramework.Case.id")


def test_case_id_absent_is_reported_not_guessed():
    cid, src = resolve_case_id({}, {}, {"id": "ISSUE-1"})
    assert cid is None
    assert "no case id" in src
