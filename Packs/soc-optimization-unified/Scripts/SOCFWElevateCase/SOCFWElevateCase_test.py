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

from SOCFWElevateCase import decide, evaluate, pick_target, resolve_case_id  # noqa: E402

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
    cid, src = resolve_case_id({}, {}, {"parentXDRIncident": "INCIDENT-49101"})
    assert cid == "49101"
    assert src == "incident.parentXDRIncident"


def test_case_id_strips_the_incident_prefix():
    """The issue carries INCIDENT-49101; the Cases API wants 49101."""
    assert resolve_case_id({}, {}, {"parentXDRIncident": "INCIDENT-49101"})[0] == "49101"


def test_case_id_accepts_a_bare_numeric_id():
    assert resolve_case_id({}, {}, {"parentXDRIncident": 50183})[0] == "50183"


def test_non_numeric_case_id_is_refused():
    cid, src = resolve_case_id({}, {}, {"parentXDRIncident": "INCIDENT-abc"})
    assert cid is None
    assert "not a numeric id" in src


def test_case_id_from_context():
    cid, src = resolve_case_id({}, {"SOCFramework": {"Case": {"id": "777"}}}, {})
    assert (cid, src) == ("777", "SOCFramework.Case.id")


def test_case_id_absent_is_reported_not_guessed():
    cid, src = resolve_case_id({}, {}, {"id": "ISSUE-1"})
    assert cid is None
    assert "no case id" in src


# ── raise-only behaviour ──────────────────────────────────────────────────────

def test_raises_when_target_is_higher():
    go, why = decide("high", "critical")
    assert go is True
    assert why == "high -> critical"


def test_never_lowers():
    """The whole point: a critical case is not dropped to high."""
    go, why = decide("critical", "high")
    assert go is False
    assert "raise-only" in why


def test_no_change_when_equal():
    go, why = decide("high", "high")
    assert go is False
    assert "already high" in why


def test_refuses_on_unrecognised_current_severity():
    """Raising blind could lower it, so refuse rather than guess."""
    go, why = decide("wibble", "high")
    assert go is False
    assert "unrecognised" in why


def test_info_current_can_be_raised():
    assert decide("info", "low")[0] is True


def test_rejects_unsettable_target():
    go, why = decide("low", "info")
    assert go is False
    assert "not a settable severity" in why


def test_raise_only_off_allows_lowering():
    assert decide("critical", "high", raise_only=False)[0] is True


# ── target selection ─────────────────────────────────────────────────────────

def test_highest_matching_target_wins():
    matched = [{"target_severity": "high"}, {"target_severity": "critical"}]
    assert pick_target(matched, {"target_severity": "low"}) == "critical"


def test_falls_back_to_block_default():
    assert pick_target([{"name": "no target"}], {"target_severity": "high"}) == "high"


def test_invalid_target_is_dropped_not_sent():
    assert pick_target([{"target_severity": "extremely-bad"}], {"target_severity": "medium"}) == "medium"


def test_no_valid_target_anywhere():
    assert pick_target([{"target_severity": "nope"}], {}) is None


# ── requires: AND within a rule (conservative starring) ──────────────────────

MAL_HIGH = {
    "name": "malicious_high_confidence",
    "field": "verdict", "op": "in", "values": ["malicious"],
    "requires": [{"field": "confidence", "op": "gte", "value": "high"}],
    "reason": "Assessment returned a malicious verdict at high confidence",
}


def test_malicious_at_high_confidence_matches():
    assert evaluate(MAL_HIGH, {"verdict": "malicious", "confidence": "high"})[0] is True


def test_malicious_at_medium_confidence_does_not_match():
    """The whole point of requires: a lower-confidence malicious must not star."""
    matched, detail = evaluate(MAL_HIGH, {"verdict": "malicious", "confidence": "medium"})
    assert matched is False
    assert "requires" in detail


def test_benign_at_high_confidence_does_not_match():
    assert evaluate(MAL_HIGH, {"verdict": "benign", "confidence": "high"})[0] is False


def test_requires_with_an_absent_field_does_not_match():
    """A missing confidence is not an implicit pass."""
    matched, detail = evaluate(MAL_HIGH, {"verdict": "malicious"})
    assert matched is False


def test_all_requires_must_hold():
    rule = dict(MAL_HIGH, requires=[
        {"field": "confidence", "op": "gte", "value": "high"},
        {"field": "already_contained", "op": "eq", "value": False},
    ])
    ok = {"verdict": "malicious", "confidence": "high", "already_contained": False}
    assert evaluate(rule, ok)[0] is True
    assert evaluate(rule, dict(ok, already_contained=True))[0] is False
