"""
SOCFWCloseDecision_test_main.py

Characterisation tests for main(): the policy list read, the decision row
written to the dataset, the close request sent to the wrapper and the War Room
output, in order, compared with a golden file captured from the code before
decide() was restructured. The scenarios reach every branch of decide.

Regenerate the golden file only for an intended behaviour change, never to make
a refactor pass:

    SOCFW_UPDATE_GOLDEN=1 pytest SOCFWCloseDecision_test_main.py
"""

import copy
import json
import os
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest

from SOCFWCloseDecision_test import scd

GOLDEN = Path(__file__).parent / "test_data" / "main_golden.json"
UPDATE = os.environ.get("SOCFW_UPDATE_GOLDEN") == "1"
ERROR_ENTRY = 4

CLOSEABLE = {
    "verdict": "benign", "exposure": "none", "already_contained": True,
    "closure_recommended": True, "closure_confidence": "high", "closure_reason": "admin tool, expected",
    "closure_blockers": [],
}

POLICY = {
    "min_closure_confidence": "high",
    "category_overrides": {
        "email": {"min_closure_confidence": "medium"},
        "identity": {"skip": True},
        "endpoint": {"require_no_blockers": False},
        "saas": {"min_closure_confidence": "certain"},
    },
}

# What getList returns for SOCFWClosurePolicy, by how the list stands.
LIST_REPLIES = {
    "missing": [{"Type": 1, "Contents": "Item not found (8)"}],
    "json": [{"Type": 1, "Contents": json.dumps(POLICY)}],
    "object": [{"Type": 1, "Contents": POLICY}],
    "blockers_off": [{"Type": 1, "Contents": json.dumps(dict(POLICY, require_no_blockers=False))}],
    "blank": [{"Type": 1, "Contents": "  "}],
    "no_contents": [{"Type": 1}],
    "not_json": [{"Type": 1, "Contents": "{min_closure_confidence: high"}],
    "not_an_object": [{"Type": 1, "Contents": "[\"high\"]"}],
    "error": [{"Type": ERROR_ENTRY, "Contents": "list service unavailable"}],
    "no_reply": [],
    "raises": None,
}


def s(assessment: object = None, **spec: object) -> dict:
    """A scenario: an assessment in context, an unowned issue, the policy list as JSON, an email category."""
    return dict({"assessment": copy.deepcopy(CLOSEABLE) if assessment is None else assessment,
                 "incident": {"id": "42"}, "policy": "json", "category": "email"}, **spec)


def a(**changes: object) -> dict:
    """The closeable assessment with some fields changed."""
    return dict(copy.deepcopy(CLOSEABLE), **changes)


SCENARIOS = {
    # The assessment itself
    "closes": s(),
    "closes_with_reasoning": s(a(story=["WHAT FIRED: x", " ", "VERDICT: benign"], closure_blockers=["", None])),
    "no_assessment": s({}),
    "assessment_absent_from_context": s(..., incident={"id": "42"}),
    "assessment_as_a_list": s([a()]),
    "assessment_as_an_empty_list": s([]),
    "assessment_as_json_text": s(json.dumps(a())),
    "assessment_as_bad_text": s("{verdict: benign"),
    "assessment_not_an_object": s(["benign"]),
    # Guards
    "truncated": s(a(truncated=True)),
    "truncated_old_flag": s(a(_truncated=True, verdict="malicious")),
    "starred_text": s(incident={"id": "42", "starred": "true"}),
    "starred_one": s(incident={"id": "42", "starred": 1}),
    "starred_bool": s(incident={"id": "42", "starred": True}),
    "not_starred": s(incident={"id": "42", "starred": "false"}),
    "assigned": s(incident={"id": "42", "owner": "analyst1"}),
    "status_without_owner": s(incident={"id": "42", "status": 2}),
    "no_incident": s(incident=None),
    "malicious": s(a(verdict="Malicious")),
    "not_recommended": s(a(closure_recommended=False)),
    # Exposure
    "delivered_not_contained": s(a(verdict="suspicious", exposure="delivered", already_contained=False)),
    "executed_contained": s(a(verdict="suspicious", exposure="executed", already_contained=True)),
    "executed_benign": s(a(exposure="Executed", already_contained=False)),
    "attempted_not_contained": s(a(verdict="suspicious", exposure="attempted", already_contained=False)),
    # The policy list
    "policy_missing_uses_defaults": s(a(closure_confidence="medium"), policy="missing"),
    "policy_missing_high_closes": s(policy="missing"),
    "policy_as_object": s(a(closure_confidence="medium"), policy="object"),
    "policy_blank": s(policy="blank"),
    "policy_no_contents": s(policy="no_contents"),
    "policy_not_json": s(policy="not_json"),
    "policy_not_an_object": s(policy="not_an_object"),
    "policy_error": s(policy="error"),
    "policy_no_reply": s(policy="no_reply"),
    "policy_raises": s(policy="raises"),
    "guard_before_policy_problem": s(incident={"id": "42", "owner": "analyst1"}, policy="not_json"),
    # Tuning
    "category_skipped": s(category="identity"),
    "category_case_folded": s(a(closure_confidence="medium"), category="Email"),
    "category_none": s(a(closure_confidence="medium"), category=None),
    "blockers_outstanding": s(a(closure_blockers=["confirm with owner", "", "check logons"])),
    "blockers_allowed_by_category": s(a(closure_blockers=["confirm with owner"]), category="endpoint"),
    "blockers_allowed_everywhere": s(a(closure_blockers=["confirm with owner"]), policy="blockers_off",
                                     category="network"),
    "confidence_below_category_bar": s(a(closure_confidence="low")),
    "confidence_below_default_bar": s(a(closure_confidence="medium"), category="network"),
    "confidence_missing": s(a(closure_confidence=None)),
    "confidence_unknown_word": s(a(closure_confidence="certain")),
    "bar_unknown_word": s(category="saas"),
}


class _FixedClock:
    """Stands in for datetime so the decision row's time is the same on every run."""

    @staticmethod
    def now(tz: timezone) -> datetime:
        """The fixed time, in the zone asked for."""
        return datetime(2026, 11, 23, 12, 0, tzinfo=tz)


def _lookup(ctx: dict, path: str) -> object:
    """demisto.get: a dotted path into context, None where it stops."""
    node = ctx
    for part in path.split("."):
        node = node.get(part) if isinstance(node, dict) else None
    return node


def _run(name: str) -> dict:
    """Run main() once for a scenario and record every tenant call and the War Room output."""
    spec = copy.deepcopy(SCENARIOS[name])
    reply = copy.deepcopy(LIST_REPLIES[spec["policy"]])
    ctx = {"SOCFramework": {"Product": {"category": spec["category"]}}}
    if spec["assessment"] is not ...:
        ctx["Assessment"] = {"AI": spec["assessment"]}
    calls: list = []
    shown: list = []

    def execute(command: str, args: dict) -> list:
        calls.append([command, json.loads(args["JSON"]) if command == "socfw-post-to-dataset" else args])
        if command == "getList":
            if reply is None:
                raise RuntimeError("getList timed out")
            return reply
        return [{"Type": 1, "Contents": "ok"}]

    saved = (scd.demisto, scd.datetime, scd.isError, scd.CommandResults, scd.return_results)
    scd.demisto = types.SimpleNamespace(context=lambda: ctx, incident=lambda: spec["incident"],
                                        get=_lookup, executeCommand=execute,
                                        debug=lambda msg: calls.append(["debug", msg]))
    scd.datetime = _FixedClock
    scd.isError = lambda res: bool(res) and isinstance(res[0], dict) and res[0].get("Type") == ERROR_ENTRY
    scd.CommandResults = lambda **kwargs: kwargs
    scd.return_results = shown.append
    try:
        scd.main()
    finally:
        scd.demisto, scd.datetime, scd.isError, scd.CommandResults, scd.return_results = saved
    return {"calls": calls, "war_room": shown}


def _golden() -> dict:
    """The recorded outcome of every scenario."""
    return json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_main_matches_golden(name: str) -> None:
    """
    Given an issue, its assessment and the closure policy list in a known state
    When the close decision runs
    Then the list read, decision row, close request and War Room output match the golden file
    """
    got = _run(name)
    if UPDATE:
        golden = _golden()
        golden[name] = got
        GOLDEN.write_text(json.dumps(golden, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
        return
    assert name in _golden(), f"no golden for {name}; generate it from main with SOCFW_UPDATE_GOLDEN=1"
    assert json.dumps(got, ensure_ascii=False, sort_keys=True) == \
        json.dumps(_golden()[name], ensure_ascii=False, sort_keys=True)


def test_golden_has_no_stale_scenarios() -> None:
    """
    Given the golden file
    When its scenario names are compared with this file's
    Then each golden entry still has a scenario that produces it
    """
    assert set(_golden()) <= set(SCENARIOS)
