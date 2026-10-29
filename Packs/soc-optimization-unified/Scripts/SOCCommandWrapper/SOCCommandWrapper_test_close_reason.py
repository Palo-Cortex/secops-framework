"""
SOCCommandWrapper_test_close_reason.py

soc-close-issue takes its reason from the assessment (RESOLVED_FALSE_POSITIVE ...).
closeInvestigation records the platform's resolution only for its own wording
("Resolved - False Positive"); the enum string is stored as RESOLVED_OTHER. The
row's value_map translates it. Each wording checked on the dev tenant, 29 Oct 2026.

Run: pytest Scripts/SOCCommandWrapper/SOCCommandWrapper_test_close_reason.py -v
"""
import copy
import json
import os

import pytest

from SOCCommandWrapper_test import load_script

_LISTS = os.path.join(os.path.dirname(__file__), "..", "..", "Lists")
ACTIONS = json.load(open(os.path.join(_LISTS, "SOCFrameworkActions_V3", "SOCFrameworkActions_V3_data.json")))
LIVE = {"shadow": {"soc-close-issue": {"automation": False}}}


def _run(reason, tenant=LIVE):
    script, demisto = load_script()
    demisto._args = {"action": "soc-close-issue", "list_name": "SOCFrameworkActions_V3",
                     "output_key": "UCTest.Executions", "Action_Actor": "automation"}
    demisto._context = {"SOCFramework": {"RunID": "r", "Product": {"key": "ds_okta_systemlog",
                                                                  "category": "Identity"}},
                        "Assessment": {"closure_reason": reason, "verdict": "benign",
                                       "closure_confidence": "high"}}

    def _route(args):
        name = (args or {}).get("listName")
        if name == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps({"soc-close-issue": copy.deepcopy(ACTIONS["soc-close-issue"])})}]
        if name == "SOCFWTenantConfig":
            return [{"Contents": json.dumps(tenant)}]
        return [{"Type": 4, "Contents": f" - Item not found (8) on list [{name}] (2609)"}]

    demisto._command_responses = {
        "getList": _route,
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "closeInvestigation": [{"Type": 1, "Contents": "closed"}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }
    script.main()
    calls = [a for c, a in demisto._commands if c == "closeInvestigation"]
    return calls, demisto


@pytest.mark.parametrize("enum, wording", [
    ("RESOLVED_TRUE_POSITIVE", "Resolved - True Positive"),
    ("RESOLVED_FALSE_POSITIVE", "Resolved - False Positive"),
    ("RESOLVED_KNOWN_ISSUE", "Resolved - Known Issue"),
    ("RESOLVED_DUPLICATE_ISSUE", "Resolved - Duplicate Issue"),
    ("RESOLVED_SECURITY_TESTING", "Resolved - Security Testing"),
    ("RESOLVED_OTHER", "Resolved - Other"),
])
def test_the_ai_reason_is_sent_in_the_platforms_wording(enum, wording):
    calls, _ = _run(enum)
    assert [c["closeReason"] for c in calls] == [wording]


def test_a_reason_already_in_the_platforms_wording_passes_through():
    calls, _ = _run("Resolved - False Positive")
    assert calls[0]["closeReason"] == "Resolved - False Positive"


def test_an_unmapped_reason_passes_through_unchanged():
    calls, _ = _run("SOMETHING_NEW")
    assert calls[0]["closeReason"] == "SOMETHING_NEW"


def test_a_shadowed_close_records_the_platforms_wording():
    calls, demisto = _run("RESOLVED_FALSE_POSITIVE", tenant={})
    assert calls == []
    shadow = [r["Contents"] for r in demisto._results if isinstance(r, dict) and isinstance(r.get("Contents"), dict)
              and r["Contents"].get("shadow_mode") is True and "success" in r["Contents"]]
    assert shadow and shadow[0]["args"]["closeReason"] == "Resolved - False Positive"


def test_every_ai_closure_reason_is_mapped():
    """Every reason the assessment prompts can return has a wording."""
    root = os.path.join(os.path.dirname(__file__), "..", "..", "..", "soc-framework-nist-ir-ai")
    import re
    reasons = set()
    for f in ("SOCFWIssueAssessment.prompt.md", "SOCFWCaseAnalysis.prompt.md"):
        reasons |= set(re.findall(r'"(RESOLVED_[A-Z_]+)"', open(os.path.join(root, f)).read()))
    mapped = set(ACTIONS["soc-close-issue"]["responses"]["Builtin"]["value_map"]["closeReason"])
    assert reasons and reasons <= mapped
