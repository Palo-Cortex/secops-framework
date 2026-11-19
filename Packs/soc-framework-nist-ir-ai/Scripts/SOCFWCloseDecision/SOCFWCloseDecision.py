"""Decide whether the assessment may close this issue, and record the decision.

Nothing closes while `soc-close-issue` is in shadow mode. That flag is the on/off
switch and lives with the action in SOCFrameworkActions_V3, so going live is the
same single flip PS already uses for containment. In shadow the wrapper prints
what it would close and writes the execution row without closing anything.

SOCFWClosurePolicy carries tuning only — the confidence bar and per-category
overrides. The guards below are in code because they should not be configurable:

  starred          A starred issue is always closed by a person. Star is set at
                   alert creation and marks what the SOC has scoped in.
  assigned         An analyst owns it, so a person closes it. Tested on the
                   assigned user and deliberately NOT on status: automation moves
                   an issue off New, so a status test reads every issue whose
                   lifecycle has started as one a human is working.
  truncated        The model's reply was cut off. closure_blockers is emitted late
                   in the schema and is the first thing truncation eats, so an
                   empty blocker list on a truncated reply means "never got there",
                   not "nothing blocks this".
  verdict          Never close a true-positive verdict at any confidence.

A decision row is written whichever way it goes, including for issues held back,
because the reason for a hold is what says whether a threshold change would
release something safe.
"""
import json
from datetime import datetime, timezone

import demistomock as demisto
from CommonServerPython import *

POLICY_LIST = "SOCFWClosurePolicy"
CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


def _policy():
    """(policy, problem). A missing list is ({}, None): the defaults in decide()
    apply. A list that exists but cannot be read or parsed is ({}, why), and no
    issue closes until a person fixes it, because the policy is where an owner
    tightens closing and silently falling back to the defaults would undo that."""
    try:
        res = demisto.executeCommand("getList", {"listName": POLICY_LIST})
    except Exception as e:  # noqa: BLE001
        return {}, f"getList raised: {e}"
    first = res[0] if isinstance(res, list) and res and isinstance(res[0], dict) else {}
    raw = first.get("Contents")
    if isinstance(raw, str) and "Item not found" in raw:
        return {}, None
    if not res or isError(res):
        return {}, f"getList failed: {str(raw)[:120]}"
    if isinstance(raw, dict):
        return raw, None
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return {}, None
    try:
        doc = json.loads(raw)
    except (TypeError, ValueError) as e:
        return {}, f"not valid JSON: {e}"
    return (doc, None) if isinstance(doc, dict) else ({}, "not a JSON object")


def _assessment(ctx):
    obj = demisto.get(ctx, "Assessment.AI")
    if isinstance(obj, list):
        obj = obj[0] if obj else None
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except (ValueError, TypeError):
            obj = None
    return obj if isinstance(obj, dict) else {}


def _is_truncated(a):
    """True when the assessment object came from a reply that was cut off.

    SOCFWPromoteAssessment writes `truncated`; SOCFWRenderAssessment historically
    wrote `_truncated`. Read both rather than picking one, so a promoted object
    from either path trips the guard.
    """
    return bool(a.get("truncated") or a.get("_truncated"))


def reasoning(assessment):
    """The assessment's own reasoning, flattened for the dataset.

    story is the four labelled lines the analyst reads (WHAT FIRED, EXPOSURE,
    VERDICT, NEXT CHECK); closure_blockers is what a human still has to verify.
    Both arrive as lists and are written as one string each, so every decision
    row can carry the why alongside the what.
    """
    out = {}
    if not isinstance(assessment, dict):
        return out
    story = assessment.get("story")
    if isinstance(story, list):
        lines = [str(s).strip() for s in story if str(s).strip()]
        if lines:
            out["story"] = " | ".join(lines)
    blockers = assessment.get("closure_blockers")
    if isinstance(blockers, list):
        items = [str(b).strip() for b in blockers if str(b).strip()]
        if items:
            out["closure_blockers"] = "; ".join(items)
    return out


def decide(a, incident, policy, category, policy_problem=None):
    """Return (may_close, reason). Recorded whichever way it goes.

    policy_problem is set when SOCFWClosurePolicy exists but could not be read;
    nothing closes until it is fixed."""
    if not a:
        return False, "no assessment"

    # A truncated reply is not a shorter answer, it is an unfinished one. Both
    # _salvage implementations flag it; read either so an older promoted object
    # still trips the guard.
    if _is_truncated(a):
        return False, "assessment reply was truncated — blockers may be missing"

    # Guards. Deliberately not in the policy list.
    if str(incident.get("starred") or "").lower() in ("true", "1"):
        return False, "starred — a person closes this"
    if incident.get("owner"):
        return False, "assigned to an analyst"
    if str(a.get("verdict") or "").lower() == "malicious":
        return False, "a true-positive verdict is never auto-closed"

    if not a.get("closure_recommended"):
        return False, "assessment did not recommend closure"

    # Something that reached the asset still needs removing, and removing it is a
    # case-scope action. Enforced here as well as in the prompt so a model that
    # ignores the instruction still cannot close one. "attempted" and "none" are
    # fine: nothing landed, so nothing is owed.
    # ...unless the verdict is benign. "It executed" is only a remediation debt
    # when the thing that executed was bad. A legitimate admin tool that ran is
    # benign AND exposure "executed", and that is the shape of most real false
    # positives — an FP is an FP precisely because the activity happened and was
    # fine. Without this exemption the close path is reachable only for activity
    # that never ran, which is a small minority of what a SOC actually closes.
    landed = str(a.get("exposure") or "").lower() in ("delivered", "executed")
    benign = str(a.get("verdict") or "").lower() == "benign"
    if landed and not benign and not a.get("already_contained"):
        return False, f"{a.get('exposure')} and not contained — a remediation is owed"

    if policy_problem:
        return False, f"{POLICY_LIST} unreadable ({policy_problem}) - a person decides"

    # Tuning. A category override loosens or tightens one category without
    # changing the rule everywhere else.
    override = (policy.get("category_overrides") or {}).get(str(category or "").lower()) or {}
    if override.get("skip"):
        return False, f"{category} is excluded by policy"

    if override.get("require_no_blockers", policy.get("require_no_blockers", True)):
        blockers = [b for b in (a.get("closure_blockers") or []) if b]
        if blockers:
            return False, f"{len(blockers)} outstanding blocker(s)"

    want = str(override.get("min_closure_confidence",
                            policy.get("min_closure_confidence", "high"))).lower()
    got = str(a.get("closure_confidence") or "").lower()
    if CONFIDENCE_RANK.get(got, 0) < CONFIDENCE_RANK.get(want, 3):
        return False, f"closure confidence {got or 'none'} below {want}"

    return True, "policy satisfied"


def main():
    ctx = demisto.context()
    incident = demisto.incident() or {}
    a = _assessment(ctx)
    policy, policy_problem = _policy()
    if policy_problem:
        demisto.debug(f"SOCFWCloseDecision: {POLICY_LIST} unreadable, nothing closes: {policy_problem}")
    category = demisto.get(ctx, "SOCFramework.Product.category")

    may_close, reason = decide(a, incident, policy, category, policy_problem)

    row = {
        "event_type": "ai_close_decision",
        "phase": "Assessment",
        "lifecycle": "NIST_IR",
        "incident_id": str(incident.get("id") or ""),
        "alert_category": category or "",
        "would_close": bool(a.get("closure_recommended")),
        "did_close": may_close,
        "decision_reason": reason,
        "verdict": a.get("verdict") or "",
        "closure_confidence": a.get("closure_confidence") or "",
        "closure_reason": a.get("closure_reason") or "",
        "blocker_count": len([b for b in (a.get("closure_blockers") or []) if b]),
        # Carried so truncation rate is measurable per model and per prompt, and
        # so a zero blocker_count can be told apart from one that was cut off.
        "truncated": _is_truncated(a),
        "decided_at": datetime.now(timezone.utc).isoformat(),
    }
    row.update(reasoning(a))
    try:
        demisto.executeCommand("socfw-post-to-dataset",
                               {"using": "socfw_ir_execution_writer", "JSON": json.dumps(row)})
    except Exception as e:  # noqa: BLE001 - telemetry must never fail the phase
        demisto.debug(f"SOCFWCloseDecision: decision row not written: {e}")

    if not may_close:
        return_results(CommandResults(readable_output=f"⚪ **Not closing** — {reason}."))
        return

    # Shadow mode on the action decides whether this actually closes anything.

    demisto.executeCommand("SOCCommandWrapper", {
        "action": "soc-close-issue",
        "Phase": "Assessment",
        "LifeCycle": "NIST_IR",
        "Action_Actor": "ai",
    })
    return_results(CommandResults(readable_output=(
        f"🟢 **Close requested** — {a.get('closure_reason') or 'no reason given'} "
        f"({a.get('closure_confidence')} confidence).  Whether it actually closes "
        f"depends on shadow mode for soc-close-issue."
    )))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
