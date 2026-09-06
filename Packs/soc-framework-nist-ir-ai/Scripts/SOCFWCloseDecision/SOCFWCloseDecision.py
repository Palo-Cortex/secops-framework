"""Decide whether the assessment may close this issue, and record the decision.

Nothing closes while `soc-close-issue` is in shadow mode. That flag is the on/off
switch and lives with the action in SOCFrameworkActions_V3, so going live is the
same single flip PS already uses for containment. In shadow the wrapper prints
what it would close and writes the execution row without closing anything.

SOCFWClosurePolicy carries tuning only — the confidence bar and per-category
overrides. The guards below are in code because they should not be configurable:

  starred          A starred issue is always closed by a person. Star is set at
                   alert creation and marks what the SOC has scoped in.
  touched          Somebody is already working it.
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
    try:
        res = demisto.executeCommand("getList", {"listName": POLICY_LIST})
        if not isError(res):
            raw = res[0].get("Contents")
            return json.loads(raw) if isinstance(raw, str) else (raw or {})
    except Exception as e:  # noqa: BLE001
        demisto.debug(f"SOCFWCloseDecision: policy list unreadable, closing stays off: {e}")
    return {}


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


def decide(a, incident, policy, category):
    """Return (may_close, reason). Recorded whichever way it goes."""
    if not a:
        return False, "no assessment"

    # Guards. Deliberately not in the policy list.
    if str(incident.get("starred") or "").lower() in ("true", "1"):
        return False, "starred — a person closes this"
    if incident.get("owner") or str(incident.get("status") or "") not in ("", "0", "1"):
        return False, "already being worked"
    if str(a.get("verdict") or "").lower() == "malicious":
        return False, "a true-positive verdict is never auto-closed"

    if not a.get("closure_recommended"):
        return False, "assessment did not recommend closure"

    # Something that reached the asset still needs removing, and removing it is a
    # case-scope action. Enforced here as well as in the prompt so a model that
    # ignores the instruction still cannot close one. "attempted" and "none" are
    # fine: nothing landed, so nothing is owed.
    landed = str(a.get("exposure") or "").lower() in ("delivered", "executed")
    if landed and not a.get("already_contained"):
        return False, f"{a.get('exposure')} and not contained — a remediation is owed"

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
    policy = _policy()
    category = demisto.get(ctx, "SOCFramework.Product.category")

    may_close, reason = decide(a, incident, policy, category)

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
        "decided_at": datetime.now(timezone.utc).isoformat(),
    }
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
