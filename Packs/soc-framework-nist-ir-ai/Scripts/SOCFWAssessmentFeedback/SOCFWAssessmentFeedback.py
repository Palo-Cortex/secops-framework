"""Record an analyst's judgement of the AI assessment.

Writes a feedback row to the execution dataset, capturing the verdict as it stood
when the analyst judged it. A row that only pointed at the issue would silently
re-attach to a different answer if the assessment were re-run, which is the flaw
that made free-text agreement tags unusable for measurement.

Args:
  feedback   correct | wrong | missing_context
  note       optional free text from the analyst
"""
import json
from datetime import datetime, timezone

import demistomock as demisto
from CommonServerPython import *

# Agreement is recorded, not inferred. It was originally derived by joining the
# assessment row to xdm.issue.status.resolution_reason on close, on the reasoning
# that the analyst already states a resolution in the tenant's own vocabulary.
# That only measures the issues that get closed. Analysts are not being asked to
# close these, so an agreement rate built that way describes the closing subset
# rather than the assessments, and silence reads as absence rather than as assent.
#
# Each row still snapshots the verdict it judged, so a positive answer stays
# attached to the answer it was given about even if the assessment is re-run.
AXIS = {
    "correct": "verdict",
    "wrong": "verdict",
    "missing_context": "evidence",
}

LABEL = {
    "correct": "🟢 Confirmed the assessment",
    "wrong": "🔴 Marked the assessment wrong",
    "missing_context": "🟠 Flagged missing context",
}


def _agreement(feedback, a):
    """Explicit only. missing_context judges the evidence, not the verdict."""
    if feedback == "correct":
        return True
    if feedback == "wrong":
        return False
    return None


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


def _current_user(incident):
    """Who is giving the feedback. Falls back to the issue owner."""
    try:
        res = demisto.executeCommand("getUsers", {"current": "true"})
        if not isError(res):
            data = res[0].get("Contents")
            if isinstance(data, list) and data:
                return data[0].get("username") or data[0].get("id") or ""
    except Exception:  # noqa: BLE001
        pass
    return incident.get("owner") or ""


def main():
    args = demisto.args() or {}
    feedback = str(args.get("feedback") or "").strip().lower()
    if feedback not in AXIS:
        return_error(f"feedback must be one of {', '.join(AXIS)}; got {feedback!r}")
        return

    ctx = demisto.context()
    a = _assessment(ctx)
    incident = demisto.incident() or {}

    row = {
        "event_type": "ai_feedback",
        "phase": "Assessment",
        "lifecycle": "NIST_IR",
        "incident_id": str(incident.get("id") or ""),
        "alert_name": incident.get("name") or "",
        "alert_category": demisto.get(ctx, "SOCFramework.Product.category") or "",
        "product_key": demisto.get(ctx, "SOCFramework.Product.key") or "",
        "feedback": feedback,
        "feedback_axis": AXIS[feedback],
        "agreement": _agreement(feedback, a),
        # Typed into the AI Feedback Note field on the layout before clicking.
        # Carried on the row so the reason travels with the verdict it refers to,
        # rather than sitting in a separate note nothing joins to.
        "feedback_note": args.get("note") or "",
        "analyst": _current_user(incident),
        # the verdict being judged, captured now
        "verdict": a.get("verdict") or "",
        "confidence": a.get("confidence") or "",
        "exposure": a.get("exposure") or "",
        "escalate_recommended": a.get("escalate_recommended"),
        "closure_recommended": a.get("closure_recommended"),
        "closure_reason": a.get("closure_reason") or "",
        "primary_entity_name": a.get("primary_entity_name") or "",
        "mitre_technique_id": a.get("mitre_technique_id") or "",
        "feedback_time": datetime.now(timezone.utc).isoformat(),
    }

    try:
        res = demisto.executeCommand(
            "socfw-post-to-dataset",
            {"using": "socfw_ir_execution_writer", "JSON": json.dumps(row)},
        )
        if isError(res):
            return_error(f"Could not record feedback: {get_error(res)}")
            return
    except Exception as e:  # noqa: BLE001
        return_error(f"Could not record feedback: {e}")
        return

    note = f" — {row['feedback_note']}" if row["feedback_note"] else ""
    verdict = row["verdict"] or "no verdict recorded"
    agree = row["agreement"]
    lines = [f"{LABEL[feedback]}{note}", ""]
    lines.append(f"  AI said **{verdict}** / {row['confidence'] or 'unknown'} confidence.")
    lines.append("")
    # Both ask for a comment. Missing context is the more insistent of the two:
    # "no process lineage" and "no reputation on the C2 address" send you to
    # different fixes, and nothing else on the row distinguishes them. Why the
    # verdict was wrong is often recoverable by joining to the resolution, so
    # that one asks only for what the join cannot show.
    if feedback == "missing_context":
        lines.append("  **Please comment naming what was missing** — which field, host, "
                     "user, or indicator the assessment needed and did not have. That "
                     "names the normalization or enrichment gap; without it this row says "
                     "only that something was absent.")
    elif feedback == "wrong":
        lines.append("  **Please comment on why it was wrong**, particularly if the verdict "
                     "happened to be right but the reasoning or the evidence cited was not. "
                     "Nothing else captures that.")
    else:
        lines.append("  Recorded as agreement against this verdict. No comment needed.")

    return_results(CommandResults(readable_output="\n".join(lines)))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
