"""Star a case when the assessment says a human is needed.

The conditions are data, not code. phases.triage.star in
SOCFrameworkPhasePolicy_V3 carries a list of rules; any one matching stars the
case, and the matched rule's own reason is what gets recorded and shown. Adding
a condition on exposure, confidence or already_contained is a list edit.

Starring only ever raises attention. It is never reversed here: a star is also
the backstop that stops auto-triage closing a case (SOCAutoTriageScoreFilter
refuses to close anything it cannot positively confirm is unstarred), so
un-starring would quietly remove a safety net somebody is relying on.

The dispatch goes through SOCCommandWrapper like every other action, so the
execution row, the vendor ladder and the environment-tier checks apply without
being reimplemented here. soc-star-case is deliberately not shadowed - the star
is what makes a human open a case whose containment was only simulated.
"""
import json
from datetime import datetime, timezone

import demistomock as demisto
from CommonServerPython import *

POLICY_LIST = "SOCFrameworkPhasePolicy_V3"
ACTION = "soc-star-case"

# Ordered enums, for the gte operator. A value outside the enum ranks 0 and so
# never satisfies gte - an unrecognised value must not read as "high".
RANKS = {
    "confidence": {"low": 1, "medium": 2, "high": 3},
    "closure_confidence": {"low": 1, "medium": 2, "high": 3},
    "severity": {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5},
}

ABSENT = (None, "", [], {})


def _policy():
    """phases.triage.star, or {} when the list cannot be read.

    An unreadable policy means no star. Acting on a policy we could not read is
    how a tenant gets behaviour nobody configured.
    """
    try:
        res = demisto.executeCommand("getList", {"listName": POLICY_LIST})
        if not isError(res):
            raw = res[0].get("Contents")
            doc = json.loads(raw) if isinstance(raw, str) else (raw or {})
            return ((doc.get("phases") or {}).get("triage") or {}).get("star") or {}
    except Exception as e:  # noqa: BLE001
        demisto.debug(f"SOCFWStarCase: {POLICY_LIST} unreadable, not starring: {e}")
    return {}


def _assessment(ctx, source_key):
    obj = demisto.get(ctx, source_key)
    if isinstance(obj, list):
        obj = obj[0] if obj else None
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except (ValueError, TypeError):
            obj = None
    return obj if isinstance(obj, dict) else {}


def _norm(v):
    return v.strip().lower() if isinstance(v, str) else v


def evaluate(rule, assessment):
    """(matched, detail). A rule that cannot be evaluated never matches.

    Three states throughout: matched, did not match, and could not tell. The
    third is reported rather than folded into the second, because an absent
    field means the assessment did not answer - not that it answered no.
    """
    name = rule.get("name") or "unnamed"
    field = rule.get("field")
    if not field:
        return False, f"{name}: rule names no field"

    if field not in assessment or assessment.get(field) in ABSENT:
        return False, f"{name}: {field} absent from the assessment"

    actual = _norm(assessment.get(field))
    op = (rule.get("op") or "eq").lower()

    if op == "eq":
        expected = _norm(rule.get("value"))
        if isinstance(expected, bool) or isinstance(actual, bool):
            return (bool(actual) is bool(expected)), f"{name}: {field}={actual!r}"
        return (actual == expected), f"{name}: {field}={actual!r}"

    if op == "in":
        allowed = [_norm(v) for v in (rule.get("values") or [])]
        if not allowed:
            return False, f"{name}: rule lists no values"
        return (actual in allowed), f"{name}: {field}={actual!r}"

    if op == "gte":
        ranks = RANKS.get(field)
        if not ranks:
            return False, f"{name}: gte unsupported on {field} (no ordered enum)"
        want, got = ranks.get(_norm(rule.get("value")), 0), ranks.get(actual, 0)
        if not want:
            return False, f"{name}: {rule.get('value')!r} not a known {field}"
        return (got >= want), f"{name}: {field}={actual!r}"

    return False, f"{name}: unknown operator {op!r}"


def resolve_case_id(args, ctx, incident):
    """The case this issue belongs to, or None. Never a guess.

    Starring the wrong case is worse than not starring, so every source is an
    explicit one and an unresolved id is reported as unavailable.
    """
    for value, where in (
        (args.get("case_id"), "case_id argument"),
        (demisto.get(ctx, "SOCFramework.Case.id"), "SOCFramework.Case.id"),
        (incident.get("parent_xdr_incident"), "parent_xdr_incident"),
        ((incident.get("CustomFields") or {}).get("parentxdrincident"), "CustomFields.parentxdrincident"),
    ):
        if value not in ABSENT:
            return str(value), where
    return None, "no case id on the issue"


def _row(**kw):
    row = {
        "event_type": "star_decision",
        "phase": "triage",
        "action": ACTION,
        "action_actor": "framework",
        "decided_at": datetime.now(timezone.utc).isoformat(),
    }
    row.update({k: v for k, v in kw.items() if v not in ABSENT})
    try:
        demisto.executeCommand("socfw-post-to-dataset",
                               {"using": "socfw_ir_execution_writer", "JSON": json.dumps(row, default=str)})
    except Exception as e:  # noqa: BLE001 - telemetry must never fail the phase
        demisto.debug(f"SOCFWStarCase: star_decision row not written: {e}")


def main():
    args = demisto.args() or {}
    ctx = demisto.context()
    incident = demisto.incident() or {}
    source_key = args.get("source_key") or "Assessment.AI"

    policy = _policy()
    assessment = _assessment(ctx, source_key)
    issue_id = str(incident.get("id") or "")

    if not policy.get("enabled"):
        reason = "phases.triage.star.enabled is not true in " + POLICY_LIST
        _row(incident_id=issue_id, status="disabled", decision_reason=reason)
        return_results(CommandResults(readable_output=f"⚪ **Not starring** — {reason}."))
        return

    if not assessment:
        reason = f"no assessment at `{source_key}`"
        _row(incident_id=issue_id, status="unavailable", decision_reason=reason)
        return_results(CommandResults(readable_output=f"⚪ **Not starring** — {reason}."))
        return

    rules = policy.get("rules") or []
    if not rules:
        reason = "no rules configured under phases.triage.star.rules"
        _row(incident_id=issue_id, status="unavailable", decision_reason=reason)
        return_results(CommandResults(readable_output=f"⚪ **Not starring** — {reason}."))
        return

    matched, details = [], []
    for rule in rules:
        hit, detail = evaluate(rule, assessment)
        details.append(("match" if hit else "no") + f" — {detail}")
        if hit:
            matched.append(rule)

    trail = "\n".join(f"- {d}" for d in details)

    if not matched:
        _row(incident_id=issue_id, status="no_match",
             decision_reason="; ".join(details), verdict=assessment.get("verdict"))
        return_results(CommandResults(readable_output=(
            f"⚪ **Not starring** — no rule matched.\n{trail}")))
        return

    why = matched[0].get("reason") or matched[0].get("name") or "policy rule matched"
    case_id, source = resolve_case_id(args, ctx, incident)

    if not case_id:
        # The verdict warranted a star and we could not place it. That is a gap
        # worth surfacing, not a silent pass.
        _row(incident_id=issue_id, status="unavailable", decision_reason=f"star warranted but {source}",
             verdict=assessment.get("verdict"), capability=why)
        return_results(CommandResults(readable_output=(
            f"🟡 **Star warranted but not placed** — {why}, however {source}. "
            f"Starring is case-level; this issue is not attached to a case yet.\n{trail}")))
        return

    star_field = policy.get("star_field") or "starred"
    demisto.setContext("SOCFramework.Star.case_id", case_id)
    demisto.setContext("SOCFramework.Star.field", star_field)

    _row(incident_id=issue_id, case_id=case_id, parent_xdr_incident=case_id,
         status="starring", decision_reason=why, verdict=assessment.get("verdict"),
         escalate_recommended=assessment.get("escalate_recommended"),
         already_contained=assessment.get("already_contained"), capability=why)

    demisto.executeCommand("SOCCommandWrapper", {
        "action": ACTION,
        "Phase": "triage",
        "Action_Actor": "framework",
    })

    return_results(CommandResults(readable_output=(
        f"⭐ **Starring case {case_id}** — {why}.  "
        f"(case id from {source}; field `{star_field}`)\n{trail}")))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
