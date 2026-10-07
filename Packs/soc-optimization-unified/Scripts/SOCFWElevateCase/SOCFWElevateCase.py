"""Raise a case's severity when the assessment says a human is needed.

The conditions are data, not code. phases.triage.elevate in
SOCFrameworkPhasePolicy_V3 carries a rule list; any match elevates the case, and
the matched rule's own reason is what gets recorded and shown. Adding a condition
on exposure, confidence or already_contained is a list edit.

RAISE ONLY. The framework never lowers a case's severity. A case already at or
above the target is left untouched and the decision is still recorded, so the
no-op is visible rather than silent.

Two signals, both case-level. The star goes through the XSOAR CLI layer
(setParentIncidentFields), which writes what the XDR public APIs refuse: `starred`
is absent from incidents/update_incident's allowed keys and rejected by the Cases
API case/update with "Invalid update fields". Severity goes through user_severity
on the Cases API, which is writable and drives the effective severity. Both
verified on a tenant.

The star is idempotent on the case's real starred state, not a flag - every issue
in a case runs this, so a 16-issue case would otherwise dispatch sixteen stars.
The framework never un-stars: a star is the backstop that stops auto-triage
closing a case.

Elevation is case-level. An issue cannot be elevated this way, so where the issue
has no case yet this reports a gap rather than acting.

The dispatch goes through SOCCommandWrapper like every other action, so shadow
mode, the execution row and the environment-tier checks apply without being
reimplemented here. Whether this run really changes anything is the wrapper's
decision, not this script's.
"""
import json
from datetime import datetime, timezone

import demistomock as demisto
from CommonServerPython import *

POLICY_LIST = "SOCFrameworkPhasePolicy_V3"
ACTION_SEVERITY = "soc-raise-case-severity"
ACTION_STAR = "soc-star-case"

# The platform's effective severity enum. user_severity accepts the four above
# info, so info is readable as a current value but never a target.
SEVERITY_RANK = {"info": 1, "informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SETTABLE = ("low", "medium", "high", "critical")

RANKS = {
    "confidence": {"low": 1, "medium": 2, "high": 3},
    "closure_confidence": {"low": 1, "medium": 2, "high": 3},
    "severity": SEVERITY_RANK,
}

ABSENT = (None, "", [], {})


def _policy():
    """phases.triage.elevate, or {} when the list cannot be read."""
    try:
        res = demisto.executeCommand("getList", {"listName": POLICY_LIST})
        if not isError(res):
            raw = res[0].get("Contents")
            doc = json.loads(raw) if isinstance(raw, str) else (raw or {})
            return ((doc.get("phases") or {}).get("triage") or {}).get("elevate") or {}
    except Exception as e:  # noqa: BLE001
        demisto.debug(f"SOCFWElevateCase: {POLICY_LIST} unreadable, not elevating: {e}")
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
    """(matched, detail). A rule that cannot be evaluated never matches."""
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


def pick_target(matched, policy):
    """Highest target among matching rules, falling back to the block default.

    A target the platform will not accept is dropped rather than sent, so a typo
    in the list cannot turn into a failed dispatch.
    """
    candidates = [r.get("target_severity") for r in matched]
    candidates.append(policy.get("target_severity"))
    valid = [_norm(c) for c in candidates if _norm(c) in SETTABLE]
    if not valid:
        return None
    return max(valid, key=lambda s: SEVERITY_RANK[s])


def decide(current, target, raise_only=True):
    """(should_dispatch, reason). Raise only: never lower, never sideways."""
    if target not in SETTABLE:
        return False, f"{target!r} is not a settable severity"
    cur_rank = SEVERITY_RANK.get(_norm(current), 0)
    tgt_rank = SEVERITY_RANK[target]
    if not cur_rank:
        # Unknown current severity. Raising blind could lower it, so refuse.
        return False, f"current severity {current!r} unrecognised — refusing to guess"
    if raise_only and tgt_rank <= cur_rank:
        return False, f"already {current} (target {target}) — raise-only, leaving it"
    return True, f"{current} -> {target}"


def resolve_case_id(args, ctx, incident):
    """The case this issue belongs to, or None. Never a guess."""
    for value, where in (
        (args.get("case_id"), "case_id argument"),
        (demisto.get(ctx, "SOCFramework.Case.id"), "SOCFramework.Case.id"),
        # The issue object names this parentXDRIncident (camelCase). The snake_case
        # spelling is the execution-dataset COLUMN name, not a field on the issue -
        # reading that was why a matching issue reported "no case id" on a tenant.
        (incident.get("parentXDRIncident"), "incident.parentXDRIncident"),
        (incident.get("parent_xdr_incident"), "incident.parent_xdr_incident"),
        ((incident.get("CustomFields") or {}).get("parentxdrincident"), "CustomFields.parentxdrincident"),
    ):
        if value not in ABSENT:
            # The issue carries it prefixed ("INCIDENT-49101"); the Cases API wants the
            # bare numeric id. Strip rather than assume either shape.
            cid = str(value).strip()
            if cid.upper().startswith("INCIDENT-"):
                cid = cid.split("-", 1)[1].strip()
            if not cid.isdigit():
                return None, f"case id {value!r} is not a numeric id"
            return cid, where
    return None, "no case id on the issue"


def read_case(case_id):
    """(severity, starred) for the case, or (None, None) when it cannot be read."""
    body = json.dumps({"request_data": {"filters": [
        {"field": "case_id", "operator": "in", "value": [int(case_id)]}]}})
    try:
        res = demisto.executeCommand("core-api-post",
                                     {"uri": "/public_api/v1/case/search", "body": body})
        if isinstance(res, list):
            res = res[0] if res else {}
        # executeCommand returns a war-room ENTRY; the command's own payload sits under
        # Contents. Reading the entry's top level found nothing on a tenant and the
        # severity silently went unread, which then suppressed the raise. Try the entry
        # body first, then the bare shapes, so either wrapping works.
        rows = []
        for base_obj in (demisto.get(res, "Contents") or {}, res):
            rows = (demisto.get(base_obj, "response.reply.DATA")
                    or demisto.get(base_obj, "reply.DATA")
                    or demisto.get(base_obj, "DATA") or [])
            if rows:
                break
        if rows:
            return rows[0].get("severity"), rows[0].get("starred")
    except Exception as e:  # noqa: BLE001
        demisto.debug(f"SOCFWElevateCase: cannot read case {case_id}: {e}")
    return None, None


def _row(**kw):
    row = {
        "event_type": "elevate_decision",
        "phase": "triage",
        "action_actor": kw.pop("actor", "framework"),
        "decided_at": datetime.now(timezone.utc).isoformat(),
    }
    row.update({k: v for k, v in kw.items() if v not in ABSENT})
    try:
        demisto.executeCommand("socfw-post-to-dataset",
                               {"using": "socfw_ir_execution_writer", "JSON": json.dumps(row, default=str)})
    except Exception as e:  # noqa: BLE001 - telemetry must never fail the phase
        demisto.debug(f"SOCFWElevateCase: elevate_decision row not written: {e}")


def main():
    args = demisto.args() or {}
    ctx = demisto.context()
    incident = demisto.incident() or {}
    source_key = args.get("source_key") or "Assessment.AI"
    # Which surface is calling. Defaults to the automated path, which ships
    # shadowed; a layout button or a test passes analyst, which is live.
    actor = (args.get("actor") or "framework").strip().lower()

    policy = _policy()
    assessment = _assessment(ctx, source_key)
    issue_id = str(incident.get("id") or "")

    def stop(status, reason, icon="⚪", extra=""):
        _row(incident_id=issue_id, status=status, decision_reason=reason,
             verdict=assessment.get("verdict"))
        return_results(CommandResults(readable_output=f"{icon} **Not elevating** — {reason}.{extra}"))

    if not policy.get("enabled"):
        return stop("disabled", f"phases.triage.elevate.enabled is not true in {POLICY_LIST}")
    if not assessment:
        return stop("unavailable", f"no assessment at `{source_key}`")
    rules = policy.get("rules") or []
    if not rules:
        return stop("unavailable", "no rules configured under phases.triage.elevate.rules")

    matched, details = [], []
    for rule in rules:
        hit, detail = evaluate(rule, assessment)
        details.append(("match" if hit else "no") + f" — {detail}")
        if hit:
            matched.append(rule)
    trail = "\n" + "\n".join(f"- {d}" for d in details)

    if not matched:
        return stop("no_match", "no rule matched", extra=trail)

    why = matched[0].get("reason") or matched[0].get("name") or "policy rule matched"
    target = pick_target(matched, policy)
    if not target:
        return stop("unavailable", "no valid target_severity on the matching rules or the block", extra=trail)

    case_id, source = resolve_case_id(args, ctx, incident)
    if not case_id:
        _row(incident_id=issue_id, status="unavailable", capability=why,
             decision_reason=f"elevation warranted but {source}", verdict=assessment.get("verdict"))
        return_results(CommandResults(readable_output=(
            f"🟡 **Elevation warranted but not applied** — {why}, however {source}. "
            f"Elevation is case-level; this issue is not attached to a case yet.{trail}")))
        return

    current, already_starred = read_case(case_id)

    # Star first and separately: it is the cheap, reversible-by-a-human signal, and
    # it should land even when the severity is already high enough to need no change.
    # Idempotent on the case's actual starred state rather than a flag, because every
    # issue in a case runs this and a 16-issue case would otherwise dispatch 16 times.
    star_done, star_note = False, "star_case disabled in policy"
    if policy.get("star_case"):
        if already_starred:
            star_note = "already starred"
        else:
            demisto.executeCommand("SOCCommandWrapper", {
                "action": ACTION_STAR,
                "Phase": "triage",
                "Action_Actor": actor,
            })
            star_done, star_note = True, "star requested"

    if current is None:
        # Starring needs no prior value; raising does, and raising blind could lower
        # it. So an unreadable severity stops the raise and nothing else.
        _row(incident_id=issue_id, case_id=case_id, status="star_only", capability=why,
             action=ACTION_STAR,
             decision_reason=f"{star_note}; severity unreadable — not raising blind")
        return_results(CommandResults(readable_output=(
            f"⭐ **Case {case_id}: {star_note}** — {why}.  Severity left alone: could "
            f"not read the current value, and raising blind risks lowering it.{trail}")))
        return

    if not policy.get("raise_severity", True):
        _row(incident_id=issue_id, case_id=case_id, status="star_only", capability=why,
             action=ACTION_STAR,
             decision_reason=star_note, verdict=assessment.get("verdict"))
        return_results(CommandResults(readable_output=(
            f"⭐ **Case {case_id}: {star_note}** — {why}.  "
            f"Severity raising is off in policy.{trail}")))
        return

    go, reason = decide(current, target, bool(policy.get("raise_only", True)))
    _row(incident_id=issue_id, case_id=case_id, parent_xdr_incident=case_id,
         action=ACTION_SEVERITY if go else ACTION_STAR,
         status="requested" if go else "no_change",
         decision_reason=f"{reason}; {star_note}", capability=why,
         severity=target, verdict=assessment.get("verdict"),
         escalate_recommended=assessment.get("escalate_recommended"),
         already_contained=assessment.get("already_contained"))

    if not go:
        icon = "⭐" if star_done else "⚪"
        return_results(CommandResults(readable_output=(
            f"{icon} **Case {case_id}: {star_note}**, severity unchanged — {reason}.  "
            f"({why}){trail}")))
        return

    demisto.setContext("SOCFramework.Elevate.case_id", case_id)
    demisto.setContext("SOCFramework.Elevate.target", target)

    demisto.executeCommand("SOCCommandWrapper", {
        "action": ACTION_SEVERITY,
        "Phase": "triage",
        "Action_Actor": actor,
    })
    return_results(CommandResults(readable_output=(
        f"🔴 **Case {case_id}: {star_note}, severity {reason}** — {why}.  "
        f"(case id from {source})  Whether it applies depends on shadow mode for "
        f"{ACTION_SEVERITY}.{trail}")))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
