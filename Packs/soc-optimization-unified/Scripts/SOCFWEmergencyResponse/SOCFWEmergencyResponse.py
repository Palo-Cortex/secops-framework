"""Respond to an issue without waiting for its case to develop.

Emergency response is a short list of policies: when an issue matches one, run
its actions now, at issue level, as the issue_emergency actor. The pack ships
default policies in phases.triage.emergency of SOCFrameworkPhasePolicy_V3; a
tenant adds or edits its own in SOCFWTenantConfig (emergency.policies), written
by !SOCFWConfig command=emergency. A tenant policy with the same label as a
shipped one edits it, key by key; a new label adds a policy. Every policy that
matches fires, and each action runs once.

A policy says what the issue is about and how sure the assessment must be:

  about          identity, endpoint, email ... - matches the issue's product
                 category (from the source key, subdivided by product_map) OR the
                 assessment's primary_entity_type. An Okta login from a bad IP is
                 an Identity issue even when the model names the IP as the entity;
                 a credential theft seen by an EDR is about an identity even though
                 its source is Endpoint.
  source         source keys, e.g. ds_okta_systemlog
  rule_id        the detection rule's id (issue.ruleid). Local to a tenant, so
                 only ever in a tenant policy - but it survives a rename.
  name_contains  text in the issue name, case-insensitive. For issues with no rule
                 id; it depends on how the detection is named.
  verdict        assessment verdicts allowed (default malicious; "any" drops it)
  confidence     minimum assessment confidence (default high; "any" drops it)
  exposure       assessment exposure values allowed (default: any)
  actions        SOCFrameworkActions_V3 actions to run, in order

The subject fields that are given must all hold. A policy that names no subject
never fires.

Never acts on an issue the assessment says is already contained.

The actions go through SOCCommandWrapper like every other action, so shadow per
actor, tenant config, the execution row and the environment checks apply
without being reimplemented here. Whether a call really ran is the wrapper's
answer, read from the entries it returns - not assumed.

The issue is closed as true positive, contained, only when every action of the
matched policies really ran and succeeded. When any was simulated, skipped or
failed it records what would have been closed and leaves the issue open for the
rest of the entry point, so a shadowed PoV never closes a malicious issue on the
strength of a simulated containment. The close is its own action,
soc-close-issue-contained, shadowed per actor like the rest.
"""
import json
from datetime import datetime, timezone

import demistomock as demisto
from CommonServerPython import *

POLICY_LIST = "SOCFrameworkPhasePolicy_V3"
TENANT_CONFIG_LIST = "SOCFWTenantConfig"
ACTIONS_LIST = "SOCFrameworkActions_V3"
ACTOR = "issue_emergency"
CLOSE_ACTION = "soc-close-issue-contained"
DISPATCH_KEY = "SOCFramework.Emergency.Dispatch"
NOTES_KEY = "SOCFramework.Emergency.close_notes"

CONFIDENCE = {"low": 1, "medium": 2, "high": 3}
DEFAULT_VERDICT = ["malicious"]
DEFAULT_CONFIDENCE = "high"
SUBJECT_FIELDS = ("about", "source", "rule_id", "name_contains")
ABSENT = (None, "", [], {})


# ── Reading ──────────────────────────────────────────────────────────────────

def _get_list(name):
    try:
        res = demisto.executeCommand("getList", {"listName": name})
        if res and not isError(res):
            raw = res[0].get("Contents")
            if isinstance(raw, dict):
                return raw
            if isinstance(raw, str) and "Item not found" not in raw:
                doc = json.loads(raw)
                return doc if isinstance(doc, dict) else {}
    except Exception as e:  # noqa: BLE001
        demisto.debug(f"SOCFWEmergencyResponse: {name} unreadable: {e}")
    return {}


def _as_list(value):
    if value in ABSENT:
        return []
    items = value if isinstance(value, list) else str(value).split(",")
    return [str(i).strip() for i in items if str(i).strip()]


def merge_policies(section, tenant_cfg):
    """Shipped policies edited by the tenant's, then the tenant's own, in order.

    The same merge SOCFWConfig shows in command=emergency; a test holds the two
    to each other.
    """
    tenant = ((tenant_cfg or {}).get("emergency") or {}).get("policies") or {}
    if not isinstance(tenant, dict):
        tenant = {}
    out, seen = [], set()
    for p in (section or {}).get("policies") or []:
        if not isinstance(p, dict) or not p.get("policy"):
            continue
        name = p["policy"]
        merged = dict(p)
        edit = tenant.get(name)
        if isinstance(edit, dict):
            merged.update({k: v for k, v in edit.items() if k != "policy"})
            merged["origin"] = "shipped, edited on this tenant"
        else:
            merged["origin"] = "shipped"
        out.append(merged)
        seen.add(name)
    for name, p in tenant.items():
        if name in seen or not isinstance(p, dict):
            continue
        out.append(dict(p, policy=name, origin="this tenant"))
    return out


def facts_for(assessment, ctx, incident):
    custom = incident.get("CustomFields") or {}
    rule_id = incident.get("ruleid") or incident.get("ruleId") or custom.get("ruleid")
    return {
        "category": str(demisto.get(ctx, "SOCFramework.Product.category") or "").strip().lower(),
        "source": str(demisto.get(ctx, "SOCFramework.Product.key") or "").strip().lower(),
        "rule_id": str(rule_id).strip() if rule_id not in ABSENT else "",
        "name": str(incident.get("name") or ""),
        "entity_type": str(assessment.get("primary_entity_type") or "").strip().lower(),
        "verdict": str(assessment.get("verdict") or "").strip().lower(),
        "confidence": str(assessment.get("confidence") or "").strip().lower(),
        "exposure": str(assessment.get("exposure") or "").strip().lower(),
        "already_contained": assessment.get("already_contained"),
    }


# ── Matching ─────────────────────────────────────────────────────────────────

def _off(policy):
    return policy.get("enabled") is False or str(policy.get("enabled")).strip().lower() == "false"


def evaluate(policy, f):
    """(matched, detail). Every condition the policy names must hold."""
    name = policy.get("policy") or "unnamed"
    if _off(policy):
        return False, f"{name}: turned off"
    if not any(_as_list(policy.get(k)) for k in SUBJECT_FIELDS):
        return False, f"{name}: names no subject (about, source, rule_id or name_contains)"
    if not _as_list(policy.get("actions")):
        return False, f"{name}: lists no actions"

    held = []
    about = [v.lower() for v in _as_list(policy.get("about"))]
    if about:
        if f["category"] in about:
            held.append(f"category {f['category']}")
        elif f["entity_type"] in about:
            held.append(f"entity {f['entity_type']}")
        else:
            return False, (f"{name}: about {'/'.join(about)}, issue is category "
                           f"{f['category'] or '(none)'}, entity {f['entity_type'] or '(none)'}")
    sources = [v.lower() for v in _as_list(policy.get("source"))]
    if sources:
        if f["source"] not in sources:
            return False, f"{name}: source {f['source'] or '(none)'} not in {', '.join(sources)}"
        held.append(f"source {f['source']}")
    rule_ids = _as_list(policy.get("rule_id"))
    if rule_ids:
        if not f["rule_id"] or f["rule_id"] not in rule_ids:
            return False, f"{name}: rule id {f['rule_id'] or '(none)'} not in {', '.join(rule_ids)}"
        held.append(f"rule {f['rule_id']}")
    contains = _as_list(policy.get("name_contains"))
    if contains:
        hit = next((c for c in contains if c.lower() in f["name"].lower()), None)
        if not hit:
            return False, f"{name}: issue name contains none of {', '.join(contains)}"
        held.append(f"name contains {hit!r}")

    verdicts = [v.lower() for v in (_as_list(policy.get("verdict")) or DEFAULT_VERDICT)]
    if "any" not in verdicts:
        if f["verdict"] not in verdicts:
            return False, f"{name}: verdict {f['verdict'] or '(none)'}, needs {'/'.join(verdicts)}"
        held.append(f["verdict"])
    floor = str(policy.get("confidence") or DEFAULT_CONFIDENCE).strip().lower()
    if floor != "any":
        if floor not in CONFIDENCE:
            return False, f"{name}: confidence {floor!r} is not low, medium, high or any"
        if CONFIDENCE.get(f["confidence"], 0) < CONFIDENCE[floor]:
            return False, f"{name}: confidence {f['confidence'] or '(none)'}, needs {floor} or higher"
        held.append(f"{f['confidence']} confidence")
    exposures = [v.lower() for v in _as_list(policy.get("exposure"))]
    if exposures and "any" not in exposures:
        if f["exposure"] not in exposures:
            return False, f"{name}: exposure {f['exposure'] or '(none)'}, needs {'/'.join(exposures)}"
        held.append(f"exposure {f['exposure']}")
    return True, f"{name}: " + ", ".join(held)


def plan(policies, f):
    """(matched policies, ordered unique actions, trail)."""
    matched, actions, trail = [], [], []
    for p in policies:
        hit, detail = evaluate(p, f)
        trail.append(("match" if hit else "no") + f" — {detail} ({p.get('origin')})")
        if hit:
            matched.append(p)
            for a in _as_list(p.get("actions")):
                if a not in actions:
                    actions.append(a)
    return matched, actions, trail


# ── Outcome of what the wrapper did ──────────────────────────────────────────

def records_from(action, entries):
    """The wrapper's record of each call, from the entries executeCommand returns.

    The wrapper logs each record as a structured War Room entry - SHADOW MODE,
    Command Success, Command Failure, Command Execution Error - whose Contents is
    the record itself, and each skip under a "<action>: skipped" title with its
    reason. Read from the entries because what a nested script writes to context
    is not visible to its caller until the caller finishes - measured on
    deathstar, 28 Oct 2026.
    """
    records = []
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        contents = e.get("Contents")
        title = str(e.get("HumanReadable") or "").split("\n", 1)[0]
        if e.get("Type") == 4:
            records.append({"action": action, "success": False, "shadow_mode": False,
                            "error": str(contents)[:300]})
        elif isinstance(contents, dict) and "success" in contents and contents.get("action") == action:
            records.append(contents)
        elif isinstance(contents, dict) and f"{action}: skipped" in title:
            records.append({"action": action, "skipped": True,
                            "skip_reason": str(contents.get("reason") or title)})
    return records


def outcome_of(action, records):
    """(executed | shadow | skipped | failed | no_record, why)."""
    mine = [r for r in records if isinstance(r, dict) and r.get("action") == action]
    if not mine:
        return "no_record", "the wrapper reported nothing for it"
    skipped = [r for r in mine if r.get("skipped")]
    if skipped:
        return "skipped", str(skipped[0].get("skip_reason") or "skipped")
    errors = [r for r in mine if r.get("error")]
    if errors:
        return "failed", str(errors[0].get("error"))
    if any(r.get("shadow_mode") for r in mine):
        return "shadow", "simulated (shadow mode)"
    if all(r.get("success") is True for r in mine):
        return "executed", "ran on " + ", ".join(sorted({str(r.get("vendor")) for r in mine}))
    return "failed", "the wrapper did not report success"


def _dispatch(action, phase):
    """(outcome, why) for one wrapper call."""
    try:
        entries = demisto.executeCommand("SOCCommandWrapper", {
            "action": action,
            "Phase": phase,
            "Action_Actor": ACTOR,
            "output_key": DISPATCH_KEY,
        })
    except Exception as e:  # noqa: BLE001
        return "failed", f"the wrapper raised: {e}"
    return outcome_of(action, records_from(action, entries))


def _row(**kw):
    row = {"event_type": "emergency_decision", "phase": "triage", "action_actor": ACTOR,
           "decided_at": datetime.now(timezone.utc).isoformat()}
    row.update({k: v for k, v in kw.items() if v not in ABSENT})
    try:
        demisto.executeCommand("socfw-post-to-dataset",
                               {"using": "socfw_ir_execution_writer", "JSON": json.dumps(row, default=str)})
    except Exception as e:  # noqa: BLE001 - telemetry must never fail the phase
        demisto.debug(f"SOCFWEmergencyResponse: emergency_decision row not written: {e}")


ICON = {"executed": "✅", "shadow": "🟡", "skipped": "⚪", "failed": "🔴", "no_record": "⚠️"}


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


def main():
    args = demisto.args() or {}
    ctx = demisto.context() or {}
    incident = demisto.incident() or {}
    issue_id = str(incident.get("id") or "")
    source_key = args.get("source_key") or "Assessment.AI"

    assessment = _assessment(ctx, source_key)
    section = ((_get_list(POLICY_LIST).get("phases") or {}).get("triage") or {}).get("emergency") or {}
    f = facts_for(assessment, ctx, incident)

    def stop(status, reason, extra=""):
        _row(incident_id=issue_id, status=status, decision_reason=reason,
             verdict=f["verdict"], confidence=f["confidence"])
        return_results(CommandResults(readable_output=f"⚪ **No emergency response** — {reason}.{extra}"))

    if section.get("enabled") is not True:
        return stop("disabled", f"phases.triage.emergency.enabled is not true in {POLICY_LIST}")
    if not assessment:
        return stop("unavailable", f"no assessment at `{source_key}`")
    if str(f["already_contained"]).strip().lower() == "true":
        return stop("already_contained", "the assessment says the issue is already contained")

    policies = merge_policies(section, _get_list(TENANT_CONFIG_LIST))
    matched, actions, trail = plan(policies, f)
    trail_md = "\n" + "\n".join(f"- {t}" for t in trail)
    if not matched:
        return stop("no_match", "no policy matched", extra=trail_md)

    rows = _get_list(ACTIONS_LIST)
    names = ", ".join(p["policy"] for p in matched)
    results = []
    for action in actions:
        row = rows.get(action)
        if not isinstance(row, dict) or "responses" not in row:
            results.append((action, "skipped", f"not in {ACTIONS_LIST}"))
            continue
        status, why = _dispatch(action, row.get("phase") or "containment")
        results.append((action, status, why))

    contained = bool(results) and all(s == "executed" for _, s, _ in results)
    close_status, close_why = "not_attempted", ""
    if section.get("close_when_contained", True) is not True:
        close_why = "closing is off (phases.triage.emergency.close_when_contained)"
    elif not contained:
        held = [a for a, s, _ in results if s != "executed"]
        close_why = ("not closed: " + ", ".join(held) + " did not run for real, so the "
                     "issue is not contained")
    elif CLOSE_ACTION not in rows:
        close_status, close_why = "skipped", f"{CLOSE_ACTION} is not in {ACTIONS_LIST}"
    else:
        demisto.setContext(NOTES_KEY, (
            f"Contained by SOC Framework emergency response ({names}): "
            + ", ".join(a for a, _, _ in results)
            + f". Assessment: {f['verdict']}, {f['confidence']} confidence."))
        close_status, close_why = _dispatch(CLOSE_ACTION, "triage")

    _row(incident_id=issue_id, status="contained" if contained else "responded",
         policy=names, action=",".join(actions),
         action_status="; ".join(f"{a}={s}" for a, s, _ in results),
         contained=contained, close_status=close_status,
         decision_reason=close_why or f"closed through {CLOSE_ACTION}",
         verdict=f["verdict"], confidence=f["confidence"], exposure=f["exposure"],
         entity_type=f["entity_type"], rule_id=f["rule_id"])

    demisto.setContext("SOCFramework.Emergency.policies", [p["policy"] for p in matched])
    demisto.setContext("SOCFramework.Emergency.contained", contained)
    demisto.setContext("SOCFramework.Emergency.closed", close_status == "executed")

    md = [f"### 🚨 Emergency response — {names}", "", "| Action | Outcome | |", "|---|---|---|"]
    md += [f"| {a} | {ICON.get(s, '')} {s} | {w} |" for a, s, w in results]
    if close_status == "executed":
        md += ["", f"**Closed** as true positive, contained ({CLOSE_ACTION})."]
    else:
        md += ["", f"**Close:** {close_status} — {close_why}."]
    md += ["", "Policies:" + trail_md]
    return_results(CommandResults(readable_output="\n".join(md)))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
