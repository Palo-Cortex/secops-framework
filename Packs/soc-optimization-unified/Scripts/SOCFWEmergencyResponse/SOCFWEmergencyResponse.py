"""Contain an issue without waiting for its case to develop.

Emergency response is a short list of policies: when an issue matches one, run
its containment actions now, at issue level, as the issue_emergency actor. The
pack ships default policies in phases.triage.emergency of
SOCFrameworkPhasePolicy_V3; a tenant adds or edits its own in SOCFWTenantConfig
(emergency.policies), written by !SOCFWConfig command=emergency. A tenant policy
with the same label as a shipped one edits it, key by key; a new label adds a
policy. Every policy that matches fires, and each action runs once. Only
containment actions run here - eradication and recovery wait for the case.

A policy says what the issue is about and how sure the assessment must be:

  about          identity, endpoint, email ... - the issue's product category
                 (from the source key, subdivided by product_map)
  entity_type    optional: the assessment's primary_entity_type must be one of these
  source         source keys, e.g. ds_okta_systemlog
  rule_id        the detection rule's id (issue.ruleid). Local to a tenant, so
                 only ever in a tenant policy - but it survives a rename.
  name_contains  text in the issue name, case-insensitive. For issues with no rule
                 id; it depends on how the detection is named.
  verdict        assessment verdicts allowed (default malicious; "any" drops it)
  confidence     minimum assessment confidence (default high; "any" drops it)
  exposure       assessment exposure values allowed (default: any)
  actions        SOCFrameworkActions_V3 containment actions to run, in order

Which hosts and accounts may be contained is set once for the section:

  protect            never contained: host:<name or pattern>, ip:<address>,
                     cidr:<range>, account:<name or pattern>, list:<XSIAM list>
  containable_hosts  when set, a host action runs only on these (same entries)
  containable_roles  otherwise the host's role must be one of these (default
                     workstation; any turns the check off)
  role               host:<pattern>:<role> - a role for hosts that report none

The role is the first to answer: this tenant's role entries, the EDR
(SOCFramework.Endpoint.role, refreshed by soc-enrich-endpoint), the operating
system (macOS and Windows client editions read as workstation, Windows Server as
server, Linux as unknown). An unknown role is never contained. A host the EDR
already reports contained or pending is skipped as already done.

Containment that was needed but did not happen - protected, role or host not
containable, the vendor failed or the action skipped - stars the case and raises
its severity to escalate_severity, raise only, as automation, so a person
contains it by hand. Never acts on an issue the assessment says is already
contained.

The actions go through SOCCommandWrapper like every other action, so shadow per
actor, tenant config, the execution row and the environment checks apply
without being reimplemented here. Whether a call really ran is the wrapper's
answer, read from the entries it returns - not assumed.

The issue is closed as true positive, contained only when every action of the
matched policies really ran, or the EDR already reported the host contained.
When any was simulated, skipped or failed it records what would have been done
and leaves the issue open for the rest of the entry point, so a shadowed PoV
never closes a malicious issue on the strength of a simulated containment. The
close is its own action, soc-close-issue-contained, run as automation.
"""
import fnmatch
import ipaddress
import json
from datetime import datetime, timezone

import demistomock as demisto
from CommonServerPython import *

POLICY_LIST = "SOCFrameworkPhasePolicy_V3"
TENANT_CONFIG_LIST = "SOCFWTenantConfig"
ACTIONS_LIST = "SOCFrameworkActions_V3"
ACTOR = "issue_emergency"          # containment only
TRIAGE_ACTOR = "automation"        # the close and the escalation
CLOSE_ACTION = "soc-close-issue-contained"
STAR_ACTION = "soc-star-case"
SEVERITY_ACTION = "soc-raise-case-severity"
HOST_SCOPE = "host"
IDENTITY_SCOPE = "identity"
DISPATCH_KEY = "SOCFramework.Emergency.Dispatch"
NOTES_KEY = "SOCFramework.Emergency.close_notes"

CONFIDENCE = {"low": 1, "medium": 2, "high": 3}
DEFAULT_VERDICT = ["malicious"]
DEFAULT_CONFIDENCE = "high"
SUBJECT_FIELDS = ("about", "source", "rule_id", "name_contains")
ABSENT = (None, "", [], {})
SEVERITY_RANK = {"info": 1, "informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
CONTAINED_STATES = ("contained", "containment_pending")
SECTION_SETTINGS = ("containable_roles", "containable_hosts", "protect", "role", "escalate_severity")


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
        "hostnames": _values(ctx, "SOCFramework.Artifacts.Endpoint.Hostname", "SOCFramework.Endpoint.hostname"),
        "ips": _values(ctx, "SOCFramework.Artifacts.Endpoint.IPAddress", "SOCFramework.Endpoint.ip_address"),
        "os": " ".join(_values(ctx, "SOCFramework.Artifacts.Endpoint.OSVersion",
                               "SOCFramework.Artifacts.Endpoint.OS", "SOCFramework.Endpoint.os")),
        "reported_role": str(demisto.get(ctx, "SOCFramework.Endpoint.role") or "").strip().lower(),
        "containment_status": str(demisto.get(ctx, "SOCFramework.Endpoint.containment_status") or "").strip().lower(),
        "accounts": _values(ctx, "SOCFramework.Artifacts.Identity.User.UPN", "SOCFramework.Artifacts.Identity.User.Email",
                            "SOCFramework.Artifacts.Identity.User.SAM", "SOCFramework.Primary.User"),
    }


def _values(ctx, *paths):
    out = []
    for path in paths:
        v = demisto.get(ctx, path)
        for item in (v if isinstance(v, list) else [v]):
            if item not in ABSENT and str(item).strip() and str(item).strip() not in out:
                out.append(str(item).strip())
    return out


# ── Which hosts and accounts may be contained ────────────────────────────────

def merge_settings(section, tenant_cfg):
    """The section's host settings, each replaced whole by the tenant's when set.

    The same merge SOCFWConfig shows; a test holds the two to each other.
    """
    tenant = (tenant_cfg or {}).get("emergency") or {}
    out = {}
    for key in SECTION_SETTINGS:
        if isinstance(tenant, dict) and key in tenant:
            out[key], out[f"{key}_from"] = tenant[key], "this tenant"
        else:
            out[key], out[f"{key}_from"] = (section or {}).get(key), "shipped"
    return out


def expand_entries(entries):
    """Entries with list:<name> replaced by that XSIAM list's lines.

    A line may carry its own prefix; a bare line reads as ip, cidr or host by its shape.
    """
    out = []
    for entry in _as_list(entries):
        if entry.lower().startswith("list:"):
            text = _list_text(entry.split(":", 1)[1].strip())
            out += [line.strip() for line in text.splitlines()
                    if line.strip() and not line.strip().startswith("#")]
        else:
            out.append(entry)
    return [_typed(e) for e in out]


def _list_text(name):
    try:
        res = demisto.executeCommand("getList", {"listName": name})
        if res and not isError(res):
            raw = res[0].get("Contents")
            return raw if isinstance(raw, str) and "Item not found" not in raw else ""
    except Exception as e:  # noqa: BLE001
        demisto.debug(f"SOCFWEmergencyResponse: list {name} unreadable: {e}")
    return ""


def _typed(entry):
    if ":" in entry and entry.split(":", 1)[0].lower() in ("host", "ip", "cidr", "account"):
        kind, value = entry.split(":", 1)
        return kind.lower(), value.strip()
    try:
        if "/" in entry:
            ipaddress.ip_network(entry, strict=False)
            return "cidr", entry
        ipaddress.ip_address(entry)
        return "ip", entry
    except ValueError:
        return "host", entry


def _short(name):
    return str(name).strip().lower().split(".")[0]


def _ip_in(ip, net):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
    except ValueError:
        return False


def host_matches(entries, f):
    """The first entry naming this host, or None."""
    for kind, value in entries:
        if kind == "host" and any(fnmatch.fnmatch(_short(h), _short(value)) for h in f["hostnames"]):
            return f"host {value}"
        if kind == "ip" and value in f["ips"]:
            return f"ip {value}"
        if kind == "cidr" and any(_ip_in(ip, value) for ip in f["ips"]):
            return f"cidr {value}"
    return None


def _account_key(name):
    n = str(name).strip().lower()
    return n.split("\\")[-1].split("@")[0]


def account_matches(entries, f):
    for kind, value in entries:
        if kind == "account" and any(
                fnmatch.fnmatch(str(a).lower(), value.lower())
                or fnmatch.fnmatch(_account_key(a), _account_key(value)) for a in f["accounts"]):
            return f"account {value}"
    return None


def os_role(os_text):
    t = (os_text or "").lower()
    if not t:
        return ""
    if "windows" in t and "server" in t:
        return "server"
    if any(m in t for m in ("mac", "darwin", "os x")):
        return "workstation"
    if "windows" in t:
        return "workstation"
    return ""


def host_role(settings, f):
    """(role, where it came from). The first source to answer wins."""
    for entry in _as_list(settings.get("role")):
        parts = entry.split(":")
        if len(parts) == 3 and parts[0].lower() == "host" and any(
                fnmatch.fnmatch(_short(h), _short(parts[1])) for h in f["hostnames"]):
            return parts[2].strip().lower(), f"tenant role entry {parts[1]}"
    if f["reported_role"] and f["reported_role"] != "unknown":
        return f["reported_role"], "EDR"
    r = os_role(f["os"])
    if r:
        return r, f"operating system ({f['os']})"
    return "unknown", "no source reported one"


def gate(scope, settings, f):
    """(go, outcome, why) for one action on this issue's host or account."""
    protect = expand_entries(settings.get("protect"))
    if scope == HOST_SCOPE:
        hit = host_matches(protect, f)
        if hit:
            return False, "blocked", f"protected ({settings.get('protect_from')}: {hit})"
        listed = expand_entries(settings.get("containable_hosts"))
        if listed:
            hit = host_matches(listed, f)
            if not hit:
                return False, "blocked", f"not in containable_hosts ({settings.get('containable_hosts_from')})"
        else:
            roles = [r.lower() for r in _as_list(settings.get("containable_roles"))]
            if "any" not in roles:
                role, source = host_role(settings, f)
                if role not in roles:
                    return False, "blocked", (f"role {role} ({source}) is not in containable_roles "
                                              f"{'/'.join(roles) or '(none)'}")
        if f["containment_status"] in CONTAINED_STATES:
            return False, "already", f"the EDR reports the host {f['containment_status']}"
    elif scope == IDENTITY_SCOPE:
        hit = account_matches(protect, f)
        if hit:
            return False, "blocked", f"protected ({settings.get('protect_from')}: {hit})"
    return True, "", ""


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
        if f["category"] not in about:
            return False, f"{name}: about {'/'.join(about)}, issue is category {f['category'] or '(none)'}"
        held.append(f"category {f['category']}")
    entities = [v.lower() for v in _as_list(policy.get("entity_type"))]
    if entities:
        if f["entity_type"] not in entities:
            return False, f"{name}: entity {f['entity_type'] or '(none)'} not in {', '.join(entities)}"
        held.append(f"entity {f['entity_type']}")
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


def _dispatch(action, phase, actor=ACTOR, target=None):
    """(outcome, why, record) for one wrapper call."""
    args = {"action": action, "Phase": phase, "Action_Actor": actor, "output_key": DISPATCH_KEY}
    if target:
        args["target"] = target
    try:
        entries = demisto.executeCommand("SOCCommandWrapper", args)
    except Exception as e:  # noqa: BLE001
        return "failed", f"the wrapper raised: {e}", {}
    records = records_from(action, entries)
    status, why = outcome_of(action, records)
    return status, why, (records[0] if records else {})


def case_severity(incident):
    """(case id, current severity) of the issue's case, or (None, None)."""
    raw = incident.get("parentXDRIncident") or (incident.get("CustomFields") or {}).get("parentxdrincident")
    cid = str(raw or "").strip()
    if cid.upper().startswith("INCIDENT-"):
        cid = cid.split("-", 1)[1]
    if not cid.isdigit():
        return None, None
    body = json.dumps({"request_data": {"filters": [
        {"field": "case_id", "operator": "in", "value": [int(cid)]}]}})
    try:
        res = demisto.executeCommand("core-api-post", {"uri": "/public_api/v1/case/search", "body": body})
        res = res[0] if isinstance(res, list) and res else (res or {})
        for base in (demisto.get(res, "Contents") or {}, res):
            rows = (demisto.get(base, "response.reply.DATA") or demisto.get(base, "reply.DATA")
                    or demisto.get(base, "DATA") or [])
            if rows:
                return cid, str(rows[0].get("severity") or "").lower() or None
    except Exception as e:  # noqa: BLE001
        demisto.debug(f"SOCFWEmergencyResponse: cannot read case {cid}: {e}")
    return cid, None


def escalate(incident, target, reasons):
    """Star the case and raise its severity to target - raise only - as automation.

    Returns (star outcome, severity outcome, note). A severity that cannot be
    read is not raised blind; the star still goes.
    """
    star, _, _ = _dispatch(STAR_ACTION, "triage", actor=TRIAGE_ACTOR)
    target = str(target or "critical").lower()
    if target not in SEVERITY_RANK or target in ("info", "informational"):
        return star, "skipped", f"escalate_severity {target!r} is not low, medium, high or critical"
    cid, current = case_severity(incident)
    if cid is None:
        return star, "skipped", "the issue has no case yet"
    if current is None:
        return star, "skipped", f"case {cid} severity unreadable - not raising blind"
    if SEVERITY_RANK.get(current, 0) >= SEVERITY_RANK[target]:
        return star, "no_change", f"case {cid} already {current}"
    sev, why, _ = _dispatch(SEVERITY_ACTION, "triage", actor=TRIAGE_ACTOR, target=target)
    return star, sev, f"case {cid} {current} -> {target} ({why})"


def _row(**kw):
    row = {"event_type": "emergency_decision", "phase": "triage", "action_actor": ACTOR,
           "decided_at": datetime.now(timezone.utc).isoformat()}
    row.update({k: v for k, v in kw.items() if v not in ABSENT})
    try:
        demisto.executeCommand("socfw-post-to-dataset",
                               {"using": "socfw_ir_execution_writer", "JSON": json.dumps(row, default=str)})
    except Exception as e:  # noqa: BLE001 - telemetry must never fail the phase
        demisto.debug(f"SOCFWEmergencyResponse: emergency_decision row not written: {e}")


ICON = {"executed": "✅", "shadow": "🟡", "skipped": "⚪", "failed": "🔴", "no_record": "⚠️",
        "blocked": "⛔", "already": "☑️", "excluded": "➖"}


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

    tenant_cfg = _get_list(TENANT_CONFIG_LIST)
    policies = merge_policies(section, tenant_cfg)
    settings = merge_settings(section, tenant_cfg)
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
        if str(row.get("phase") or "").lower() != "containment":
            results.append((action, "excluded", f"{row.get('phase')} action - emergency response runs "
                                                "containment only"))
            continue
        go, outcome, why = gate(row.get("entity_scope"), settings, f)
        if not go:
            results.append((action, outcome, why))
            continue
        status, why, record = _dispatch(action, "containment")
        results.append((action, status, why))
        if status == "executed" and row.get("entity_scope") == HOST_SCOPE:
            # Tell the next issue on this host - and the analyst - that it is under way.
            demisto.setContext("SOCFramework.Endpoint.containment_status", "containment_pending")
            demisto.executeCommand("setIssue", {"endpointisolationstatus": "containment_pending"})

    done = ("executed", "already", "excluded")
    contained = (any(s in ("executed", "already") for _, s, _ in results)
                 and all(s in done for _, s, _ in results))
    needs_person = [(a, s, w) for a, s, w in results if s in ("blocked", "failed", "skipped", "no_record")]
    escalation = ""
    if needs_person:
        star, sev, note = escalate(incident, settings.get("escalate_severity"),
                                   [w for _, _, w in needs_person])
        escalation = f"star {star}; severity {sev} ({note})"

    close_status, close_why = "not_attempted", ""
    if section.get("close_when_contained", True) is not True:
        close_why = "closing is off (phases.triage.emergency.close_when_contained)"
    elif not contained:
        held = [a for a, s, _ in results if s not in done]
        close_why = ("not closed: " + ", ".join(held) + " did not run for real, so the "
                     "issue is not contained")
    elif CLOSE_ACTION not in rows:
        close_status, close_why = "skipped", f"{CLOSE_ACTION} is not in {ACTIONS_LIST}"
    else:
        demisto.setContext(NOTES_KEY, (
            f"Contained by SOC Framework emergency response ({names}): "
            + ", ".join(f"{a} ({s})" for a, s, _ in results)
            + f". Assessment: {f['verdict']}, {f['confidence']} confidence."))
        close_status, close_why, _ = _dispatch(CLOSE_ACTION, "triage", actor=TRIAGE_ACTOR)

    _row(incident_id=issue_id, status="contained" if contained else "responded",
         policy=names, action=",".join(actions),
         action_status="; ".join(f"{a}={s}" for a, s, _ in results),
         blocked_reason="; ".join(f"{a}: {w}" for a, s, w in results if s == "blocked"),
         escalation=escalation,
         contained=contained, close_status=close_status,
         decision_reason=close_why or f"closed through {CLOSE_ACTION}",
         verdict=f["verdict"], confidence=f["confidence"], exposure=f["exposure"],
         entity_type=f["entity_type"], rule_id=f["rule_id"],
         entity_value=",".join(f["hostnames"]) or None)

    demisto.setContext("SOCFramework.Emergency.policies", [p["policy"] for p in matched])
    demisto.setContext("SOCFramework.Emergency.contained", contained)
    demisto.setContext("SOCFramework.Emergency.closed", close_status == "executed")
    demisto.setContext("SOCFramework.Emergency.escalated", bool(needs_person))

    md = [f"### 🚨 Emergency response — {names}", "", "| Action | Outcome | |", "|---|---|---|"]
    md += [f"| {a} | {ICON.get(s, '')} {s} | {w} |" for a, s, w in results]
    if escalation:
        md += ["", f"**Escalated** for a person to contain: {escalation}."]
    if close_status == "executed":
        md += ["", f"**Closed** as true positive, contained ({CLOSE_ACTION})."]
    else:
        md += ["", f"**Close:** {close_status} — {close_why}."]
    md += ["", "Policies:" + trail_md]
    return_results(CommandResults(readable_output="\n".join(md)))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
