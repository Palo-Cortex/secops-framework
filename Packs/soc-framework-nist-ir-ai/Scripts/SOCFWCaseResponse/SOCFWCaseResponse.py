"""Run the case's containment, eradication and recovery plans, in that order.

Case Analysis writes three ordered plans onto the case. This is the executor
side: it reads them back, works out which steps are already done from the
ledger, and hands each remaining step to SOCFWPhaseExecutor inside an issue of
the case whose contract carries what the vendor command needs (the agent id,
the message id, the hash). Nothing is resolved here, and every check the
executor and the Universal Command already make - environment denies, policy
mode and authority, shadow mode, missing integrations - applies exactly as it
does when an analyst presses the button.

A person stays in the middle of anything that would really run. While an
action is simulated (shadow, the default and the PoV setting) every step goes
to the wrapper, whose shadow record carries the action and its time, so
containment, eradication and recovery are measured before anything is turned
on. Once an action is live, a step the plan marks requires_human or the policy
rules approve is recorded as awaiting and never dispatched; when an analyst
runs it from the issue layout the wrapper writes its row and the next pass
counts the step as done. The executor makes that call - this driver only hands
it the step.

Each phase is recorded on the case as the contract SOCFrameworkPhaseContract_V3
declares for it - isolated_hosts, disabled_users, files_removed and the rest -
derived from the step results, so the next phase and the layout read one shape
whether a playbook, an analyst or this driver produced it.

Deliberately not a forEach over a sub-playbook: an argument that resolves to an
array runs a task once per element, which is what produced 118 verdict entries
for 16 cases. Everything loops in-process and reads the JOB's context directly.
"""

import json
import re
from datetime import datetime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

PHASES = ("containment", "eradication", "recovery")
PLAN_LEAF = {"containment": "containment_plan", "eradication": "eradication_plan",
             "recovery": "recovery_plan"}
ANALYSIS_ROOT = "SOCFramework.Analysis.AI"
POLICY_LIST = "SOCFrameworkPhasePolicy_V3"
ACTIONS_LIST = "SOCFrameworkActions_V3"
CONTRACT_LIST = "SOCFrameworkPhaseContract_V3"
# The wrapper's statuses that mean the action happened, live or simulated.
DONE_STATUSES = ("success", "simulated", "shadow", "executed", "completed")
RAN = ("done", "dispatched")
# A step the wrapper skipped (no implementation for the source, nothing to act
# on) is reported from the last pass, not sent again every few minutes.
REPORTED = ("skipped",)
# Fields of an issue's artifacts that name each kind of scope entity.
AIM_FIELDS = {"host": ("Endpoint.Hostname", "Endpoint.Name", "Hostname"),
              "identity": ("Identity.User.Name", "Identity.User.UPN", "Identity.User.Email",
                           "Identity.User.ID", "User"),
              "file": ("File", "Hash", "Target.SHA256", "Target.File", "FilePath"),
              "email": ("Email.Sender", "Email.Recipient", "Email.Address"),
              "ip": ("Network.IP", "IP", "Endpoint.IPAddress"),
              "domain": ("Domain", "Network.Domain", "URL")}
GAPS = ("environment_denied", "policy_blocked", "integration_unavailable",
        "contract_gap", "content_gap", "skipped", "failed", "error")
# Scope entity types as the agent writes them, mapped to the executor's.
ENTITY_TYPE = {"host": "host", "identity": "identity", "email": "artifact",
               "domain": "artifact", "file": "artifact", "ip": "artifact"}
# Which contract array each action fills with its target once it has run.
# Actions outside this table still count in status, story and Execution.
TARGET_OF = {"soc-isolate-endpoint": "isolated_hosts", "soc-disable-user": "disabled_users",
             "soc-delete-file": "files_removed", "soc-remove-file": "files_removed",
             "soc-remove-persistence": "persistence_removed"}
TEMPLATE = re.compile(r"\$\{([^}]+)\}")


def utc_now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def api(uri, body):
    """core-api-post, unwrapped to the response body. Raises on an error entry."""
    res = demisto.executeCommand("core-api-post", {"uri": uri, "body": json.dumps(body)})
    entry = res[0] if isinstance(res, list) and res else res
    if isinstance(entry, dict) and entry.get("Type") == entryTypes["error"]:
        raise DemistoException(str(entry.get("Contents"))[:200])
    contents = entry.get("Contents") if isinstance(entry, dict) else entry
    if isinstance(contents, str):
        try:
            contents = json.loads(contents)
        except Exception:
            return contents
    if isinstance(contents, dict) and "response" in contents:
        return contents["response"]
    return contents


def as_obj(value):
    """A JSON string or an object, to an object. Case context stores arrays as strings.

    setParentIncidentContext appends on every repeat write, so a leaf written by
    two analysis passes reads as two JSON strings. The last one is the current
    pass; the earlier ones are history the writer could not remove.
    """
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        value = value[-1]
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return None
    return value


def get_context(inv_id):
    """Another investigation's whole context, via the built-in getContext.

    The HTTP context endpoint needs its query wrapped in ${...}, and that gets
    template-expanded against the calling issue before the request ever leaves,
    so it answers with the wrong investigation's value. getContext takes the id
    directly and returns the context as a JSON string.
    """
    try:
        raw = demisto.executeCommand("getContext", {"id": str(inv_id)})
    except Exception as e:
        raise DemistoException("getContext failed: {}".format(str(e)[:80]))
    if isinstance(raw, list):
        raw = raw[0] if raw else {}
    if isinstance(raw, dict):
        raw = raw.get("Contents", raw)
    if isinstance(raw, str):
        raw = json.loads(raw)
    if isinstance(raw, dict) and isinstance(raw.get("context"), dict):
        raw = raw["context"]
    return raw if isinstance(raw, dict) else {}


def get_list(name):
    try:
        res = demisto.executeCommand("getList", {"listName": name})
        raw = res[0].get("Contents") if res else None
        return json.loads(raw) if isinstance(raw, str) else (raw or {})
    except Exception as e:
        demisto.debug("SOCFWCaseResponse: cannot read {} ({})".format(name, e))
        return {}


def post_row(payload):
    try:
        demisto.executeCommand("socfw-post-to-dataset", {
            "using": "socfw_ir_execution_writer", "JSON": json.dumps(payload)})
    except Exception as e:
        demisto.debug("SOCFWCaseResponse: dataset post failed ({})".format(e))


def read_contract(case_id):
    """The Analysis contract on the case: scope rows, the three plans and what to verify."""
    try:
        whole = get_context("INCIDENT-{}".format(case_id))
        node = demisto.get(whole, ANALYSIS_ROOT)
        if node is None:
            whole = get_context(str(case_id))
            node = demisto.get(whole, ANALYSIS_ROOT)
    except Exception as e:
        return None, "contract read failed: {}".format(str(e)[:80])
    if isinstance(node, list):
        node = node[-1] if node else None
    if not isinstance(node, dict):
        return None, "no Analysis contract on the case"
    out = {"verdict": node.get("verdict"), "response_recommended": node.get("response_recommended"),
           "scope": as_obj(node.get("scope")) or [],
           "verify_by_human": [v for v in (as_obj(node.get("verify_by_human")) or []) if v],
           "recorded": {}}
    for phase, leaf in PLAN_LEAF.items():
        out[phase] = [s for s in (as_obj(node.get(leaf)) or []) if isinstance(s, dict)]
        prior = demisto.get(whole, "SOCFramework.{}.story".format(phase.title()))
        out["recorded"][phase] = as_obj(prior) if prior not in (None, "") else None
        execution = as_obj(demisto.get(whole, "SOCFramework.{}.Execution".format(phase.title()))) or {}
        out.setdefault("recorded_steps", {})[phase] = step_signature(execution.get("by_step") or [])
        # The last pass, keyed by step, target and the issue it ran in. A row
        # with no issue (written before the issue was recorded) matches nothing.
        out.setdefault("finished", {})[phase] = {
            (r.get("action"), r.get("target"), str(r.get("issue"))): {"status": r.get("status"),
                                                                    "reason": r.get("reason"),
                                                                    "vendor": r.get("vendor")}
            for r in (execution.get("by_step") or [])
            if isinstance(r, dict) and r.get("issue") and r.get("status") in RAN + REPORTED}
    return out, None


def step_signature(rows):
    """What a phase record says per step, with ran and done read as one.

    A story can stay the same while the record under it is missing or stale -
    a record written before Execution was declared - and a phase that never
    rewrites its record re-sends its steps on every pass.
    """
    return [(r.get("action"), r.get("target"), "ran" if r.get("status") in RAN else r.get("status"),
             str(r.get("issue")) if r.get("issue") else None)
            for r in rows if isinstance(r, dict)]


OPEN_CASE = ("new", "under_investigation")


def open_cases(case_ids):
    """The candidates that are still open. A resolved case gets no response.

    The candidate query reads analysis rows, which outlive the case, so without
    this a closed case was worked again on every pass. An unreadable status
    keeps the case: failing closed here would silently stop all response.
    """
    if not case_ids:
        return []
    try:
        res = api("/public_api/v1/incidents/get_incidents", {"request_data": {
            "filters": [{"field": "incident_id_list", "operator": "in", "value": list(case_ids)}],
            "search_from": 0, "search_to": 100}})
        found = demisto.get(res, "reply.incidents")
        if not isinstance(found, list):
            return list(case_ids)
    except Exception as e:
        demisto.debug("SOCFWCaseResponse: case status unreadable, keeping all ({})".format(e))
        return list(case_ids)
    status = {str(c.get("incident_id")): str(c.get("status") or "").lower() for c in found}
    return [c for c in case_ids if status.get(str(c), "new") in OPEN_CASE]


def member_issues(case_id):
    """Every issue of the case, so a step can run in any issue that evidences its artifact."""
    try:
        res = api("/xsoar/public/v1/incidents/search",
                  {"filter": {"query": "caseid:{}".format(case_id), "size": 200}})
        return [str(i.get("id")) for i in (res or {}).get("data") or [] if i.get("id")]
    except Exception as e:
        demisto.debug("SOCFWCaseResponse: member search failed ({})".format(e))
        return []


def active_brands():
    """Brands with an active instance. None when the registry is unreadable (fail open)."""
    try:
        modules = demisto.getModules() or {}
    except Exception:
        return None
    if not modules:
        return None
    brands = {}
    for module in modules.values():
        if isinstance(module, dict) and module.get("brand"):
            brands.setdefault(module["brand"], []).append(module.get("state"))
    return {b for b, states in brands.items() if "active" in states}


def resolve_path(ctx, path):
    node = ctx
    for part in path.split("."):
        if isinstance(node, dict):
            node = node.get(part)
        elif isinstance(node, list) and node:
            node = node[0].get(part) if isinstance(node[0], dict) else None
        else:
            return None
        if node is None:
            return None
    return node


def binding_gaps(entry, brands, ctx):
    """The fewest ${...} arguments an issue's contract leaves unresolved, over reachable bindings.

    The same check SOCFWPhaseExecutor makes before it dispatches, applied here
    so the step is sent to an issue where it can run. The executor still makes
    its own check in that issue; this only chooses where.
    """
    responses = entry.get("responses") or {}
    best = None
    for vendor, binding in responses.items():
        if brands is not None and vendor not in brands:
            continue
        missing = []
        for raw in TEMPLATE.findall(json.dumps(binding.get("inline_args") or {})):
            if raw.startswith("SOCFramework."):
                value = resolve_path(ctx.get("SOCFramework") or {}, raw[len("SOCFramework."):])
            else:
                value = resolve_path(ctx, raw)
            if value in (None, "", [], {}):
                missing.append(raw)
        if best is None or len(missing) < len(best):
            best = missing
    return best


def name_forms(value):
    """A name and its short forms: host.fqdn -> host, user@dom / DOM\\user -> user."""
    v = str(value or "").strip().lower()
    forms = {v}
    if "@" in v:
        forms.add(v.split("@", 1)[0])
    if "\\" in v:
        forms.add(v.rsplit("\\", 1)[1])
    if "." in v and "@" not in v and not v.replace(".", "").isdigit():
        forms.add(v.split(".", 1)[0])
    return {f for f in forms if f}


def aims_at(entity, ctx):
    """Whether the issue's artifacts are this entity, so a step run there acts on it.

    The universal command acts on the issue's own artifacts. A reset for one user
    run in an issue whose user is another resets the wrong account, so an issue
    is used for a step only when its artifacts name the step's target. Types the
    table does not know, and steps with no target, match any issue.
    """
    fields = AIM_FIELDS.get(entity.get("type"))
    want = name_forms(entity.get("name"))
    if not fields or not want:
        return True
    artifacts = (ctx.get("SOCFramework") or {}).get("Artifacts") or {}
    for path in fields:
        value = resolve_path(artifacts, path)
        for item in (value if isinstance(value, list) else [value]):
            if item not in (None, "") and want & name_forms(item):
                return True
    return False


def pick_issue(step, entity, entry, brands, members, contexts):
    """The issue to run the step in: the first whose contract fills the most of the binding.

    Candidates in order of how directly they evidence the step: the step's own
    evidence_refs, then the scope entity's, then every other issue of the case.
    On a case where the quarantine step cited an issue carrying only the host,
    the neighbouring issue held both the agent id and the hash; the executor
    would have reported a contract gap in the first and run in the second.
    """
    candidates = []
    for ref in list(step.get("evidence_refs") or []) + list(entity.get("evidence_refs") or []) + members:
        ref = str(ref)
        if ref and ref not in candidates:
            candidates.append(ref)
    if not candidates:
        return None, None
    chosen, chosen_gaps, aimed = None, None, False
    for ref in candidates:
        if ref not in contexts:
            try:
                contexts[ref] = get_context(ref)
            except Exception:
                contexts[ref] = {}
        if not aims_at(entity, contexts[ref]):
            continue
        aimed = True
        chosen = chosen or ref
        if not entry.get("responses"):
            return ref, None
        gaps = binding_gaps(entry, brands, contexts[ref])
        if gaps is None:
            continue
        if chosen_gaps is None or len(gaps) < len(chosen_gaps):
            chosen, chosen_gaps = ref, gaps
        if not gaps:
            break
    if not aimed:
        return None, ["no issue in the case carries {} {}".format(entity.get("type"), entity.get("name"))]
    return chosen, chosen_gaps


def ledger_index(rows):
    """What already happened, keyed by (issue, action) from the wrapper's rows.

    Returns (done, no_instance). A shadow dispatch for a command no enabled
    instance serves is recorded no_instance with no time; it is final for this
    tenant, so the step is reported rather than sent again on every pass.
    """
    done, no_instance = set(), set()
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        action = r.get("universal_command") or r.get("action_taken")
        status = str(r.get("action_status") or "").lower()
        key = (str(r.get("incident_id") or ""), action)
        if action and status in DONE_STATUSES:
            done.add(key)
        elif action and status == "no_instance":
            no_instance.add(key)
    return done, no_instance


def step_seen(step, entity, members, keys):
    """True when any issue of the case carries a wrapper row for the action in keys, whoever ran it."""
    refs = list(step.get("evidence_refs") or []) + list(entity.get("evidence_refs") or []) + members
    return any((str(ref), step.get("action")) in keys for ref in refs)


def run_step(step, entity, phase, case_id, issue):
    """One step, inside the issue that evidences it. Returns the executor's decision."""
    plan_step = {"action": step.get("action"), "phase": phase,
                 "entity_type": ENTITY_TYPE.get(entity.get("type"), "artifact"),
                 "entity_value": entity.get("name") or "",
                 "rationale": step.get("why") or "",
                 "requires_human": str(step.get("requires_human")).lower() == "true"}
    blob = json.dumps([plan_step], separators=(",", ":")).replace("`", "'")
    try:
        res = api("/xsoar/public/v1/entry/execute/sync",
                  {"investigationId": str(issue),
                   "data": "!SOCFWPhaseExecutor phase={} case_id={} plan=`{}`".format(
                       phase, case_id, blob)})
    except Exception as e:
        return {"status": "error", "reason": str(e)[:120]}
    for entry in (res if isinstance(res, list) else [res]):
        if isinstance(entry, dict) and (entry.get("type") == 4 or entry.get("Type") == entryTypes["error"]):
            return {"status": "error", "reason": str(entry.get("contents") or entry.get("Contents"))[:120]}
    # The sync reply carries the rendered entry, not its context; the decision
    # is read back from the issue, where the executor writes it.
    try:
        after = get_context(issue)
    except Exception as e:
        return {"status": "error", "reason": "decision read failed: {}".format(str(e)[:80])}
    node = demisto.get(after, "SOCFramework.Phase.Plan")
    decisions = node if isinstance(node, list) else [node]
    for d in reversed(decisions):
        if isinstance(d, dict) and d.get("action") == step.get("action") and \
                (d.get("entity_value") or "") == (entity.get("name") or ""):
            # The executor's key merges by step number, so fields from an earlier
            # decision survive under this one: a reason under a dispatch, a
            # shadow flag under a gap. Keep only what belongs to this status.
            if d.get("status") == "dispatched":
                d.pop("reason", None)
                d.update(dispatch_outcome(after, step.get("action")))
            if d.get("status") != "dispatched":
                d.pop("shadow", None)
            return d
    return {"status": "error", "reason": "executor returned no decision"}


def dispatch_outcome(ctx, action):
    """What the wrapper did with a dispatch, from the record the executor keeps for it.

    The executor marks a step dispatched as soon as it hands it to the wrapper.
    The wrapper then routes by the issue's source vendor and may skip the action
    outright, and a skip writes no ledger row - so without reading its record the
    step would be dispatched again on every pass, for ever.
    """
    node = demisto.get(ctx, "SOCFramework.Phase.Dispatch")
    records = [r for r in (node if isinstance(node, list) else [node])
               if isinstance(r, dict) and r.get("action") == action]
    if not records:
        return {}
    last = max(records, key=lambda r: str(r.get("timestamp") or ""))
    if last.get("duplicate"):
        # Already taken on this target in this case, by another path or an
        # analyst: the step is done, and nothing ran twice.
        prior = last.get("duplicate_of") or {}
        return {"status": "done", "reason": "already {} by {}".format(
            "simulated" if prior.get("m") == "shadow" else "done", prior.get("by") or "another path")}
    if last.get("skipped"):
        return {"status": "skipped", "reason": str(last.get("skip_reason") or "skipped by the wrapper")[:120]}
    if last.get("success") is False and not last.get("shadow_mode"):
        return {"status": "failed", "reason": str(last.get("error") or last.get("message") or "command failed")[:120]}
    return {}


def run_phase(phase, contract, case_id, ledger, policy, actions, brands, members, contexts,
              prior_outstanding):
    """Every step of one phase. Returns (results, outstanding)."""
    cfg = (policy.get("phases") or {}).get(phase) or {}
    executes = cfg.get("enabled", False) and cfg.get("mode") == "execute"
    _, no_instance = ledger
    finished = (contract.get("finished") or {}).get(phase)
    finished = finished if isinstance(finished, dict) else {}
    scope = {r.get("id"): r for r in contract["scope"] if isinstance(r, dict)}
    results, outstanding = [], 0
    for step in sorted(contract[phase], key=lambda s: int(s.get("step") or 0)):
        action = step.get("action")
        entity = scope.get(step.get("target")) or {"type": "artifact", "name": step.get("target")}
        row = {"step": step.get("step"), "action": action, "target": entity.get("name"),
               "why": step.get("why") or ""}
        # Done is judged for this step's own target in the issue that carries it:
        # counting any row for the action anywhere in the case marked a host done
        # because a different host had been isolated. Who else acted on the same
        # target is the wrapper's ledger, which answers a repeat with duplicate.
        quiet = False
        if step_seen(step, entity, members, no_instance):
            row.update(status="integration_unavailable",
                       reason="simulated with no enabled instance for the command; no time credited")
        else:
            issue, gaps = pick_issue(step, entity, actions.get(action) or {}, brands, members, contexts)
            prior = finished.get((action, entity.get("name"), str(issue))) if issue else None
            if prior and prior.get("status") in RAN:
                row.update(status="done", issue=issue, vendor=prior.get("vendor"))
            elif not cfg.get("enabled", False):
                row.update(status="policy_blocked", reason="phase disabled in policy")
            elif executes and prior_outstanding:
                row.update(status="waiting", reason="earlier phase has steps awaiting approval")
                outstanding += 1
            elif not issue:
                row.update(status="contract_gap", reason=(gaps or ["step names no evidence issue"])[0])
                outstanding += 1
            elif prior and prior.get("status") in REPORTED:
                # Reported as last time; its row is already in the dataset.
                row.update(status=prior["status"], reason=prior.get("reason"), issue=issue,
                           vendor=prior.get("vendor"))
                quiet = True
            else:
                decision = run_step(step, entity, phase, case_id, issue)
                row.update(status=decision.get("status"), reason=decision.get("reason"),
                           vendor=decision.get("vendor"), issue=issue,
                           shadow=bool(decision.get("shadow")))
                if decision.get("status") == "dispatched":
                    finished[(action, entity.get("name"), str(issue))] = {"status": "dispatched",
                                                                        "vendor": decision.get("vendor")}
                elif decision.get("status") == "awaiting_approval":
                    # Only a step waiting on a person holds the next phase. A
                    # gap is final for this pass and is reported, not waited on.
                    outstanding += 1
        if row["status"] not in RAN and not quiet:
            post_row({"timestamp": utc_now(), "event_type": "phase_step",
                      "incident_id": case_id, "case_id": case_id, "phase": phase,
                      "action_taken": action, "action_status": row["status"],
                      "action_actor": "automation", "execution_mode": "plan",
                      "entity_value": entity.get("name"), "error_message": row.get("reason")})
        results.append(row)
    return results, outstanding


MARK = {"done": "\u2705", "dispatched": "\u2705", "awaiting_approval": "\u23f8\ufe0f",
        "direction": "\U0001f4cb", "waiting": "\u23f3", "environment_denied": "\u26d4",
        "policy_blocked": "\u26d4", "integration_unavailable": "\U0001f50c",
        "contract_gap": "\u26a0\ufe0f", "content_gap": "\u26a0\ufe0f", "skipped": "\u26a0\ufe0f",
        "failed": "\u274c", "duplicate": "\u21bb"}


def phase_state(results, outstanding):
    if not results:
        return "nothing_to_do"
    if outstanding:
        return "in_progress"
    blocked = [r for r in results if r["status"] in GAPS]
    return "complete_with_gaps" if blocked else "complete"


def phase_story(results):
    def note(r):
        if r.get("shadow") and r.get("status") in RAN:
            return " (simulated - shadow mode)"
        return " ({})".format(r["reason"]) if r.get("reason") else ""
    return ["{} {}. {} -> {}{}".format(MARK.get(r["status"], "\u2022"), r.get("step"),
                                       r.get("action"), r.get("target"), note(r))
            for r in results]


def artifact_report(contract, eradication, telemetry):
    """What eradication acted on, what to watch after recovery, and what the case could see.

    Eradicated: every artifact an eradication step ran on (simulated in shadow).
    Monitor: every artifact eradication could not act on, with the reason first,
    then everything else the analysis put in scope - so nothing in scope is
    silently dropped. Eradication and monitoring are only as good as the
    telemetry, so the report names the sources the case's issues came from.
    """
    by_name = {}
    for e in contract.get("scope") or []:
        if isinstance(e, dict) and e.get("name"):
            by_name.setdefault(e["name"], e)
    eradicated, monitor, seen = [], [], set()
    for r in eradication:
        entity = by_name.get(r.get("target")) or {}
        kind = entity.get("type") or "artifact"
        if r["status"] in RAN:
            eradicated.append({"type": kind, "value": r.get("target"), "action": r.get("action"),
                               "status": "simulated" if r.get("shadow") else
                               ("recorded" if r["status"] == "done" else "executed")})
        elif r.get("target") and (kind, r["target"]) not in seen:
            seen.add((kind, r["target"]))
            monitor.append({"type": kind, "value": r["target"],
                            "why": "not eradicated: {}".format(r.get("reason") or r["status"])})
    for e in contract.get("scope") or []:
        if not isinstance(e, dict) or not e.get("name"):
            continue
        key = (e.get("type") or "artifact", e["name"])
        if key not in seen:
            seen.add(key)
            monitor.append({"type": key[0], "value": key[1],
                            "why": "in scope ({})".format(e.get("role") or "unspecified")})
    return eradicated, monitor, telemetry


def case_telemetry(members, contexts, limit=15):
    """The sources the case's issues came from, as one line: 'Endpoint: CrowdStrike Falcon (EDR)'.

    Read from each issue's SOCFramework.Product, which the normalize step writes.
    Bounded so a large case does not turn this into hundreds of reads.
    """
    sources = []
    for issue in members[:limit]:
        if issue not in contexts:
            try:
                contexts[issue] = get_context(issue)
            except Exception:
                contexts[issue] = {}
        product = demisto.get(contexts[issue], "SOCFramework.Product") or {}
        if isinstance(product, list):
            product = product[-1] if product else {}
        if not isinstance(product, dict) or not product.get("category"):
            continue
        line = "{}: {}{}".format(product.get("category"), product.get("response") or product.get("_prod") or "unknown",
                                 " ({})".format(product["type"]) if product.get("type") else "")
        if line not in sources:
            sources.append(line)
    return "; ".join(sources) or "unknown - no issue in the case names its source"


def flat(rows, keys):
    """A report list as one string for the dataset: 'file:abc (simulated); host:ws-01 (in scope)'."""
    return "; ".join("{}:{} ({})".format(r.get("type"), r.get("value"), ", ".join(
        str(r.get(k)) for k in keys if r.get(k))) for r in rows)


def phase_targets(phase, results, state, contract, declared, report=None):
    """The values of the phase's declared targets, from the step results.

    Everything here is derived, never decided: the arrays hold the targets of
    steps that ran, the booleans say whether the plan asked for the phase and
    how far it got, and Recovery's monitoring comes from what the analysis said
    a person must verify. A target the contract declares but nothing here
    produces keeps its declared init, so the shape is always complete.
    """
    ran = [r for r in results if r["status"] in RAN]
    actions_ran = []
    for r in ran:
        if r.get("action") and r["action"] not in actions_ran:
            actions_ran.append(r["action"])
    derived = {"status": state, "story": phase_story(results),
               "Execution": {"steps": len(results), "ran": len(ran),
                             "outstanding": sum(1 for r in results if r["status"] in ("awaiting_approval", "waiting")),
                             "gaps": sum(1 for r in results if r["status"] in GAPS),
                             "by_step": [{k: r.get(k) for k in ("step", "action", "target", "status", "issue", "vendor",
                                                                "shadow", "reason")}
                                         for r in results],
                             "updated_at": utc_now()}}
    for r in ran:
        key = TARGET_OF.get(r.get("action"))
        if key and r.get("target"):
            derived.setdefault(key, [])
            if r["target"] not in derived[key]:
                derived[key].append(r["target"])
    if phase == "containment":
        derived.update(required=bool(results), action=", ".join(actions_ran))
    elif phase == "eradication":
        derived.update(attempted=bool(ran), success=(state == "complete"),
                       artifacts=(report or ([], [], ""))[0])
    elif phase == "recovery":
        eradicated, monitor, telemetry = report or ([], [], "")
        verify = contract.get("verify_by_human") or []
        derived.update(restore_required=bool(results), restore_method=", ".join(
            a for a in dict.fromkeys(r.get("action") for r in results) if a),
            monitor=monitor, telemetry=telemetry,
            monitoring_required=bool(monitor or verify),
            monitoring_scope="; ".join("{} {}".format(m["type"], m["value"]) for m in monitor))
    out = {}
    for w in declared:
        target = w.get("target") or ""
        leaf = target.split(".", 1)[1] if "." in target else target
        out[leaf] = derived.get(leaf, w.get("init"))
    return out or derived


def clear_phase(case_id, phase):
    """Remove the phase subtree from the case so the write that follows replaces it.

    setParentIncidentContext appends on every repeat write and ignores
    append=false, so without this the status reads as a list after the second
    pass. DeleteContext runs inside the case investigation, where !Set panics.
    """
    api("/xsoar/public/v1/entry/execute/sync",
        {"investigationId": "INCIDENT-{}".format(case_id),
         "data": "!DeleteContext key=SOCFramework.{}".format(phase.title())})


def write_phase(case_id, issue, phase, values):
    """Record the phase on the case, under SOCFramework.<Phase>, in one call."""
    blob = json.dumps(values, separators=(",", ":")).replace("`", "'")
    try:
        clear_phase(case_id, phase)
    except Exception as e:
        # Writing over an uncleared subtree appends, so leave the old record intact.
        demisto.debug("SOCFWCaseResponse: phase clear failed, write skipped ({})".format(e))
        return False
    try:
        api("/xsoar/public/v1/entry/execute/sync",
            {"investigationId": str(issue),
             "data": "!SOCFWCaseContractWrite root=SOCFramework.{} contract=`{}`".format(
                 phase.title(), blob)})
    except Exception as e:
        demisto.debug("SOCFWCaseResponse: phase write failed ({})".format(e))
        return False
    return True


def post_to_case(case_id, markdown):
    try:
        api("/xsoar/public/v1/entry", {"investigationId": "INCIDENT-{}".format(case_id),
                                       "data": markdown, "markdown": True})
    except Exception as e:
        demisto.debug("SOCFWCaseResponse: War Room post failed ({})".format(e))


def respond(case_id, ledger_rows, policy, actions, declared, brands):
    contract, err = read_contract(case_id)
    if err:
        return {"case_id": case_id, "note": err, "phases": {}}
    if str(contract.get("response_recommended")).lower() != "true":
        return {"case_id": case_id, "note": "analysis did not recommend a response", "phases": {}}
    ledger = ledger_index(ledger_rows)
    members = member_issues(case_id)
    contexts = {}
    # The phase record goes up through any member issue; the first evidenced one will do.
    refs = [str(s["evidence_refs"][0]) for p in PHASES for s in contract[p] if s.get("evidence_refs")]
    write_from = (refs or members or [None])[0]
    summary, lines, outstanding, changed = {}, ["## Response - case {}".format(case_id), ""], 0, False
    telemetry = case_telemetry(members, contexts)
    report = ([], [], telemetry)
    for phase in PHASES:
        results, outstanding = run_phase(phase, contract, case_id, ledger, policy, actions, brands,
                                         members, contexts, outstanding)
        if phase == "eradication":
            report = artifact_report(contract, results, telemetry)
        state = phase_state(results, outstanding)
        summary[phase] = {"state": state, "steps": len(results), "outstanding": outstanding}
        lines.append("**{}** - {}".format(phase.upper(), state.replace("_", " ")))
        story = phase_story(results)
        lines.extend("  " + x for x in story)
        lines.append("")
        # Only a change reaches the case. The same plan read every few minutes
        # must not write the same story and post the same entry every time.
        recorded_steps = (contract.get("recorded_steps") or {}).get(phase)
        if write_from and results and (story != contract["recorded"].get(phase)
                                       or step_signature(results) != recorded_steps):
            values = phase_targets(phase, results, state, contract, declared.get(phase) or [], report)
            if write_phase(case_id, write_from, phase, values):
                changed = True
    if not changed:
        return {"case_id": case_id, "phases": summary, "note": "unchanged"}
    eradicated, monitor, _ = report
    lines += ["### Eradicated", ""]
    lines += ["- {} `{}` - {} ({})".format(a["type"], a["value"], a["action"], a["status"]) for a in eradicated] \
        or ["- nothing yet"]
    lines += ["", "### Monitor for", ""]
    lines += ["- {} `{}` - {}".format(m["type"], m["value"], m["why"]) for m in monitor] or ["- nothing in scope"]
    verify = contract.get("verify_by_human") or []
    if verify:
        lines += ["", "### Verify by a person", ""] + ["- {}".format(v) for v in verify]
    lines += ["", "_Eradication and monitoring cover only what this case's telemetry shows: {}._".format(telemetry)]
    post_to_case(case_id, "\n".join(lines))
    post_row({"timestamp": utc_now(), "event_type": "case_response", "incident_id": case_id,
              "case_id": case_id, "action_actor": "automation", "execution_mode": "plan",
              "containment_state": summary["containment"]["state"],
              "eradication_state": summary["eradication"]["state"],
              "recovery_state": summary["recovery"]["state"],
              "eradicated_count": len(eradicated), "monitor_count": len(monitor),
              "eradicated_artifacts": flat(eradicated, ("action", "status")),
              "monitor_artifacts": flat(monitor, ("why",)),
              "telemetry": telemetry})
    return {"case_id": case_id, "phases": summary}


def query_results(ctx, query_name):
    """The rows of the XQL task that ran with this query_name, found by walking context.

    The XQL command writes every result set under the same root, so the name set
    on the task is the only thing that tells the candidate rows from the ledger rows.
    """
    rows = []
    stack = [ctx]
    seen = 0
    while stack and seen < 10000:
        node = stack.pop()
        seen += 1
        if isinstance(node, dict):
            name = node.get("query_name") or node.get("QueryName")
            results = node.get("results") or node.get("Results")
            if name == query_name and isinstance(results, list):
                rows.extend(results)
                continue
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return rows


def main():
    args = demisto.args()
    ctx = demisto.context() or {}
    cases = as_obj(args.get("cases")) or query_results(ctx, args.get("cases_query") or "socfw_response_candidates")
    ledger = as_obj(args.get("ledger")) or query_results(ctx, args.get("ledger_query") or "socfw_response_ledger")
    if isinstance(cases, dict):
        cases = [cases]
    case_ids = []
    for c in cases:
        cid = c.get("case_id") if isinstance(c, dict) else c
        if cid and str(cid) not in case_ids:
            case_ids.append(str(cid))
    # Each step is a round trip into an issue, so a run is bounded by cases,
    # not left to the script timeout. The rest wait for the next pass.
    limit = int(args.get("max_cases") or 3)
    policy = get_list(POLICY_LIST)
    actions = {k: v for k, v in (get_list(ACTIONS_LIST) or {}).items() if isinstance(v, dict)}
    declared = (get_list(CONTRACT_LIST) or {}).get("writes_by_phase") or {}
    brands = active_brands()
    still_open = open_cases(case_ids)
    results = [respond(cid, ledger, policy, actions, declared, brands) for cid in still_open[:limit]]
    lines = ["## Case response - {} case(s)".format(len(results)), ""]
    for r in results:
        if r.get("phases"):
            lines.append("- case {}: {}".format(r["case_id"], ", ".join(
                "{} {}".format(p, v["state"]) for p, v in r["phases"].items())))
        else:
            lines.append("- case {}: {}".format(r["case_id"], r.get("note")))
    return_results(CommandResults(outputs_prefix="SOCFramework.Response.Results",
                                  outputs=results, readable_output="\n".join(lines)))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
