"""Drive containment across every candidate case in one invocation.

Deliberately not a forEach over a sub-playbook. XSIAM runs a task once per
element when an argument resolves to an array, and the accumulating-input bug
that produced 118 verdict entries for 16 cases came from exactly that shape.
Looping in-process means the array never reaches a task argument.

Per case: build a plan from the case payload, hand it to the executor, record
what happened. The planner and executor are unchanged - this only sequences them
and keeps the ledger per case.
"""
import json
import traceback
from datetime import datetime, timezone

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def as_list(raw):
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            return []
    if isinstance(raw, dict):
        return [raw]
    return raw or []


def run(command, args):
    try:
        res = demisto.executeCommand(command, args)
    except Exception as e:
        return None, str(e)
    if not res:
        return None, "no result from {}".format(command)
    entry = res[0] if isinstance(res, list) else res
    if isinstance(entry, dict) and entry.get("Type") == entryTypes["error"]:
        return None, str(entry.get("Contents"))[:300]
    return res, None


def plan_for(case, phase):
    """Ask the planner for one phase of one case."""
    payload = case.get("Payload")
    if isinstance(payload, (dict, list)):
        payload = json.dumps(payload)
    res, err = run("SOCFWBuildPhasePlan", {
        "phase": phase,
        "case_payload": payload or "{}",
        "include_gaps": "true",
    })
    if err:
        return [], err
    for entry in (res if isinstance(res, list) else [res]):
        ec = (entry or {}).get("EntryContext") or {}
        for key, val in ec.items():
            if key.startswith("SOCFramework.Phase.Proposed"):
                return as_list(val), None
    return [], "planner returned no steps"


def execute(steps, phase, case_id):
    """Hand the plan to the executor. It decides; this only reports."""
    if not steps:
        return [], None
    res, err = run("SOCFWPhaseExecutor", {
        "phase": phase,
        "case_id": str(case_id),
        "plan": json.dumps(steps),
    })
    if err:
        return [], err
    for entry in (res if isinstance(res, list) else [res]):
        ec = (entry or {}).get("EntryContext") or {}
        for key, val in ec.items():
            if key.startswith("SOCFramework.Phase.Plan"):
                return as_list(val), None
    return [], "executor returned no decisions"


def post_row(payload):
    try:
        demisto.executeCommand("socfw-post-to-dataset", {
            "using": "socfw_ir_execution_writer", "JSON": json.dumps(payload)})
    except Exception as e:
        demisto.debug("SOCFWCaseContainment: dataset post failed ({})".format(e))


def summarise(decisions):
    tally = {}
    for d in decisions:
        tally[d.get("status")] = tally.get(d.get("status"), 0) + 1
    return tally


def containment_state(decisions):
    """Contained only when nothing that needed doing was left undone.

    A capability gap or a policy refusal leaves part of the intrusion live, and a
    case that reads 'contained' on partial coverage is how an environment gets
    handed back to an attacker at recovery.
    """
    if not decisions:
        return "nothing_to_contain"
    done = sum(1 for d in decisions if d.get("status") == "dispatched")
    blocked = sum(1 for d in decisions if d.get("status") in (
        "integration_unavailable", "contract_gap", "content_gap",
        "environment_denied", "policy_blocked"))
    pending = sum(1 for d in decisions if d.get("status") in (
        "awaiting_approval", "direction"))
    if done and not blocked and not pending:
        return "contained"
    if done or pending:
        return "partially_contained"
    return "uncontained"


def main():
    args = demisto.args()
    cases = as_list(args.get("cases"))
    run_id = "contain-{}".format(utc_now())
    results, lines = [], []

    for case in cases:
        if not isinstance(case, dict):
            continue
        case_id = case.get("ID") or case.get("case_id") or ""

        steps, err = plan_for(case, "containment")
        decisions, exec_err = execute(steps, "containment", case_id)
        state = containment_state(decisions)
        tally = summarise(decisions)

        # Eradication and recovery are directions_only for now, so the executor
        # returns them as steps for an analyst rather than dispatching. Producing
        # them here means MTTE and MTTR are measured from the first run, even
        # though nothing automates those phases yet.
        erad, _ = plan_for(case, "eradication")
        recov, _ = plan_for(case, "recovery")

        post_row({
            "timestamp": utc_now(), "event_type": "case_containment",
            "run_id": run_id, "case_id": str(case_id), "incident_id": str(case_id),
            "phase": "containment", "action_actor": "automation",
            "containment_state": state,
            "steps_planned": len(steps),
            "steps_dispatched": tally.get("dispatched", 0),
            "steps_awaiting_approval": tally.get("awaiting_approval", 0),
            "steps_unavailable": tally.get("integration_unavailable", 0),
            "steps_contract_gap": tally.get("contract_gap", 0),
            "steps_denied": tally.get("environment_denied", 0),
            "eradication_directions": len(erad),
            "recovery_directions": len(recov),
            "error_message": err or exec_err or "",
        })

        results.append({"case_id": case_id, "containment_state": state,
                        "planned": len(steps), "decisions": decisions,
                        "eradication_directions": erad,
                        "recovery_directions": recov,
                        "error": err or exec_err or ""})
        lines.append("**Case {}** - {} | {} planned, {} eradication, {} recovery "
                     "| {}".format(case_id, state, len(steps), len(erad), len(recov),
                                   ", ".join("{} {}".format(v, k)
                                             for k, v in sorted(tally.items())) or "no decisions"))

    header = "## Containment - {} case(s)".format(len(results))
    return_results(CommandResults(
        outputs_prefix="SOCFramework.Containment.Cases",
        outputs_key_field="case_id",
        outputs=results,
        readable_output="\n\n".join([header] + lines) if lines else
        header + "\n\n_No candidate cases._"))


if __name__ in ("__builtin__", "builtins", "__main__"):
    try:
        main()
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error("SOCFWCaseContainment failed: {}".format(e))
