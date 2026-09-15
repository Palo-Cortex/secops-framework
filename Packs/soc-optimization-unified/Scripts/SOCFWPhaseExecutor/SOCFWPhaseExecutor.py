"""Plans are proposals. This decides what actually dispatches.

The model (or the deterministic fallback) says what to do and in what order.
Everything that cannot be reasoned about - what the customer forbids, what the
tenant can reach, what already ran - is settled here, against lists, before any
vendor command is called.
"""
import json
import re
import traceback
from datetime import datetime, timezone

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

ACTIONS_LIST = "SOCFrameworkActions_V3"
ENV_LIST = "SOCFrameworkEnvironment_V3"
POLICY_LIST = "SOCFrameworkPhasePolicy_V3"

# Strictness order. Two sources may both have an opinion about a step; the
# stricter one wins, so a permissive phase policy can never loosen an
# environment tier.
AUTHORITY_RANK = {"auto": 0, "approve": 1, "recommend_only": 2}

TEMPLATE = re.compile(r"\$\{([^}]+)\}")


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_list(name):
    try:
        res = demisto.executeCommand("getList", {"listName": name})
        raw = res[0]["Contents"] if res else None
        if isinstance(raw, str):
            return json.loads(raw)
        return raw or {}
    except Exception as e:
        demisto.debug("SOCFWPhaseExecutor: cannot read {} ({})".format(name, e))
        return {}


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


def unresolved_args(action_entry, vendor, ctx):
    """Which ${...} arguments this binding needs and context does not have.

    An empty argument is not a vendor failure - the command would be dispatched
    well-formed against nothing. Catching it here keeps a contract problem from
    being reported as an integration problem.
    """
    binding = (action_entry.get("responses") or {}).get(vendor) or {}
    missing = []
    for raw in TEMPLATE.findall(json.dumps(binding.get("inline_args") or {})):
        path = raw[len("SOCFramework."):] if raw.startswith("SOCFramework.") else raw
        value = resolve_path(ctx.get("SOCFramework") or {}, path) if raw.startswith(
            "SOCFramework.") else resolve_path(ctx, raw)
        if value in (None, "", [], {}):
            missing.append(raw)
    return missing


def active_brands():
    """Brands with at least one active instance, from the in-process registry.

    Mirrors SOCCommandWrapper.brand_available and fails open the same way: an
    unreadable registry must never be the reason a step is skipped.
    """
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


def pick_vendor(action_entry, brands, ctx=None):
    """Prefer a reachable vendor whose arguments the contract can actually fill.

    Picking on brand alone reports a contract gap for an action that would have
    worked through a different binding - disable-user failed on the AD binding's
    Email while the Graph binding only needed the UPN that was sitting right
    there. Reachable-but-unsatisfiable is the fallback, not the first choice, so
    the gap is still reported when no binding can run.
    """
    responses = action_entry.get("responses") or {}
    if not responses:
        return None, False
    reachable = [v for v in responses if brands is None or v in brands]
    if ctx is not None:
        for vendor in reachable:
            if not unresolved_args(action_entry, vendor, ctx):
                return vendor, True
    if reachable:
        return reachable[0], True
    return list(responses)[0], False


def env_ruling(env, entity_type, entity_value, action_name):
    """First matching entry wins, so ordering in the list is customer intent."""
    for entry in env.get("entries") or []:
        if entry.get("entity_type") != entity_type:
            continue
        try:
            if not re.search(entry.get("match") or "", entity_value or ""):
                continue
        except re.error:
            continue
        tier = entry.get("tier")
        if action_name in (entry.get("deny_actions") or []):
            return "denied", tier, entry.get("name"), entry.get("note")
        if action_name in (entry.get("require_approval_actions") or []):
            return "approve", tier, entry.get("name"), entry.get("note")
        tier_auth = ((env.get("tiers") or {}).get(tier) or {}).get("authority")
        return tier_auth, tier, entry.get("name"), entry.get("note")
    return None, (env.get("defaults") or {}).get("unmatched_tier"), None, None


def stricter(a, b):
    candidates = [x for x in (a, b) if x in AUTHORITY_RANK]
    if not candidates:
        return "recommend_only"
    return max(candidates, key=lambda x: AUTHORITY_RANK[x])


def order_steps(steps, actions):
    """Keep the plan's order; fall back to sequence_rank only where it is absent.

    A reasoned order encodes case-specific dependencies a static rank cannot -
    kill the process before quarantining the file it holds open. Re-sorting the
    plan by rank would discard exactly that.
    """
    if all(s.get("order") is not None for s in steps) and steps:
        return sorted(steps, key=lambda s: s["order"])
    return sorted(
        steps,
        key=lambda s: (actions.get(s.get("action")) or {}).get("sequence_rank", 999))


def evidence_first(ordered, actions):
    """Flag a destructive step with no collection step ahead of it.

    NIST SP 800-61 3.3.2 wants volatile evidence captured before it is
    destroyed. The executor reports the conflict rather than reordering, because
    inserting a collection step the plan never asked for is its own surprise.
    """
    seen_capture = False
    for step in ordered:
        entry = actions.get(step.get("action")) or {}
        if entry.get("phase") == "investigation":
            seen_capture = True
        elif entry.get("destroys_evidence") and not seen_capture:
            step["evidence_warning"] = (
                "destroys volatile evidence with no collection step ahead of it")
    return ordered


def post_row(payload):
    try:
        demisto.executeCommand(
            "socfw-post-to-dataset",
            {"using": "socfw_ir_execution_writer", "JSON": json.dumps(payload)})
    except Exception as e:
        demisto.debug("SOCFWPhaseExecutor: dataset post failed ({})".format(e))


def decide(step, actions, env, policy, brands, ctx, ledger):
    """One step, one verdict. Order of checks is the order of authority.

    Ledger first (already done is a fact), then environment deny (customer
    prohibition), then contract, then reachability, then authority. Anything
    that is not 'dispatch' still produces a row, because a step that did not run
    is the finding.
    """
    name = step.get("action")
    entry = actions.get(name) or {}
    scope = entry.get("entity_scope") or "artifact"
    entity = step.get("entity_value") or ""
    etype = step.get("entity_type") or scope
    out = {
        "action": name,
        "capability": entry.get("capability") or name,
        "entity_type": etype,
        "entity_value": entity,
        "rationale": step.get("rationale") or "",
        "evidence_warning": step.get("evidence_warning"),
    }

    if not entry:
        out.update(status="content_gap", gap_kind="content_gap",
                   reason="no registry entry for this action")
        return out

    if (name, entity) in ledger:
        out.update(status="duplicate", reason="already performed on this entity for this case")
        return out

    ruling, tier, rule, note = env_ruling(env, etype, entity, name)
    out["asset_tier"] = tier
    if ruling == "denied":
        out.update(status="environment_denied", gap_kind="policy",
                   reason=note or "denied by {}".format(rule), matched_rule=rule)
        return out

    phase_cfg = (policy.get("phases") or {}).get(step.get("phase")) or {}
    if not phase_cfg.get("enabled", False):
        out.update(status="policy_blocked", reason="phase disabled in policy")
        return out

    vendor, reachable = pick_vendor(entry, brands, ctx)
    out["vendor"] = vendor
    if vendor is None:
        out.update(status="content_gap", gap_kind="content_gap",
                   reason="action has no vendor bindings")
        return out

    # Reachability first. With no enabled vendor there is no binding whose
    # arguments are meaningful, and checking them anyway reported a contract gap
    # for an action that simply has nowhere to run.
    if not reachable:
        out.update(status="integration_unavailable", gap_kind="config_gap",
                   reason="no enabled integration for this capability",
                   required_brands=sorted(entry.get("responses") or {}))
        return out

    missing = unresolved_args(entry, vendor, ctx)
    if missing:
        out.update(status="contract_gap", gap_kind="contract_gap",
                   reason="unresolved arguments: {}".format(", ".join(missing)),
                   required_keys=missing)
        return out

    authority = stricter(
        (phase_cfg.get("authority_by_scope") or {}).get(scope),
        ruling if ruling in AUTHORITY_RANK else None)
    out["authority"] = authority

    if phase_cfg.get("mode") != "execute":
        out.update(status="direction", reason="phase runs in {} mode".format(
            phase_cfg.get("mode")))
        return out
    if authority == "recommend_only":
        out.update(status="direction", reason="policy permits recommendation only")
        return out
    if authority == "approve":
        out.update(status="awaiting_approval", reason="analyst approval required")
        return out

    out.update(status="dispatch")
    return out


def load_plan(args, ctx):
    """Read the plan from context by default rather than take it as an argument.

    A ${...} argument that resolves to an array makes XSIAM run the task once
    per element, so the executor would run once per step with a single step each
    time. Reading the whole array in-process is the only way the plan arrives
    intact.
    """
    raw = args.get("plan")
    if raw:
        if isinstance(raw, (list, dict)):
            return raw if isinstance(raw, list) else [raw]
        try:
            return json.loads(raw)
        except Exception:
            return_error("SOCFWPhaseExecutor: plan argument is not valid JSON")
            return []
    key = args.get("plan_key") or "SOCFramework.Phase.Proposed"
    node = ctx
    for part in key.split("."):
        node = node.get(part) if isinstance(node, dict) else None
        if node is None:
            return []
    return node if isinstance(node, list) else [node]


def main():
    args = demisto.args()
    phase = args.get("phase") or "containment"
    case_id = args.get("case_id") or ""
    ctx = demisto.context() or {}
    plan = load_plan(args, ctx)

    actions = {k: v for k, v in (get_list(ACTIONS_LIST) or {}).items()
               if isinstance(v, dict)}
    env = get_list(ENV_LIST) or {}
    policy = get_list(POLICY_LIST) or {}
    brands = active_brands()

    for step in plan:
        step.setdefault("phase", phase)
    ordered = evidence_first(order_steps(plan, actions), actions)

    ledger = set()
    results = []
    run_id = "{}-{}".format(case_id or "nocase", utc_now())

    for idx, step in enumerate(ordered, 1):
        verdict = decide(step, actions, env, policy, brands, ctx, ledger)
        verdict["step"] = idx
        if verdict["status"] == "dispatch":
            entry = actions.get(verdict["action"]) or {}
            demisto.executeCommand("SOCCommandWrapper", {
                "action": verdict["action"],
                "shadow_mode": str(entry.get("shadow_mode", True)).lower(),
                "Phase": phase,
                "Action_Actor": "automation",
                "output_key": "SOCFramework.Phase.Dispatch",
            })
            # The wrapper writes its own execution row and knows whether the
            # vendor call really happened; do not duplicate its verdict here.
            verdict["status"] = "dispatched"
            ledger.add((verdict["action"], verdict["entity_value"]))
        else:
            post_row({
                "timestamp": utc_now(), "event_type": "phase_step",
                "run_id": run_id, "incident_id": case_id, "case_id": case_id,
                "phase": phase, "action_taken": verdict["action"],
                "action_status": verdict["status"],
                "action_actor": "framework", "execution_mode": "plan",
                "entity_type": verdict.get("entity_type"),
                "entity_value": verdict.get("entity_value"),
                "capability": verdict.get("capability"),
                "gap_kind": verdict.get("gap_kind"),
                "required_brands": ",".join(verdict.get("required_brands") or []),
                "error_message": verdict.get("reason"),
            })
        results.append(verdict)
    return results, phase, case_id


def render(results, phase, case_id):
    """One scannable entry. War Room truncates past roughly thirty lines, so
    lead with the counts and keep one line per step."""
    marker = {
        "dispatched": "\u2705", "shadow": "\U0001f7e1", "direction": "\U0001f4cb",
        "awaiting_approval": "\u23f8\ufe0f", "integration_unavailable": "\U0001f50c",
        "contract_gap": "\u26a0\ufe0f", "content_gap": "\u26a0\ufe0f",
        "environment_denied": "\u26d4", "policy_blocked": "\u26d4",
        "duplicate": "\u21bb",
    }
    tally = {}
    for r in results:
        tally[r["status"]] = tally.get(r["status"], 0) + 1
    lines = ["## {} plan - case {}".format(phase.title(), case_id or "n/a"),
             "", " | ".join("{} {}".format(v, k) for k, v in sorted(tally.items())), ""]
    for r in results:
        lines.append("{} **{}** - {} `{}`".format(
            marker.get(r["status"], "\u2022"), r["step"], r["capability"], r["entity_value"]))
        if r.get("rationale"):
            lines.append("   {}".format(r["rationale"]))
        if r.get("reason"):
            lines.append("   _{}_".format(r["reason"]))
        if r.get("evidence_warning"):
            lines.append("   \u26a0\ufe0f {}".format(r["evidence_warning"]))
    return "\n".join(lines)


if __name__ in ("__builtin__", "builtins", "__main__"):
    try:
        _results, _phase, _case = main()
        return_results(CommandResults(
            outputs_prefix="SOCFramework.Phase.Plan",
            outputs_key_field="step",
            outputs=_results,
            readable_output=render(_results, _phase, _case)))
    except Exception as _e:
        demisto.error(traceback.format_exc())
        return_error("SOCFWPhaseExecutor failed: {}".format(_e))
