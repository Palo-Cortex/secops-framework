"""The deterministic producer of a phase plan.

Reads the normalized contract, asks the action registry which actions belong to
the phase, and emits one step per action whose arguments the contract can
actually supply. Ordering comes from sequence_rank.

This exists so the phase pipeline has a producer that does not depend on a
model. The AI planner emits the same step shape and replaces the ordering with
a reasoned one; everything downstream is identical either way.
"""
import json
import re
import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

ACTIONS_LIST = "SOCFrameworkActions_V3"
TEMPLATE = re.compile(r"\$\{([^}]+)\}")


def get_list(name):
    try:
        res = demisto.executeCommand("getList", {"listName": name})
        raw = res[0]["Contents"] if res else None
        return json.loads(raw) if isinstance(raw, str) else (raw or {})
    except Exception as e:
        demisto.debug("SOCFWBuildPhasePlan: cannot read {} ({})".format(name, e))
        return {}


def resolve_path(root, path):
    node = root
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


def resolved_args(binding, ctx):
    """Every ${...} in a binding, paired with whatever the contract has for it."""
    out = []
    for raw in TEMPLATE.findall(json.dumps(binding.get("inline_args") or {})):
        value = resolve_path(ctx, raw)
        out.append((raw, value))
    return out


# Most specific identifier first. The ledger dedups on (action, entity), so an
# action that acts on a process must key on the process - keying on its host
# would make a second malicious process look like work already done.
ENTITY_PREFERENCE = [
    "Process.PID", "Process.Name",
    "Email.MessageID", "Email.From", "Email.Subject",
    "Hash", "FilePath", "File",
    "Network.Destination.IP", "Network.Destination.Hostname",
    "Identity.User.UPN", "Identity.User.Name", "Identity.User.ID",
    "Email.To", "Endpoint.Hostname", "EndPointID", "Endpoint.AgentID",
]


def scalar(value):
    if isinstance(value, (str, int)) and str(value).strip():
        return str(value)
    if isinstance(value, list) and value:
        return str(value[0])
    return ""


def first_value(pairs):
    """The entity a step is about - the most specific argument that resolved."""
    resolved = {path: scalar(value) for path, value in pairs if scalar(value)}
    for suffix in ENTITY_PREFERENCE:
        for path, value in resolved.items():
            if path.endswith(suffix):
                return value
    return next(iter(resolved.values()), "")


def describe(action_entry, entity):
    cap = action_entry.get("capability") or ""
    return "{} on {}".format(cap, entity) if entity else cap


def build(phase, actions, ctx, include_gaps):
    """One step per action in the phase that the contract can act on.

    An action whose arguments resolve to nothing is dropped by default - the
    contract has no entity for it, so proposing it would be noise. Setting
    include_gaps keeps it, which turns the plan into a capability-coverage
    report: every action the phase could run, and what the contract is missing.
    """
    steps = []
    for name, entry in actions.items():
        if not isinstance(entry, dict) or entry.get("phase") != phase:
            continue
        responses = entry.get("responses") or {}
        if not responses:
            continue
        # Union across vendors. The executor picks its vendor by what the tenant
        # can reach, which need not be the first one here, and the entity a step
        # is about must not depend on that choice.
        pairs = []
        for binding in responses.values():
            pairs.extend(resolved_args(binding, ctx))
        entity = first_value(pairs)
        if not entity and not include_gaps:
            continue
        steps.append({
            "action": name,
            "entity_type": entry.get("entity_scope") or "artifact",
            "entity_value": entity,
            "order": entry.get("sequence_rank", 999),
            "rationale": describe(entry, entity),
            "planner": "deterministic",
        })
    steps.sort(key=lambda s: (s["order"], s["action"]))
    return steps


def load_payload(args, ctx):
    """The case payload, from an argument or from where the analysis path left it."""
    raw = args.get("case_payload")
    if not raw:
        key = args.get("payload_key") or "SOCFWCase.Payload"
        node = ctx
        for part in key.split("."):
            node = node.get(part) if isinstance(node, dict) else None
            if node is None:
                return None
        raw = node
    if isinstance(raw, list):
        raw = raw[-1] if raw else None
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            return None
    return raw if isinstance(raw, dict) else None


def main():
    args = demisto.args()
    phase = args.get("phase") or "containment"
    include_gaps = str(args.get("include_gaps", "false")).lower() == "true"
    actions = get_list(ACTIONS_LIST) or {}
    ctx = demisto.context() or {}

    payload = load_payload(args, ctx)
    if payload:
        steps = build_case(phase, actions, payload, include_gaps)
        scope_note = "case - {} host(s), {} of {} shapes, {}% contract coverage".format(
            len(payload.get("hosts") or []), payload.get("shapes_analysed", "?"),
            payload.get("shapes_in_case", "?"),
            payload.get("shape_contract_coverage_pct", "?"))
    else:
        steps = build(phase, actions, ctx, include_gaps)
        scope_note = "issue"

    lines = ["## {} plan - {} step(s)".format(phase.title(), len(steps)),
             "", "_scope: {}_".format(scope_note), ""]
    for i, s in enumerate(steps, 1):
        lines.append("{}. **{}** `{}`{} - rank {}".format(
            i, s["action"], s["entity_value"] or "no entity",
            " on " + s["host"] if s.get("host") else "", s["order"]))
    if not steps:
        lines.append("_The contract supplies no entity for any {} action._".format(phase))
    if payload and payload.get("coverage_note"):
        lines.append("")
        lines.append("_{}_".format(payload["coverage_note"]))

    return_results(CommandResults(
        outputs_prefix="SOCFramework.Phase.Proposed",
        outputs_key_field="action",
        outputs=steps,
        readable_output="\n".join(lines)))



def merge_contracts(payload):
    """Union the per-shape contracts into one artifact view.

    Shapes are host-stripped so one technique is one shape, which is what keeps
    the payload small. The consequence is that a shape contract cannot say which
    host it came from - that binding lives in payload['hosts'], and case-scope
    planning re-attaches it rather than flattening everything into one bag.
    """
    merged = {}

    def deep(dst, src):
        for k, v in (src or {}).items():
            if isinstance(v, dict):
                deep(dst.setdefault(k, {}), v)
            elif k not in dst or dst[k] in (None, "", [], {}):
                dst[k] = v

    for shape in (payload.get("shapes") or []):
        deep(merged, (shape.get("contract") or {}))
    return merged


def host_contexts(payload, merged):
    """One artifact view per host, with that host's own hashes and addresses."""
    out = []
    for h in (payload.get("hosts") or []):
        view = json.loads(json.dumps(merged))
        art = view.setdefault("SOCFramework", {}).setdefault("Artifacts", {})
        art.setdefault("Endpoint", {})["Hostname"] = h.get("host_name")
        art["Endpoint"]["AgentID"] = h.get("endpoint_id")
        art["EndPointID"] = h.get("endpoint_id")
        hashes = h.get("hashes") or []
        ips = h.get("ips") or []
        if hashes:
            art["Hash"] = hashes[0]
        if ips:
            art.setdefault("Network", {}).setdefault("Destination", {})["IP"] = ips[0]
        out.append((h.get("host_name") or h.get("endpoint_id") or "", view, hashes, ips))
    return out


def build_case(phase, actions, payload, include_gaps):
    """Plan across a whole case.

    Host-scoped actions fan out per host, because containing bannik says nothing
    about hobgoblin. Artifact and identity actions stay single-instance against
    the merged view - one C2 address is blocked once, not once per host that
    talked to it.
    """
    merged = merge_contracts(payload)
    hosts = host_contexts(payload, merged)
    steps = []

    for name, entry in actions.items():
        if not isinstance(entry, dict) or entry.get("phase") != phase:
            continue
        responses = entry.get("responses") or {}
        if not responses:
            continue
        scope = entry.get("entity_scope") or "artifact"
        rank = entry.get("sequence_rank", 999)

        views = hosts if (scope == "host" and hosts) else [("", merged, [], [])]
        for host_name, view, _h, _i in views:
            pairs = []
            for binding in responses.values():
                pairs.extend(resolved_args(binding, view))
            entity = first_value(pairs)
            if not entity and not include_gaps:
                continue
            steps.append({
                "action": name,
                "entity_type": scope,
                "entity_value": entity,
                "host": host_name,
                "order": rank,
                "rationale": describe(entry, entity) + (
                    " (host {})".format(host_name) if host_name else ""),
                "planner": "deterministic",
            })
    steps.sort(key=lambda s: (s["order"], s["action"], s.get("host") or ""))
    return steps


if __name__ in ("__builtin__", "builtins", "__main__"):
    try:
        main()
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error("SOCFWBuildPhasePlan failed: {}".format(e))
