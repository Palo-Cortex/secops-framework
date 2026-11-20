"""Render the containment actions actually available on this issue.

Issue scope is assessment and containment escalation only. Eradication and
recovery are case-level phases and have no meaning against a single issue.

Layout buttons are static - a section item carries a fixed scriptId and has no
condition - so the layout cannot show or hide a button per product category.
This runs behind one button per phase and computes the set at click time, then
renders each applicable action as a clickable War Room action button.

An action is offered only when clicking it would run: the vendor is the one
SOCCommandWrapper would route to for this issue's data source (its response
integration in SOCProductCategoryMap_V3), that vendor is not known to be down,
and the contract supplies its arguments. The analyst is never offered a vendor
that does not own the alert, or something the wrapper would skip.
"""
import json
import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

ACTIONS_LIST = "SOCFrameworkActions_V3"
CLASS_LIST = "SOCActionClassMap_V3"

TEMPLATE = re.compile(r"\$\{([^}]+)\}")

# Action classes that belong to each product category, so an email issue is not
# offered endpoint isolation. Indicator actions apply everywhere - a hash or an
# address is worth blocking whatever raised it.
CATEGORY_CLASSES = {
    "endpoint": ("endpoint", "indicator"),
    "email": ("email", "indicator"),
    "identity": ("identity", "indicator"),
    "network": ("indicator",),
    "saas": ("identity", "indicator"),
    "workload": ("endpoint", "indicator"),
}


def get_list(name):
    try:
        res = demisto.executeCommand("getList", {"listName": name})
        raw = res[0]["Contents"] if res else None
        return json.loads(raw) if isinstance(raw, str) else (raw or {})
    except Exception as e:
        demisto.debug("SOCFWPhaseActions: cannot read {} ({})".format(name, e))
        return {}


def resolve(root, path):
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


def module_states():
    """brand -> the states of its instances, or None when the registry cannot be read."""
    try:
        modules = demisto.getModules() or {}
    except Exception:
        return None
    if not modules:
        return None
    states = {}
    for m in modules.values():
        if isinstance(m, dict) and m.get("brand"):
            states.setdefault(m["brand"], []).append(m.get("state"))
    return states


def reachable(vendor, states):
    """SOCCommandWrapper.brand_available: a vendor is out only when a module
    carries that brand and none of its instances is active. A label no module
    claims is dispatched anyway - registry labels do not always equal the
    installed brand ('CrowdStrike Falcon' vs 'CrowdstrikeFalcon'), and the
    platform runs commands by name."""
    if states is None or vendor == "Builtin" or vendor not in states:
        return True
    return "active" in states[vendor]


def routed_vendors(entry, action_class, ctx):
    """The vendors SOCCommandWrapper would dispatch this action to on this issue.

    The same ladder as the wrapper: the data source's response integration for
    the action's class (SOCProductCategoryMap_V3, via SOCFramework.Product.responses),
    then a Builtin-only action, then the legacy SOCFramework.Product.response. No
    fallback to another vendor's branch - the wrapper skips rather than run a
    vendor that does not own the alert. An all_applicable action goes to every
    branch it declares.
    """
    responses = entry.get("responses") or {}
    if str(entry.get("dispatch") or "routed").strip().lower() == "all_applicable":
        return list(responses)
    by_class = resolve(ctx, "SOCFramework.Product.responses") or {}
    if isinstance(by_class, str):
        try:
            by_class = json.loads(by_class)
        except ValueError:
            by_class = {}
    vendor = by_class.get(action_class) if action_class and isinstance(by_class, dict) else None
    if vendor in responses:
        return [vendor]
    if set(responses) == {"Builtin"}:
        return ["Builtin"]
    legacy = resolve(ctx, "SOCFramework.Product.response")
    if legacy in responses:
        return [legacy]
    return []


def usable(entry, action_class, ctx, states):
    """(vendor, "") for the first routed vendor that is reachable and whose
    arguments the contract supplies, else (None, why)."""
    vendors = routed_vendors(entry, action_class, ctx)
    if not vendors:
        source = resolve(ctx, "SOCFramework.Product.response") or "this source"
        return None, "no implementation for {}".format(source)
    why = ""
    for vendor in vendors:
        if not reachable(vendor, states):
            why = "{} has no active instance".format(vendor)
            continue
        args = json.dumps((entry["responses"][vendor] or {}).get("inline_args") or {})
        missing = [p.rsplit(".", 1)[-1] for p in TEMPLATE.findall(args)
                   if resolve(ctx, p) in (None, "", [], {})]
        if not missing:
            return vendor, ""
        why = "{} needs {}".format(vendor, ", ".join(missing))
    return None, why


def action_button(label, action):
    """A clickable War Room action entry.

    The %%%...%%% payload must be well-formed JSON and must sit alone on its
    line - trailing text after the closing parens is parsed as part of the entry
    and breaks it. Anything the analyst needs to read goes in the label.

    Dispatches SOCCommandWrapper rather than a vendor command, so shadow mode,
    the action registry and the execution row apply exactly as when a playbook
    fires the same action.
    """
    # Capability labels carry em dashes, which serialise to \u2014 escapes. Keep
    # the payload plain ASCII so the entry parser has nothing to choke on.
    clean = "".join(c if 32 <= ord(c) < 127 else "-" for c in str(label))
    payload = json.dumps({
        "message": clean,
        "action": "SOCCommandWrapper",
        # Identifies the caller so shadow_mode_by_actor can let an analyst act
        # for real while the JOB still only simulates.
        "params": {"action": action, "Action_Actor": "analyst"},
    }, separators=(",", ":"))
    # Bare %%%...%%% per the markdown reference. Wrapping it in colour markdown
    # breaks the parse, and anything between the markers that is not valid JSON
    # is rendered as a command instead of a button.
    return "%%%" + payload + "%%%"


def entity_for(entry, ctx):
    """The most specific argument that resolved, for display next to the button."""
    pref = ("Process.PID", "Process.Name", "Email.MessageID", "Email.From",
            "Hash", "FilePath", "File", "Network.Destination.IP",
            "Identity.User.UPN", "Identity.User.Name", "Endpoint.Hostname",
            "EndPointID")
    found = {}
    for binding in (entry.get("responses") or {}).values():
        for p in TEMPLATE.findall(json.dumps(binding.get("inline_args") or {})):
            v = resolve(ctx, p)
            if isinstance(v, (str, int)) and str(v).strip():
                found[p] = str(v)
    for suffix in pref:
        for path, val in found.items():
            if path.endswith(suffix):
                return val
    return ""


def main():
    args = demisto.args()
    phase = (args.get("phase") or "containment").lower()

    actions = get_list(ACTIONS_LIST) or {}
    classes = get_list(CLASS_LIST) or {}
    ctx = demisto.context() or {}
    states = module_states()

    category = str(resolve(ctx, "SOCFramework.Product.category") or "").lower()
    allowed = CATEGORY_CLASSES.get(category)

    offered, blocked = [], []
    for name, entry in actions.items():
        if not isinstance(entry, dict) or entry.get("phase") != phase:
            continue
        cls = classes.get(name)
        if allowed and cls and cls not in allowed:
            continue
        vendor, why = usable(entry, cls, ctx, states)
        label = entry.get("capability") or name
        if vendor:
            offered.append((entry.get("sequence_rank", 999), label, name,
                            entity_for(entry, ctx)))
        else:
            blocked.append((label, why))

    heading = ("Undo containment" if phase == "recovery"
               else "{} actions".format(phase.title()))
    lines = ["### {}".format(heading),
             "",
             "_Only actions with a reachable vendor and complete arguments are "
             "offered. Anything missing is listed below with the reason._"]
    if offered:
        # Registry order, so the suggested sequence is the same one the
        # deterministic planner would use.
        for _, label, name, entity in sorted(offered):
            lines.append("")
            lines.append(action_button(
                "{} — {}".format(label, entity) if entity else label, name))
    else:
        lines.append("")
        lines.append("_Nothing to {} on this issue._".format(
            "undo" if phase == "recovery" else "contain"))

    if blocked:
        lines.append("")
        lines.append("**Not available**")
        for label, why in sorted(blocked):
            lines.append("- {} — _{}_".format(label, why))

    return_results(CommandResults(readable_output="\n".join(lines)))


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
