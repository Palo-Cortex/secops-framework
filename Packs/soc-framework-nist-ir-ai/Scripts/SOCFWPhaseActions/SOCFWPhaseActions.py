"""Render the containment actions actually available on this issue.

Issue scope is assessment and containment escalation only. Eradication and
recovery are case-level phases and have no meaning against a single issue.

Layout buttons are static - a section item carries a fixed scriptId and has no
condition - so the layout cannot show or hide a button per product category.
This runs behind one button per phase and computes the set at click time, then
renders each applicable action as a clickable War Room action button.

An action is offered only when the tenant can reach a vendor for it and the
contract can supply its arguments. Both are the same checks SOCFWPhaseExecutor
makes before dispatch, so the analyst is never offered something that would fail.
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


def active_brands():
    try:
        modules = demisto.getModules() or {}
    except Exception:
        return None
    if not modules:
        return None
    brands = {}
    for m in modules.values():
        if isinstance(m, dict) and m.get("brand"):
            brands.setdefault(m["brand"], []).append(m.get("state"))
    return {b for b, st in brands.items() if "active" in st}


def usable(entry, ctx, brands):
    """A vendor we can reach, and every argument that vendor needs."""
    for vendor, binding in (entry.get("responses") or {}).items():
        if brands is not None and vendor not in brands:
            continue
        args = json.dumps(binding.get("inline_args") or {})
        missing = [p for p in TEMPLATE.findall(args)
                   if resolve(ctx, p) in (None, "", [], {})]
        if not missing:
            return vendor, ""
    return None, "no reachable vendor with resolvable arguments"


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
        "params": {"action": action},
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
    brands = active_brands()

    category = str(resolve(ctx, "SOCFramework.Product.category") or "").lower()
    allowed = CATEGORY_CLASSES.get(category)

    offered, blocked = [], []
    for name, entry in actions.items():
        if not isinstance(entry, dict) or entry.get("phase") != phase:
            continue
        cls = classes.get(name)
        if allowed and cls and cls not in allowed:
            continue
        vendor, why = usable(entry, ctx, brands)
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
