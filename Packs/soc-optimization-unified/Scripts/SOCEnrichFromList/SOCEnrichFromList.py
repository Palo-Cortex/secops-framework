"""
SOCEnrichFromList
=================
Data-driven SOC Framework Upon Trigger enrichment engine. Reads the per-lifecycle
SOCFrameworkEnrichmentMap_<LIFECYCLE> list and fires a built-in reputation
command (|||<lane>) per lane whose source paths resolve to at least one
non-empty value on the SOCFramework.Artifacts.* surface.

LIST CONVENTION
  A lane is either a list of source paths or an override object.

  List form — lane key is BOTH the built-in reputation command name AND its
  argument name. Example: lane 'ip' fires `!ip ip=<comma-joined values>`.

  Object form — lane key is a label only. The lane names one or more universal
  commands, dispatched through SOCCommandWrapper:

      identity:
        actions: [soc-enrich-user, soc-enrich-user-manager]
        fire_when: [Artifacts.Identity.User.UPN, ...]

  UC actions resolve their own arguments from SOCFramework.Artifacts.* inside
  the wrapper, so an override lane passes no values. Its source paths are only
  a firing condition: an alert with no identity skips the lane and costs
  nothing. Actions fire in listed order, since later ones may read what earlier
  ones published.

  Source paths in both forms point into SOCFramework.Artifacts.* (the normalized
  contract surface populated by Foundation - Normalize Artifacts).

ARGS
  lifecycle             optional — lifecycle token (default 'nist_ir'). Selects
                                   WHICH enrichment list to read by naming
                                   convention:
                                       SOCFrameworkEnrichmentMap_<LIFECYCLE.upper()>
                                   e.g. nist_ir -> SOCFrameworkEnrichmentMap_NIST_IR.
                                   A new lifecycle ships its own list under that
                                   name in its own pack; the engine finds it with
                                   no change here.
  list_name             optional — explicit override of the resolved list name.

OUTPUTS
  SOCFramework.EnrichFromList — execution summary (lanes fired, lanes skipped,
                                values per lane, list name resolved).

DESIGN NOTES
  - Read-only by definition: no shadow_mode concept here. Enrichment is
    reputation lookup, never destructive. The UC actions reachable from an
    override lane are the soc-enrich-* family, which ship shadow_mode: false.
  - Built-in shortcuts have no override field by design. A lane that needs a
    non-shortcut command names a universal command instead, so routing stays
    inside the framework rather than hard-coding a vendor here.

CONTRACT VS BEHAVIOR
  This script reads the list as ground truth. To change enrichment behavior,
  edit schemas/soc-framework/soc-framework-nist-ir/SOCFrameworkEnrichmentMap_NIST_IR.yaml
  and regenerate the list — never edit the script for per-lane changes.
"""

CONSTANT_PACK_VERSION = '3.10.2'
demisto.debug(f'pack id = soc-optimization-unified, pack version = {CONSTANT_PACK_VERSION}')

import ipaddress
import json


# ---------------------------------------------------------------------------
# List loading (mirrors SOCNormalizeFromList pattern)
# ---------------------------------------------------------------------------

def load_list_lanes(list_name):
    """
    Load the lifecycle's enrichment list and return the 'lanes' dict.
    Raises ValueError on missing list / unparseable contents / no lanes.
    """
    res = demisto.executeCommand("getList", {"listName": list_name})
    if not res:
        raise ValueError(f"getList returned no result for {list_name}")

    contents = None
    if isinstance(res, list) and res:
        contents = res[0].get("Contents")
    elif isinstance(res, dict):
        contents = res.get("Contents")

    if contents is None:
        raise ValueError(f"List {list_name} has no contents")

    if isinstance(contents, str):
        if contents.strip().lower().startswith("item not found"):
            raise ValueError(f"List {list_name} not found on tenant")
        try:
            contents = json.loads(contents)
        except Exception as e:
            raise ValueError(f"List {list_name} is not valid JSON: {e}")

    if not isinstance(contents, dict):
        raise ValueError(f"List {list_name} root is not an object")

    lanes = contents.get("lanes")
    if not isinstance(lanes, dict) or not lanes:
        raise ValueError(f"List {list_name} has no 'lanes' object")

    return lanes


# ---------------------------------------------------------------------------
# Path resolution against the SOCFramework.Artifacts.* surface
# ---------------------------------------------------------------------------

def resolve_paths(paths, ctx):
    """
    For each dotted path under SOCFramework.*, return the non-empty resolved
    values. Paths may resolve to a scalar or list. Lists are flattened; scalars
    are wrapped. Empty strings, None, and empty collections are dropped.
    Order-preserving dedupe on the final value set.
    """
    out = []
    seen = set()
    for p in paths or []:
        # Paths in the list are written as 'Artifacts.Network.IP' etc.;
        # SOCFramework.* is the implicit root.
        full = p if p.startswith("SOCFramework.") else f"SOCFramework.{p}"
        val = demisto.get(ctx, full)

        if val is None:
            continue
        if isinstance(val, list):
            items = val
        elif isinstance(val, str):
            items = [val]
        else:
            items = [val]

        for item in items:
            if item in (None, "", [], {}):
                continue
            s = str(item).strip()
            if not s:
                continue
            if s not in seen:
                seen.add(s)
                out.append(s)
    return out


# ---------------------------------------------------------------------------
# Per-lane fire
# ---------------------------------------------------------------------------

def public_ips_only(values):
    """Drop addresses no reputation service can say anything about.

    Private, loopback, link-local, CGNAT and multicast space has no reputation.
    Sending it wastes a lookup on every internal alert, and some providers raise
    rather than return empty on it, which surfaces as an errored lane on issues
    that were never enrichable in the first place.

    Anything unparseable is kept. This filter exists to remove certain noise,
    not to become a second validator.
    """
    kept = []
    for value in values:
        try:
            ip = ipaddress.ip_address(str(value).strip())
        except ValueError:
            kept.append(value)
            continue
        if ip.is_global and not ip.is_multicast:
            kept.append(value)
    return kept


def fire_lane(lane_name, values):
    """
    Call the built-in reputation command for this lane. The lane key IS the
    command name AND the argument name by convention.
    Returns (ok: bool, message: str).
    """
    try:
        result = demisto.executeCommand(
            lane_name,
            {lane_name: ",".join(values)}
        )
        # Best-effort error detection — failures are non-fatal for enrichment
        if isinstance(result, list):
            for entry in result:
                if isinstance(entry, dict) and entry.get("Type") == entryTypes.get("error", 4):
                    return False, str(entry.get("Contents", ""))[:200]
        return True, f"{len(values)} value(s) enriched"
    except Exception as e:
        return False, str(e)[:200]


def fire_actions(actions):
    """Run an override lane's universal commands through SOCCommandWrapper.

    No values are passed. The wrapper resolves each action's vendor arguments
    from SOCFramework.Artifacts.* itself, and picks the vendor from the product
    category, so this stays vendor-agnostic.

    One action failing does not stop the lane — a tenant missing a manager
    integration should still get the user record.
    """
    ok, failures = [], []
    for action in actions:
        try:
            result = demisto.executeCommand("SOCCommandWrapper", {
                "action": action,
                "Action_Actor": "automation",
                "Phase": "Enrichment",
                "tags": "Enrichment",
            })
            err = ""
            if isinstance(result, list):
                for entry in result:
                    if isinstance(entry, dict) and entry.get("Type") == entryTypes.get("error", 4):
                        err = str(entry.get("Contents", ""))[:200]
                        break
            if err:
                failures.append({"action": action, "error": err})
            else:
                ok.append(action)
        except Exception as e:
            failures.append({"action": action, "error": str(e)[:200]})

    if failures:
        return False, ok, f"{len(ok)} ran, {len(failures)} failed: " + \
            "; ".join(f"{f['action']} ({f['error']})" for f in failures)
    return True, ok, f"{len(ok)} action(s) ran"


def warroom_log(title, payload):
    try:
        demisto.results({
            "Type": entryTypes.get("note", 1),
            "ContentsFormat": formats.get("json", "json"),
            "Contents": payload,
            "HumanReadable": f"### {title}\n```json\n{json.dumps(payload, indent=2)}\n```"
        })
    except Exception as e:
        demisto.debug(f"warroom_log failed: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = demisto.args() or {}
    lifecycle = (args.get("lifecycle") or "nist_ir").strip() or "nist_ir"
    list_name = (args.get("list_name") or "").strip() \
        or f"SOCFrameworkEnrichmentMap_{lifecycle.upper()}"

    demisto.debug(f"SOCEnrichFromList: lifecycle={lifecycle} list={list_name}")

    try:
        lanes = load_list_lanes(list_name)
    except ValueError as e:
        return_error(f"SOCEnrichFromList: {e}")
        return

    ctx = demisto.context()

    fired = []
    skipped_empty = []
    errored = []

    for lane_name, lane_spec in lanes.items():
        # A lane is either a list of source paths (built-in reputation command)
        # or an object naming universal commands to dispatch instead.
        if isinstance(lane_spec, dict):
            actions = lane_spec.get("actions") or []
            source_paths = lane_spec.get("fire_when") or []
            if not actions:
                skipped_empty.append({"lane": lane_name, "reason": "no actions in list"})
                continue
        elif isinstance(lane_spec, list):
            actions = None
            source_paths = lane_spec
        else:
            skipped_empty.append({"lane": lane_name, "reason": "unrecognized lane shape"})
            continue

        if not source_paths:
            skipped_empty.append({"lane": lane_name, "reason": "no source_paths in list"})
            continue

        values = resolve_paths(source_paths, ctx)
        if not values:
            skipped_empty.append({"lane": lane_name, "reason": "all source paths empty"})
            continue

        if lane_name == "ip":
            resolved = len(values)
            values = public_ips_only(values)
            if not values:
                skipped_empty.append({"lane": lane_name,
                                      "reason": f"no public addresses among {resolved} resolved"})
                continue

        if actions:
            ok, ran, msg = fire_actions(actions)
            record = {"lane": lane_name, "actions": ran, "value_count": len(values),
                      "message": msg}
        else:
            ok, msg = fire_lane(lane_name, values)
            record = {"lane": lane_name, "values": values, "value_count": len(values),
                      "message": msg}

        if ok:
            fired.append(record)
        else:
            errored.append(record)

    summary = {
        "lifecycle": lifecycle,
        "list_name": list_name,
        "lanes_fired": len(fired),
        "lanes_skipped_empty": len(skipped_empty),
        "lanes_errored": len(errored),
        "fired": fired,
        "skipped_empty": skipped_empty,
        "errored": errored,
    }

    readable_lines = [
        f"### SOCEnrichFromList — {lifecycle}",
        f"- lanes fired: **{len(fired)}**"
        + (f"  ({', '.join(r['lane'] for r in fired)})" if fired else ""),
        f"- skipped (empty source): {len(skipped_empty)}",
        f"- errored: {len(errored)}",
        f"- list: `{list_name}`",
    ]

    return_results(CommandResults(
        readable_output="\n".join(readable_lines),
        outputs_prefix="SOCFramework.EnrichFromList",
        outputs=summary,
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
