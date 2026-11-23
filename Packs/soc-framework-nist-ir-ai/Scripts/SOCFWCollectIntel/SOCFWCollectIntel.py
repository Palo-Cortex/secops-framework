"""Collect reputation and threat-intel context into one key for the assessment prompt.

Foundation enrichment runs the reputation commands, which write their verdicts to
standard context roots (DBotScore, IP, Domain, File, URL and friends) rather than
into SOCFramework.Artifacts. A prompt variable binds a single path, so the roots
are gathered here into one object.

Which roots to read comes from SOCOptimizationConfig_V3 CaseIntelRoots, so the
issue path and the case JOB stay on one list. On top of those, the roots
SOCEnrichFromList saw this issue's enrichment answers write
(SOCFramework.EnrichFromList.intel_roots) are collected too, so a feed that
writes its own root is picked up without editing the list.

Args:
  roots       comma-separated context roots (default: the CaseIntelRoots value)
  output_key  where to write the collected object (default Assessment.Intel)
  max_chars   budget for the serialised result
"""
import json
import demistomock as demisto
from CommonServerPython import *

DEFAULT_ROOTS = "DBotScore,File,IP,Domain,URL,WildFire,AttackPattern,Tactic"


def collect(context, roots):
    """Return {root: value} for roots that resolved to something."""
    out = {}
    for root in roots:
        root = root.strip()
        if not root:
            continue
        value = demisto.dt(context, root)
        if value in (None, "", [], {}):
            continue
        out[root] = value
    return out


def reported_roots(context: dict) -> list:
    """The roots SOCEnrichFromList recorded, across every time it ran on this issue."""
    runs = demisto.dt(context, "SOCFramework.EnrichFromList")
    roots = []
    for run in runs if isinstance(runs, list) else [runs]:
        listed = run.get("intel_roots") if isinstance(run, dict) else None
        for root in listed if isinstance(listed, list) else []:
            root = str(root).strip()
            if root and root not in roots:
                roots.append(root)
    return roots


def _trim(obj: dict, max_chars: int, keep: list | tuple = ()) -> tuple[dict, list]:
    """Drop whole roots, largest first, until the payload fits the budget.

    Roots not in keep go first, so a large vendor root a feed reported never
    pushes out the configured roots such as DBotScore.

    Losing a root entirely is honest; a truncated JSON string would read to the
    model as corrupt evidence.
    """
    dropped = []
    while len(json.dumps(obj)) > max_chars and obj:
        extra = [k for k in obj if k not in keep]
        biggest = max(extra or obj, key=lambda k: len(json.dumps(obj[k])))
        obj.pop(biggest)
        dropped.append(biggest)
    return obj, dropped


def main() -> None:
    """Write the configured and reported intel roots to output_key for the assessment prompt."""
    args = demisto.args() or {}
    output_key = args.get("output_key") or "Assessment.Intel"
    try:
        max_chars = int(args.get("max_chars") or 20000)
    except (TypeError, ValueError):
        max_chars = 20000

    context = demisto.context() or {}
    roots = args.get("roots") or demisto.dt(context, "SOCFramework.Case.Config.CaseIntelRoots") or DEFAULT_ROOTS
    if isinstance(roots, list):
        roots = ",".join(str(r) for r in roots)
    configured = [r.strip() for r in str(roots).split(",") if r.strip()]
    roots = configured + [r for r in reported_roots(context) if r not in configured]

    found = collect(context, roots)
    found, dropped = _trim(found, max_chars, keep=configured)

    if not found:
        demisto.setContext(output_key, "no content")
        note = "no reputation or threat intel resolved for this issue"
    else:
        payload = dict(found)
        if dropped:
            # say what was shed, so the model reads it as missing rather than clean
            payload["coverage_note"] = "Dropped for size, not absent: " + ", ".join(dropped)
        demisto.setContext(output_key, json.dumps(payload, default=str))
        note = f"{len(found)} intel root(s): {', '.join(sorted(found))}"
        if dropped:
            note += f" — dropped for size: {', '.join(dropped)}"

    return_results(CommandResults(readable_output=f"### Intel collected\n- {note}"))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
