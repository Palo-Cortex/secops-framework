"""Collect reputation and threat-intel context into one key for the assessment prompt.

Foundation enrichment runs the reputation commands, which write their verdicts to
standard context roots (DBotScore, IP, Domain, File, URL and friends) rather than
into SOCFramework.Artifacts. A prompt variable binds a single path, so the roots
are gathered here into one object.

Which roots to read comes from SOCOptimizationConfig_V3 CaseIntelRoots, so the
issue path and the case JOB stay on one list — adding Recorded Future or GTI
there reaches both.

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


def _trim(obj, max_chars):
    """Drop whole roots, largest first, until the payload fits the budget.

    Losing a root entirely is honest; a truncated JSON string would read to the
    model as corrupt evidence.
    """
    dropped = []
    while len(json.dumps(obj)) > max_chars and obj:
        biggest = max(obj, key=lambda k: len(json.dumps(obj[k])))
        obj.pop(biggest)
        dropped.append(biggest)
    return obj, dropped


def main():
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

    found = collect(context, str(roots).split(","))
    found, dropped = _trim(found, max_chars)

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
