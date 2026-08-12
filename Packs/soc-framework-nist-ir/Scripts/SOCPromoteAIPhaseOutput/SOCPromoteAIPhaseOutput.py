"""
SOCPromoteAIPhaseOutput

The native aiTask writes its result to the Context path as a JSON *string* (this
XSIAM build stringifies it even with structured output enabled). This script parses
that string into a navigable object and promotes its flat fields into the phase
namespace the layout / phase contract reads (Analysis.*), so downstream readers and
the display resolve normally.

Idempotent, defensive against a stale list wrapper, and a no-op if the source is
already an object. If the AI prompt content does not exist on the tenant the aiTask
produces nothing and this script exits cleanly (continueonerror on the task keeps the
phase moving), so playbooks without AI content are unaffected.

Args:
  source_key        context path holding the aiTask output   (default Analysis.AI)
  target_namespace  namespace to promote flat fields into     (default Analysis)
  promote           promote flat fields into target_namespace (default true)
"""
import json
import demistomock as demisto
from CommonServerPython import *


def _load(raw):
    """Coerce the aiTask output into a dict: JSON text, stale list wrapper, or dict."""
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        return json.loads(raw)
    return None


def main():
    args = demisto.args() or {}
    source_key = args.get("source_key") or "Analysis.AI"
    target_ns = args.get("target_namespace") or "Analysis"
    promote = str(args.get("promote", "true")).lower() == "true"

    raw = demisto.dt(demisto.context(), source_key)
    if raw in (None, "", [], {}):
        return_results(CommandResults(readable_output=(
            f"### SOCPromoteAIPhaseOutput\n- `{source_key}` empty \u2014 no AI content, nothing to do."
        )))
        return

    try:
        obj = _load(raw)
    except (ValueError, TypeError) as e:
        return_error(f"SOCPromoteAIPhaseOutput: {source_key} is not valid JSON: {e}")
        return
    if not isinstance(obj, dict):
        return_error(f"SOCPromoteAIPhaseOutput: expected an object at {source_key}, got {type(raw).__name__}")
        return

    # store the parsed object back at the source key -> navigable dict
    demisto.setContext(source_key, obj)

    # promote each field into the flat namespace the layout / contract reads
    promoted = []
    if promote:
        for k, v in obj.items():
            demisto.setContext(f"{target_ns}.{k}", v)
            promoted.append(k)

    return_results(CommandResults(readable_output=(
        f"### SOCPromoteAIPhaseOutput\n"
        f"- parsed `{source_key}` \u2192 object with **{len(obj)}** keys\n"
        f"- promoted to `{target_ns}.*`: **{len(promoted)}** keys"
    )))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
