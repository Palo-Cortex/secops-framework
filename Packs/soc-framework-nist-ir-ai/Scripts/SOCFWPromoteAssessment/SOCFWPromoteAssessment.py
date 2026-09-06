"""Parse the assessment and promote it into the Assessment namespace.

The aiTask returns its answer as a JSON string. This turns it into a navigable
object, promotes the flat fields, and writes an ai_reasoning row to the execution
dataset so the verdict is queryable.

Lives in this pack deliberately. The equivalent in soc-framework-nist-ir serves
the legacy per-issue Analysis path and stays there; depending on it from here
made the AI playbook fail whenever that pack's content was absent, and a missing
script marks itself and everything downstream WillNotBeExecuted rather than
skipping.
"""
import json
import re
from datetime import datetime, timezone

import demistomock as demisto
from CommonServerPython import *

# Structured verdict fields only. The story stays out of the dataset — it is
# large, the layout already renders it, and nobody queries on it.
VERDICT_FIELDS = (
    "verdict",
    "confidence",
    "exposure",
    "already_contained",
    "escalate_recommended",
    "closure_recommended",
    "closure_reason",
    "closure_confidence",
    "primary_entity_name",
    "primary_entity_type",
    "mitre_tactic",
    "mitre_technique_id",
    "truncated",
)


def _salvage(text):
    """Recover the decision from a reply cut off by the output token limit.

    The verdict fields are emitted before the long story text, so a truncated
    object still carries what matters. Trim back to the last complete pair and
    close the object rather than losing the whole assessment.
    """
    cut = text.rfind('",')
    while cut > 0:
        try:
            obj = json.loads(text[:cut + 1] + "}")
            obj["truncated"] = True
            return obj
        except (ValueError, TypeError):
            nxt = text.rfind('",', 0, cut)
            if nxt == -1 or nxt == cut:
                return None
            cut = nxt
    return None


def _load(raw):
    """Coerce the aiTask output into a dict.

    A model may fence its answer, open with prose, or be cut off by the token
    limit. Trim to the outermost braces, then salvage, so a recoverable reply is
    not thrown away.
    """
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        text = raw
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            text = text[start:end + 1]
        try:
            return json.loads(text)
        except (ValueError, TypeError):
            obj = _salvage(text)
            if obj is None:
                raise
            return obj
    return None


def _emit_reasoning_row(status, obj, source_key, phase, error=None, raw_prefix=None):
    """Write one ai_reasoning row. Telemetry must never fail the phase."""
    payload = {
        "event_type": "ai_reasoning",
        "phase": phase,
        "lifecycle": "NIST_IR",
        "source_key": source_key,
        "reasoning_status": status,
        "incident_id": str((demisto.incident() or {}).get("id") or ""),
        "alert_name": (demisto.incident() or {}).get("name") or "",
        "alert_category": demisto.get(demisto.context(), "SOCFramework.Product.category") or "",
        "emitted_at": datetime.now(timezone.utc).isoformat(),
    }
    for f in VERDICT_FIELDS:
        if isinstance(obj, dict) and obj.get(f) not in (None, "", [], {}):
            payload[f] = obj[f]
    payload["verdict_field_count"] = sum(1 for f in VERDICT_FIELDS if f in payload)
    # A failed parse carries no fields, so the reason is the only thing that makes
    # the row useful; the prefix distinguishes a fence from a preamble.
    if error:
        payload["reasoning_error"] = error
    if raw_prefix:
        payload["reasoning_raw_prefix"] = raw_prefix
    try:
        demisto.executeCommand(
            "socfw-post-to-dataset",
            {"using": "socfw_ir_execution_writer", "JSON": json.dumps(payload, default=str)},
        )
    except Exception as e:  # noqa: BLE001
        demisto.debug(f"SOCFWPromoteAssessment: ai_reasoning row not written: {e}")


def main():
    args = demisto.args() or {}
    source_key = args.get("source_key") or "Assessment.AI"
    target = args.get("target_namespace") or "Assessment"
    phase = args.get("phase") or "Assessment"
    promote = argToBoolean(args.get("promote", "true"))

    raw = demisto.get(demisto.context(), source_key)
    if raw in (None, "", [], {}):
        _emit_reasoning_row("no_output", None, source_key, phase)
        return_results(CommandResults(readable_output=f"No assessment at `{source_key}`."))
        return

    try:
        obj = _load(raw)
    except (ValueError, TypeError) as e:
        _emit_reasoning_row("parse_error", None, source_key, phase,
                            error=str(e), raw_prefix=str(raw)[:200])
        return_error(f"SOCFWPromoteAssessment: {source_key} is not valid JSON: {e}")
        return

    if not isinstance(obj, dict):
        _emit_reasoning_row("parse_error", None, source_key, phase,
                            error=f"expected an object, got {type(raw).__name__}",
                            raw_prefix=str(raw)[:200])
        return_error(f"SOCFWPromoteAssessment: expected an object at {source_key}")
        return

    if promote:
        # Replace the string with the parsed object, then promote the flat fields
        # so downstream tasks can read either shape.
        demisto.setContext(source_key, obj)
        for k, v in obj.items():
            if v not in (None, "", [], {}):
                demisto.setContext(f"{target}.{k}", v)

    _emit_reasoning_row("promoted", obj, source_key, phase)
    fields = sum(1 for f in VERDICT_FIELDS if obj.get(f) not in (None, "", [], {}))
    note = "  Reply was truncated; this is the part that survived." if obj.get("truncated") else ""
    return_results(CommandResults(readable_output=(
        f"Promoted **{obj.get('verdict') or 'no verdict'}** "
        f"/ {obj.get('confidence') or 'unknown'} confidence into `{target}.*` "
        f"({fields} fields).{note}"
    )))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
