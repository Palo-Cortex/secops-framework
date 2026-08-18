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


# Structured verdict fields only. The narrative stays out of the dataset - it is large, it
# duplicates what the layout already renders, and it is not what anyone queries on.
VERDICT_FIELDS = (
    "verdict",
    "confidence",
    "compromise_decision",
    "compromise_level",
    "response_recommended",
    "case_score",
    "spread_level",
    "persistence_type",
    "primary_entity_type",
    "primary_entity_name",
    "primary_entity_id",
    "primary_entity_user",
    "mitre_tactic",
    "mitre_tactic_id",
    "mitre_technique",
    "mitre_technique_id",
)

# The model is not constrained to a controlled vocabulary, so it invents spellings:
# multi-host / multiple_hosts / multi_host for one concept, WindowsServer2019 in an entity
# type field. Anything keyed on these silently misses most rows, so they are snapped to
# canonical values here - the one choke point every AI branch passes through.
#
# Each entry is (canonical values, aliases -> canonical). Matching is done on a slug:
# lowercased, with spaces and hyphens folded to underscores.
CONTROLLED_FIELDS = {
    "verdict": (
        {"malicious", "suspicious", "benign", "unknown"},
        {"confirmed": "malicious", "true_positive": "malicious",
         "false_positive": "benign", "clean": "benign"},
    ),
    "confidence": (
        {"high", "medium", "low"},
        {"moderate": "medium", "med": "medium"},
    ),
    "compromise_level": (
        {"none", "host", "identity", "host_and_identity", "unknown"},
        {"endpoint": "host", "host_and_user": "host_and_identity",
         "user": "identity", "host_and_lateral": "host_and_identity",
         "account": "identity"},
    ),
    "spread_level": (
        {"single_host", "multi_host", "lateral", "unknown"},
        {"multi_hosts": "multi_host", "multiple_hosts": "multi_host",
         "multiple_host": "multi_host", "single": "single_host",
         "one_host": "single_host", "contained": "single_host"},
    ),
    "primary_entity_type": (
        {"endpoint", "identity", "file", "process", "email", "ip", "domain", "unknown"},
        {"host": "endpoint", "device": "endpoint", "machine": "endpoint",
         "user": "identity", "account": "identity", "hash": "file"},
    ),
}


def _slug(value):
    return str(value).strip().lower().replace(" ", "_").replace("-", "_")


def normalize_controlled_fields(obj):
    """Snap controlled fields to canonical values in place.

    An unrecognised value is not silently rewritten - the canonical field is set to
    "unknown" and the original is preserved at <field>_raw, so a vocabulary the model
    invented shows up in the data instead of disappearing into it.
    """
    unmapped = []
    for field, (canonical, aliases) in CONTROLLED_FIELDS.items():
        if field not in obj or obj[field] in (None, "", [], {}):
            continue
        original = obj[field]
        slug = _slug(original)
        resolved = slug if slug in canonical else aliases.get(slug)
        if resolved:
            obj[field] = resolved
            if resolved != _slug(original):
                obj[f"{field}_raw"] = original
        else:
            obj[f"{field}_raw"] = original
            obj[field] = "unknown"
            unmapped.append(f"{field}={original}")
    obj["contract_unmapped_count"] = len(unmapped)
    if unmapped:
        obj["contract_unmapped"] = "; ".join(unmapped)
    return unmapped



def _emit_reasoning_row(status, obj, source_key, phase):
    """Write one ai_reasoning row per AI execution, including executions that produced nothing.

    A prompt that runs and returns nothing is indistinguishable from a prompt that never ran,
    because continueonerror on the aiTask means neither fails the phase. The row is what makes
    the difference visible without reading the war room.
    """
    issue = demisto.incident() or {}
    payload = {
        "event_type": "ai_reasoning",
        "phase": phase,
        "reasoning_status": status,
        "source_key": source_key,
        "incident_id": issue.get("id"),
        "investigation_id": issue.get("investigationId"),
        "alert_name": issue.get("name"),
        "playbook_id": issue.get("playbookId"),
        "lifecycle": demisto.dt(demisto.context(), "SOCFramework.Lifecycle") or "NIST_IR",
        "alert_category": demisto.dt(demisto.context(), "SOCFramework.Product.category"),
    }
    for field in VERDICT_FIELDS:
        value = (obj or {}).get(field)
        if value not in (None, "", [], {}):
            payload[field] = value
    # carry the preserved originals and the violation count so drift is queryable
    for field in list(CONTROLLED_FIELDS) + ["contract_unmapped", "contract_unmapped_count"]:
        raw_key = f"{field}_raw" if field in CONTROLLED_FIELDS else field
        value = (obj or {}).get(raw_key)
        if value not in (None, "", [], {}):
            payload[raw_key] = value
    payload["verdict_field_count"] = sum(1 for f in VERDICT_FIELDS if f in payload)

    try:
        demisto.executeCommand(
            "socfw-post-to-dataset",
            {"using": "socfw_ir_execution_writer", "JSON": json.dumps(payload)},
        )
    except Exception as e:  # noqa: BLE001 - telemetry must never fail the phase
        demisto.debug(f"SOCPromoteAIPhaseOutput: ai_reasoning row not written: {e}")


def main():
    args = demisto.args() or {}
    source_key = args.get("source_key") or "Analysis.AI"
    target_ns = args.get("target_namespace") or "Analysis"
    phase = args.get("phase") or "Analysis"
    promote = str(args.get("promote", "true")).lower() == "true"

    raw = demisto.dt(demisto.context(), source_key)
    if raw in (None, "", [], {}):
        _emit_reasoning_row("no_output", None, source_key, phase)
        return_results(CommandResults(readable_output=(
            f"### SOCPromoteAIPhaseOutput\n- `{source_key}` empty \u2014 no AI content, nothing to do."
        )))
        return

    try:
        obj = _load(raw)
    except (ValueError, TypeError) as e:
        _emit_reasoning_row("parse_error", None, source_key, phase)
        return_error(f"SOCPromoteAIPhaseOutput: {source_key} is not valid JSON: {e}")
        return
    if not isinstance(obj, dict):
        _emit_reasoning_row("parse_error", None, source_key, phase)
        return_error(f"SOCPromoteAIPhaseOutput: expected an object at {source_key}, got {type(raw).__name__}")
        return

    # store the parsed object back at the source key -> navigable dict
    demisto.setContext(source_key, obj)

    # canonicalise before promoting, so downstream branches and the layout read the same
    # vocabulary the dataset does
    unmapped = normalize_controlled_fields(obj)

    # promote each field into the flat namespace the layout / contract reads
    promoted = []
    if promote:
        for k, v in obj.items():
            demisto.setContext(f"{target_ns}.{k}", v)
            promoted.append(k)

    _emit_reasoning_row("promoted" if promoted else "parsed_not_promoted", obj, source_key, phase)

    warning = f"\n- \u26a0 unmapped controlled values: {'; '.join(unmapped)}" if unmapped else ""
    return_results(CommandResults(readable_output=(
        f"### SOCPromoteAIPhaseOutput\n"
        f"- parsed `{source_key}` \u2192 object with **{len(obj)}** keys\n"
        f"- promoted to `{target_ns}.*`: **{len(promoted)}** keys{warning}"
    )))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
