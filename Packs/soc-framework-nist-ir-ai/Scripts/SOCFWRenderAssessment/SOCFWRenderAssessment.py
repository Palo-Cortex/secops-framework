"""Render the issue assessment as a War Room entry.

Matches SOCFWCaseVerdictReport so the issue verdict and the case verdict read as
siblings. XSIAM renders markdown, emoji and monospace whitespace; HTML ships as
literal tags, so emoji is the only colour available and column alignment is the
main legibility lever.

Args:
  source_key   context path holding the assessment (default Assessment.AI)
  max_blockers closure blockers to list before summarising the rest
"""
import json
import demistomock as demisto
from CommonServerPython import *

VERDICT_MARK = {
    'malicious': '🔴',
    'suspicious': '🟠',
    'benign': '🟢',
    'inconclusive': '⚪',
}

CONFIDENCE_MARK = {'high': '●●●', 'medium': '●●○', 'low': '●○○'}

EXPOSURE_NOTE = {
    'none': 'nothing reached the asset',
    'attempted': 'attempted, did not land',
    'delivered': 'delivered to the asset',
    'executed': 'executed on the asset',
    'unknown': 'unknown',
}

# Past this the entry trips XSIAM's Partial View truncation.
MAX_STORY_LINES = 6
MAX_BLOCKER_LINES = 6


def _as_object(raw):
    """Accept a dict or the raw JSON string the aiTask returns.

    The promote step normally parses it, but it lives in another pack and is
    skipped where that pack is absent. A model that fences its answer or opens
    with prose fails json.loads at char 0, so trim to the braces first.
    """
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        start, end = raw.find('{'), raw.rfind('}')
        if start != -1 and end > start:
            raw = raw[start:end + 1]
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return _salvage(raw)
    return None


def _salvage(raw):
    """Recover what we can from a response the model ran out of tokens mid-way through.

    The verdict fields are emitted before the long story text, so a truncated
    object still carries the decision. Trim back to the last complete key/value
    pair and close the object.
    """
    cut = raw.rfind('",')
    if cut == -1:
        cut = raw.rfind("},")
    while cut > 0:
        try:
            obj = json.loads(raw[:cut + 1] + "}")
            obj["_truncated"] = True
            return obj
        except (ValueError, TypeError):
            nxt = raw.rfind('",', 0, cut)
            if nxt == -1 or nxt == cut:
                return None
            cut = nxt
    return None


def _strip_label(entry):
    """Drop the model's 'LABEL:' prefix — the numbered list already sequences it."""
    text = ' '.join(str(entry).split())
    head, sep, tail = text.partition(':')
    if sep and head.isupper() and len(head) < 40:
        return tail.strip()
    return text


def render(obj, max_blockers=MAX_BLOCKER_LINES):
    verdict = str(obj.get('verdict') or '').lower() or 'inconclusive'
    confidence = str(obj.get('confidence') or '').lower()
    mark = VERDICT_MARK.get(verdict, '⚪')
    conf = CONFIDENCE_MARK.get(confidence, '○○○')
    exposure = str(obj.get('exposure') or 'unknown').lower()

    # What to do sits on the first two lines; detail comes after.
    if obj.get('closure_recommended'):
        action = f"close — {obj.get('closure_reason') or 'no reason given'}"
    elif obj.get('escalate_recommended'):
        action = 'escalate to an analyst'
    else:
        action = 'no action recommended'

    lines = [
        f"{mark} **ASSESSMENT** — {verdict.upper()}   {conf} {confidence or 'unknown'}",
        "",
        f"  action        {action}",
        f"  exposure      {EXPOSURE_NOTE.get(exposure, exposure)}"
        + ("   ·  already contained" if obj.get('already_contained') else ""),
    ]

    facts = [
        ('entity', obj.get('primary_entity_name') or obj.get('primary_entity_type')),
        ('mitre', ' '.join(f for f in (obj.get('mitre_tactic'), obj.get('mitre_technique_id')) if f)),
    ]
    for k, v in [(k, v) for k, v in facts if v]:
        lines.append(f"  {k:<13} {v}")

    story = obj.get('story') or []
    if isinstance(story, str):
        story = [story]
    if story:
        lines.append("")
        lines.append("  **ANALYSIS**")
        shown = story[:MAX_STORY_LINES]
        for i, step in enumerate(shown, 1):
            lines.append(f"  {i}. {_strip_label(step)}")
        if len(story) > len(shown):
            lines.append(f"  … {len(story) - len(shown)} further step(s) omitted")

    blockers = [b for b in (obj.get('closure_blockers') or []) if b]
    if blockers:
        lines.append("")
        lines.append("  **BEFORE THIS CAN CLOSE**")
        for b in blockers[:max_blockers]:
            lines.append(f"  · {' '.join(str(b).split())}")
        if len(blockers) > max_blockers:
            lines.append(f"  · … and {len(blockers) - max_blockers} more")

    if obj.get('_truncated'):
        lines.append("")
        lines.append("  ⚫ The model's reply was cut off by the output-token limit; "
                     "this is the part that survived.")

    if verdict == 'inconclusive' and not story:
        lines.append("")
        lines.append("  ⚫ No reasoning returned. Check the prompt inputs resolved — "
                     "an empty contract produces this exact result.")

    return "\n".join(lines)


def main():
    args = demisto.args() or {}
    source_key = args.get('source_key') or 'Assessment.AI'
    try:
        max_blockers = int(args.get('max_blockers') or MAX_BLOCKER_LINES)
    except (TypeError, ValueError):
        max_blockers = MAX_BLOCKER_LINES

    obj = _as_object(demisto.dt(demisto.context(), source_key))
    if not isinstance(obj, dict):
        return_results(CommandResults(readable_output=(
            f"⚪ **ASSESSMENT** — none\n\n  `{source_key}` was empty or could not be parsed."
        )))
        return

    return_results(CommandResults(readable_output=render(obj, max_blockers)))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
