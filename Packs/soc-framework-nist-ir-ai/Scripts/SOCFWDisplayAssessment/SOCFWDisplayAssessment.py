"""Render the issue assessment in the layout's Assessment section.

Layouts render HTML, unlike the War Room. Reads Assessment.* written by the
issue-scope prompt, and shows the case verdict alongside it where the case JOB
has also run — the case sees what a single issue cannot, so where the two
disagree the case verdict is the one to act on.
"""
import json
import demistomock as demisto
from CommonServerPython import *

PENDING = "<div style='color:#888;font-style:italic;padding:8px;'>Assessment running...</div>"

VERDICT_COLOR = {
    "malicious": "#c62828",
    "suspicious": "#e65100",
    "benign": "#2e7d32",
    "inconclusive": "#455a64",
}

EXPOSURE_NOTE = {
    "none": "nothing reached the asset",
    "attempted": "attempted, did not land",
    "delivered": "delivered to the asset",
    "executed": "executed on the asset",
    "unknown": "exposure unknown",
}


def _scalar(ctx, path):
    """Single value. Collapses a list, which the promoted flat fields can be."""
    val = demisto.get(ctx, path)
    if isinstance(val, list):
        val = val[0] if val else None
    return val if val not in (None, "", [], {}) else None


def _assessment(ctx):
    """Prefer the whole parsed object over the promoted flat fields.

    Promotion flattens each key separately, and a list-valued key read back one
    key at a time collapses to its first element — which silently truncated the
    story and the blockers to a single line each. Reading the object keeps this
    view identical to the War Room entry.
    """
    obj = demisto.get(ctx, "Assessment.AI")
    if isinstance(obj, list):
        obj = obj[0] if obj else None
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except (ValueError, TypeError):
            obj = None
    return obj if isinstance(obj, dict) else {}


def _badge(label, color):
    return (
        f"<span style='background:{color};color:#fff;padding:2px 8px;"
        f"border-radius:3px;font-size:11px;font-weight:bold;'>{label}</span>"
    )


def _section(title, content, border_color="#0288d1"):
    return (
        f"<div style='margin-bottom:12px;border-left:3px solid {border_color};"
        f"padding-left:10px;'>"
        f"<div style='font-size:10px;color:#888;text-transform:uppercase;"
        f"letter-spacing:1px;margin-bottom:4px;'>{title}</div>"
        f"<div style='color:#ddd;font-size:12px;line-height:1.5;'>{content}</div>"
        f"</div>"
    )


def _as_list(val):
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [v for v in val if v]
    return [str(val)]


def main():
    ctx = demisto.context()

    a = _assessment(ctx)

    def f(key):
        v = a.get(key)
        if v in (None, "", [], {}):
            v = _scalar(ctx, "Assessment." + key)
        return v

    verdict = f("verdict")
    confidence = f("confidence")
    exposure = str(f("exposure") or "").lower()
    contained = f("already_contained")
    escalate = f("escalate_recommended")
    close_ok = f("closure_recommended")
    close_reason = f("closure_reason")
    close_conf = f("closure_confidence")
    blockers = _as_list(f("closure_blockers"))
    story = _as_list(f("story"))
    entity = f("primary_entity_name") or f("primary_entity_type")
    tactic = f("mitre_tactic")
    technique = f("mitre_technique_id")
    truncated = f("truncated")

    case_verdict = _scalar(ctx, "SOCFramework.Analysis.AI.verdict") or _scalar(ctx, "Analysis.verdict")
    case_story = demisto.get(ctx, "SOCFramework.Analysis.AI.story") or demisto.get(ctx, "Analysis.story")

    if not verdict and not case_verdict:
        demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": PENDING})
        return

    html = "<div style='padding:4px;'>"

    if verdict:
        head = _badge(str(verdict).upper(), VERDICT_COLOR.get(str(verdict).lower(), "#555")) + "&nbsp;"
        if confidence:
            head += _badge(f"Confidence: {confidence}", "#37474f") + "&nbsp;"
        if exposure:
            head += _badge(EXPOSURE_NOTE.get(exposure, exposure), "#1a237e") + "&nbsp;"
        if contained:
            head += _badge("Already contained", "#2e7d32") + "&nbsp;"
        if escalate:
            head += _badge("Needs an analyst", "#c62828")
        html += f"<div style='margin-bottom:12px;'>{head}</div>"

    facts = []
    if entity:
        facts.append(f"<b>Entity:</b> {entity}")
    if tactic or technique:
        facts.append(f"<b>MITRE:</b> {' '.join(str(f) for f in (tactic, technique) if f)}")
    if facts:
        html += _section("Subject", "<br>".join(facts), "#0277bd")

    if story:
        body = "".join(f"<div style='margin:3px 0;'>{s}</div>" for s in story)
        html += _section("Analysis", body)

    # Closure is the decision an analyst acts on, so it gets its own block and
    # states the blockers rather than only the recommendation.
    if close_ok:
        reason = close_reason or "closure recommended"
        conf = f" ({close_conf} confidence)" if close_conf else ""
        html += _section("Closure", f"<b style='color:#81c784;'>{reason}</b>{conf}", "#2e7d32")
    elif blockers:
        items = "".join(
            f"<div style='margin:2px 0;color:#ffcc80;'>&bull; {b}</div>" for b in blockers
        )
        html += _section("Before this can close", items, "#e65100")

    if truncated:
        html += _section(
            "Note",
            "The model's reply was cut off by the output token limit; this is the part that survived.",
            "#455a64",
        )

    if case_verdict:
        case_html = _badge(str(case_verdict).upper(), VERDICT_COLOR.get(str(case_verdict).lower(), "#555"))
        if case_story:
            first = _as_list(case_story)[:1]
            if first:
                case_html += f"<div style='margin-top:6px;'>{first[0]}</div>"
        case_html += (
            "<div style='margin-top:6px;color:#888;font-size:11px;'>"
            "The case verdict sees what a single issue cannot. Where the two differ, act on this one."
            "</div>"
        )
        html += _section("Case verdict", case_html, "#6a1b9a")

    html += "</div>"
    demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
