"""Render the case analysis verdict in the case layout.

Reads SOCFramework.Analysis.AI - the same contract the containment phase
consumes - rather than a parallel copy, so the analyst sees exactly what the
framework will act on.

Layouts render HTML, unlike the War Room.
"""
import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

_MSG = "<div style='color:#888;font-style:italic;padding:8px;'>{}</div>"

# Absent and empty are different states and must not read the same. A case the
# JOB never selected is not the same as one the model could not reason about,
# and an analyst waiting on the first will wait forever on the second.
NOT_RUN = _MSG.format(
    "Case analysis has not run on this case yet. It runs once the case settles "
    "and meets the selection thresholds."
)
NO_VERDICT = _MSG.format(
    "Case analysis ran but produced no verdict. The case is queued for another "
    "attempt; nothing was published."
)

VERDICT_COLOR = {
    "malicious": "#c62828",
    "suspicious": "#e65100",
    "benign": "#2e7d32",
    "inconclusive": "#455a64",
}

CONFIDENCE_MARK = {"high": "●●●", "medium": "●●○", "low": "●○○"}


def esc(value):
    """Contract values include attacker-controlled strings - process names,
    file paths, email subjects. None of it may reach the layout as markup."""
    return (str(value)
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def read_contract():
    ctx = demisto.context() or {}
    node = (ctx.get("SOCFramework") or {}).get("Analysis") or {}
    ai = node.get("AI")
    if isinstance(ai, list):
        ai = ai[-1] if ai else None
    if isinstance(ai, str):
        try:
            ai = json.loads(ai)
        except Exception:
            return None
    return ai if isinstance(ai, dict) else None


def badge(verdict, confidence):
    colour = VERDICT_COLOR.get(str(verdict).lower(), "#455a64")
    mark = CONFIDENCE_MARK.get(str(confidence).lower(), "")
    return (
        "<div style='display:flex;align-items:center;gap:12px;"
        "padding:10px 12px;border-left:4px solid {c};background:#fafafa;'>"
        "<span style='font-size:17px;font-weight:600;color:{c};"
        "text-transform:uppercase;letter-spacing:.5px;'>{v}</span>"
        "<span style='color:#666;font-size:13px;'>{m} {conf} confidence</span>"
        "</div>"
    ).format(c=colour, v=esc(verdict or "unknown"), m=mark,
             conf=esc(confidence or "unknown"))


def facts(ai):
    rows = [
        ("Compromise", ai.get("compromise_level")),
        ("Spread", ai.get("spread_level")),
        ("Primary entity", "{} ({})".format(
            ai.get("primary_entity_name") or "unknown",
            ai.get("primary_entity_type") or "?")),
        ("MITRE", "{} {} / {} {}".format(
            ai.get("mitre_tactic") or "", ai.get("mitre_tactic_id") or "",
            ai.get("mitre_technique") or "", ai.get("mitre_technique_id") or "")),
        ("Category", ai.get("case_category")),
        ("Response recommended",
         "yes" if ai.get("response_recommended") in (True, "true", "True") else "no"),
        ("Action confidence", ai.get("action_confidence")),
        ("Analysed", ai.get("analysed_at")),
    ]
    cells = "".join(
        "<tr><td style='padding:4px 14px 4px 0;color:#777;white-space:nowrap;"
        "vertical-align:top;'>{k}</td>"
        "<td style='padding:4px 0;'>{v}</td></tr>".format(k=esc(k), v=esc(v))
        for k, v in rows if str(v or "").strip() not in ("", "/", "  / "))
    return ("<table style='font-size:13px;border-collapse:collapse;"
            "margin:12px 0 4px 2px;'>{}</table>".format(cells))


def story_block(ai):
    story = ai.get("story") or []
    if isinstance(story, str):
        try:
            story = json.loads(story)
        except Exception:
            story = [story]
    if not story:
        return ""
    items = "".join(
        "<li style='margin:0 0 7px 0;line-height:1.45;'>{}</li>".format(esc(s))
        for s in story)
    return ("<div style='margin-top:14px;'>"
            "<div style='font-weight:600;font-size:12px;color:#555;"
            "text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px;'>"
            "Reasoning</div>"
            "<ol style='margin:0;padding-left:20px;font-size:13px;'>{}</ol>"
            "</div>".format(items))


def closure_block(ai):
    """What a human would have to verify before this case could close.

    Shown even when empty, because an empty blocker list is an assertion that
    nothing is left to check - that is a claim worth seeing, not a blank space.
    """
    blockers = ai.get("closure_blockers") or []
    if isinstance(blockers, str):
        try:
            blockers = json.loads(blockers)
        except Exception:
            blockers = [blockers]
    recommended = ai.get("closure_recommended") in (True, "true", "True")
    if not blockers:
        body = ("<div style='font-size:13px;color:#2e7d32;'>No outstanding "
                "checks recorded.</div>" if recommended else
                "<div style='font-size:13px;color:#777;'>None recorded.</div>")
    else:
        body = ("<ul style='margin:0;padding-left:20px;font-size:13px;'>{}</ul>"
                .format("".join(
                    "<li style='margin:0 0 5px 0;'>{}</li>".format(esc(b))
                    for b in blockers)))
    return ("<div style='margin-top:14px;'>"
            "<div style='font-weight:600;font-size:12px;color:#555;"
            "text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px;'>"
            "Before closing</div>{}</div>".format(body))


def main():
    ai = read_contract()
    if ai is None:
        return_results({"ContentsFormat": formats["html"],
                        "Type": entryTypes["note"], "Contents": NOT_RUN})
        return
    verdict = str(ai.get("verdict") or "").strip()
    if not verdict:
        return_results({"ContentsFormat": formats["html"],
                        "Type": entryTypes["note"], "Contents": NO_VERDICT})
        return

    html = ("<div style='font-family:-apple-system,Segoe UI,Roboto,sans-serif;'>"
            + badge(verdict, ai.get("confidence"))
            + facts(ai) + story_block(ai) + closure_block(ai) + "</div>")
    return_results({"ContentsFormat": formats["html"],
                    "Type": entryTypes["note"], "Contents": html})


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
