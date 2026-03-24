import demistomock as demisto
from CommonServerPython import *


PENDING = "<div style='color:#888;font-style:italic;padding:8px;'>Containment phase pending Analysis verdict...</div>"


def _get(ctx, path):
    val = demisto.get(ctx, path)
    if isinstance(val, list):
        val = val[0] if val else None
    return val if val not in (None, "", [], {}) else None


def _section(title, content, border_color="#f57c00"):
    return (
        f"<div style='margin-bottom:12px;border-left:3px solid {border_color};"
        f"padding-left:10px;'>"
        f"<div style='font-size:10px;color:#888;text-transform:uppercase;"
        f"letter-spacing:1px;margin-bottom:4px;'>{title}</div>"
        f"<div style='color:#ddd;font-size:12px;line-height:1.5;'>{content}</div>"
        f"</div>"
    )


def _list_items(val):
    if not val:
        return ""
    if isinstance(val, str):
        items = [i.strip() for i in val.replace(";", ",").split(",") if i.strip()]
    elif isinstance(val, list):
        items = [str(i) for i in val if i]
    else:
        return str(val)
    return "<br>".join(f"&bull; {i}" for i in items)


def _shadow_banner(shadow_mode):
    if str(shadow_mode).lower() in ("true", "1", "shadow"):
        return (
            "<div style='background:#1a1a00;border:1px solid #f9a825;border-radius:4px;"
            "padding:8px;margin-bottom:12px;color:#f9a825;font-size:11px;'>"
            "&#9888; <b>SHADOW MODE</b> — Actions logged only. No vendor commands executed. "
            "Flip shadow_mode to false in SOCFrameworkActions_V3 to go live."
            "</div>"
        )
    return (
        "<div style='background:#0a1f0a;border:1px solid #2e7d32;border-radius:4px;"
        "padding:8px;margin-bottom:12px;color:#66bb6a;font-size:11px;'>"
        "&#9989; <b>LIVE MODE</b> — Containment actions executed."
        "</div>"
    )


def main():
    ctx = demisto.context()

    story = _get(ctx, "Containment.story")
    action = _get(ctx, "Containment.action")
    required = _get(ctx, "Containment.required")
    endpoints = _get(ctx, "Containment.EndpointsIsolated")
    users = _get(ctx, "Containment.UsersDisabled")
    indicators = _get(ctx, "Containment.IndicatorsBlocked")
    shadow = _get(ctx, "SOCFramework.shadow_mode")

    if not story and action is None:
        demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": PENDING})
        return

    html = "<div style='padding:4px;'>"

    if shadow is not None:
        html += _shadow_banner(shadow)

    if story:
        html += _section("What Happened", str(story).replace("\n", "<br>"))

    action_items = []
    if endpoints:
        action_items.append(f"<b>Hosts Isolated:</b><br>{_list_items(endpoints)}")
    if users:
        action_items.append(f"<b>Users Disabled:</b><br>{_list_items(users)}")
    if indicators:
        action_items.append(f"<b>Indicators Blocked:</b><br>{_list_items(indicators)}")

    if action_items:
        html += _section("Containment Actions", "<br><br>".join(action_items), "#ef6c00")
    elif required is not None:
        req_str = str(required).lower()
        if req_str in ("false", "0", "no"):
            html += _section("Containment Decision",
                "<span style='color:#66bb6a;'>Not required — verdict threshold not met.</span>",
                "#2e7d32")

    html += "</div>"
    demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
