import demistomock as demisto
from CommonServerPython import *


PENDING = "<div style='color:#888;font-style:italic;padding:8px;'>Recovery phase pending Eradication...</div>"


def _get(ctx, path):
    val = demisto.get(ctx, path)
    if isinstance(val, list):
        val = val[0] if val else None
    return val if val not in (None, "", [], {}) else None


def _section(title, content, border_color="#2e7d32"):
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


def main():
    ctx = demisto.context()

    story = _get(ctx, "Recovery.story")
    systems = _get(ctx, "Recovery.SystemsRestored")
    accounts = _get(ctx, "Recovery.AccountsRestored")
    validation = _get(ctx, "Recovery.ValidationStatus")
    monitoring = _get(ctx, "Recovery.monitoring_required")
    actions = _get(ctx, "Recovery.actions")

    if not story:
        demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": PENDING})
        return

    html = "<div style='padding:4px;'>"

    # Validation status badge
    if validation:
        v = str(validation).lower()
        if "success" in v or "clean" in v or "validated" in v:
            color, icon = "#2e7d32", "&#9989;"
        elif "fail" in v or "detected" in v:
            color, icon = "#c62828", "&#10060;"
        else:
            color, icon = "#37474f", "&#8987;"
        html += (
            f"<div style='margin-bottom:12px;background:{color}22;border:1px solid {color};"
            f"border-radius:4px;padding:8px;color:#ddd;font-size:12px;'>"
            f"{icon} <b>Validation:</b> {validation}</div>"
        )

    if story:
        html += _section("Recovery Status", str(story).replace("\n", "<br>"))

    restore_parts = []
    if systems:
        restore_parts.append(f"<b>Systems Restored:</b><br>{_list_items(systems)}")
    if accounts:
        restore_parts.append(f"<b>Accounts Restored:</b><br>{_list_items(accounts)}")
    if actions:
        restore_parts.append(f"<b>Actions Taken:</b><br>{_list_items(actions)}")
    if restore_parts:
        html += _section("Restoration Actions", "<br><br>".join(restore_parts))

    if monitoring and str(monitoring).lower() in ("true", "1", "yes"):
        html += _section("Post-Recovery",
            "<span style='color:#ffb74d;'>&#9432; Continued monitoring recommended.</span>",
            "#e65100")

    html += "</div>"
    demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
