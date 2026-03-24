import demistomock as demisto
from CommonServerPython import *


PENDING = "<div style='color:#888;font-style:italic;padding:8px;'>Eradication phase pending Containment...</div>"


def _get(ctx, path):
    val = demisto.get(ctx, path)
    if isinstance(val, list):
        val = val[0] if val else None
    return val if val not in (None, "", [], {}) else None


def _section(title, content, border_color="#7b1fa2"):
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

    story = _get(ctx, "Eradication.story")
    attempted = _get(ctx, "Eradication.attempted")
    files = _get(ctx, "Eradication.FilesRemoved")
    persistence = _get(ctx, "Eradication.PersistenceRemoved")
    creds = _get(ctx, "Eradication.CredentialsReset")
    actions = _get(ctx, "Eradication.actions")

    if not story and attempted is None:
        demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": PENDING})
        return

    html = "<div style='padding:4px;'>"

    # Attempted status badge
    if attempted is not None:
        attempted_str = str(attempted).lower()
        if attempted_str in ("true", "1"):
            badge = "<span style='background:#6a1b9a;color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;'>EXECUTED</span>"
        else:
            badge = "<span style='background:#37474f;color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;'>NOT ATTEMPTED</span>"
        html += f"<div style='margin-bottom:12px;'>{badge}</div>"

    if story:
        html += _section("What Happened", str(story).replace("\n", "<br>"))

    cleanup_parts = []
    if files:
        cleanup_parts.append(f"<b>Files Removed:</b><br><span style='font-family:monospace;font-size:11px;color:#80cbc4;'>{_list_items(files)}</span>")
    if persistence:
        cleanup_parts.append(f"<b>Persistence Removed:</b><br>{_list_items(persistence)}")
    if creds:
        cleanup_parts.append(f"<b>Credentials Reset:</b><br>{_list_items(creds)}")
    if actions:
        cleanup_parts.append(f"<b>Actions Taken:</b><br>{_list_items(actions)}")

    if cleanup_parts:
        html += _section("Cleanup Actions", "<br><br>".join(cleanup_parts), "#6a1b9a")

    html += "</div>"
    demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
