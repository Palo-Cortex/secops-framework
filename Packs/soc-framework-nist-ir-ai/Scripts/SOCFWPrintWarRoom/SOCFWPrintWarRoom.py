"""Layout button handler. Exports the issue War Room to a printable HTML file.

The War Room is already the complete record of what the SOC did - who acted,
when, through which vendor command, and what came back. What it is not is
portable: it lives behind a tenant login and truncates on screen. This renders
it to a file an analyst opens in a browser and prints straight to PDF.

Scope is the issue the button was pressed on, not the case it belongs to.

HTML rather than markdown because the destination is paper. A browser gives
page breaks, repeating context and a print dialog for free; a .md file gives
none of that and renders as raw text in most things that open it.

The file is self-contained - CSS inline, no fonts, scripts, or images fetched
from anywhere. It opens the same on a machine with no network and nothing
installed, which is the machine it will eventually be read on.

Deliberately lifecycle-agnostic and read-only. It reads entries and writes a
file. It executes nothing, so there is no Shadow Mode gate on it and no
SOCCommandWrapper call - printing a record is not an action against the
environment.

The export is verbatim. Entries are reproduced as written, in the order they
were recorded, with nothing summarised, reordered or interpreted. Where the
platform logged that a command was not executed, that entry says so in its own
words and the reader sees it in place. This script adds no verdict of its own
on top of the record.
"""

import html
import json
from datetime import datetime, timezone

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

MAX_ENTRIES = 5000       # Past this the issue is not a document.
MAX_ENTRY_CHARS = 20000  # Per entry. Anything larger is a payload dump.

# Entry type -> label. XSOAR/XSIAM numeric entry types; unknown types fall
# through to the raw number rather than being dropped, because an unlabelled
# entry in a legal record is better than a missing one.
ENTRY_TYPES = {
    1: "note",
    2: "download",
    3: "file",
    4: "error",
    6: "chat",
    9: "pinned",
    11: "image",
    13: "playbook",
    14: "file",
    15: "widget",
    16: "warning",
    17: "map",
    20: "video",
}

# Print-first stylesheet. Black on white, no colour that costs anything in
# toner or meaning in greyscale. @page owns the margins so the browser's own
# header and footer do not collide with content.
CSS = """
@page { margin: 18mm 15mm; }
* { box-sizing: border-box; }
body {
  font: 11pt/1.45 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
  color: #111; background: #fff; margin: 0 auto; padding: 24px; max-width: 60em;
}
h1 { font-size: 17pt; margin: 0 0 2px; }
.subtitle { font-size: 12pt; font-weight: 600; margin: 0 0 16px; color: #333; }
table.meta { border-collapse: collapse; margin: 0 0 16px; font-size: 10pt; }
table.meta th, table.meta td {
  border: 1px solid #bbb; padding: 3px 10px; text-align: left; vertical-align: top;
}
table.meta th { background: #f2f2f2; font-weight: 600; white-space: nowrap; }
.statement { font-size: 10pt; color: #333; margin: 0 0 16px; }
.warn {
  border: 1.5px solid #111; padding: 8px 12px; margin: 0 0 16px; font-size: 10pt;
}
hr { border: 0; border-top: 1px solid #999; margin: 18px 0; }
.entry { margin: 0 0 14px; }
.entry h2 {
  font-size: 10.5pt; font-weight: 600; margin: 0 0 4px;
  padding-bottom: 2px; border-bottom: 1px solid #ddd;
  /* Never strand a heading at the foot of a page. */
  page-break-after: avoid; break-after: avoid;
}
.entry h2 .num { color: #666; margin-right: 4px; }
.entry h2 .kind { font-weight: 400; color: #666; }
.tags { font-size: 9pt; color: #666; margin: 0 0 4px; font-style: italic; }
pre {
  font: 9.5pt/1.4 "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  background: #f7f7f7; border: 1px solid #ddd; border-left: 3px solid #999;
  padding: 7px 10px; margin: 0;
  /* Long command lines and JSON must wrap, not run off the page edge. */
  white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word;
}
.empty { color: #666; font-style: italic; font-size: 10pt; margin: 0; }
.note { font-size: 9pt; color: #444; margin: 4px 0 0; }
footer {
  margin-top: 24px; padding-top: 8px; border-top: 1px solid #999;
  font-size: 9pt; color: #555;
}
@media print {
  body { padding: 0; max-width: none; }
  /* Keep short entries whole; long ones have to break somewhere. */
  .entry { page-break-inside: avoid; break-inside: avoid; }
  .entry.long { page-break-inside: auto; break-inside: auto; }
}
"""


def api(uri, body):
    """POST to the XSOAR API from inside a script via the Core REST API."""
    return demisto.executeCommand("core-api-post", {"uri": uri, "body": json.dumps(body)})


def unwrap(res):
    if isinstance(res, list):
        res = res[0] if res else {}
    if isinstance(res, dict) and is_error(res):
        raise DemistoException(get_error(res))
    return res


def fetch_entries(issue_id):
    """Return every War Room entry for the issue, oldest first.

    One unpaged read, deliberately. Verified against the platform: the
    investigation endpoint accepts `page` and then ignores it - every page
    returns the same window - so a paging loop yields duplicates rather than
    more entries. Asking with no paging arguments returns the whole set.

    The id goes in bare. Prefixing it with INCIDENT- or ISSUE- does not fail;
    it returns an empty investigation shell and creates that shell as a side
    effect, which reads as "this issue has no entries" when it has plenty.
    """
    res = unwrap(api(f"/xsoar/public/v1/investigation/{issue_id}", {}))
    entries = (demisto.get(res, "Contents.response.entries")
               or demisto.get(res, "Contents.entries")
               or demisto.get(res, "response.entries")
               or (res.get("entries") if isinstance(res, dict) else None)
               or [])

    entries.sort(key=lambda e: e.get("created") or "")

    truncated = None
    if len(entries) > MAX_ENTRIES:
        truncated = (f"Entry cap reached: this issue has {len(entries)} entries "
                     f"and only the first {MAX_ENTRIES} are included. This "
                     f"export is incomplete.")
        entries = entries[:MAX_ENTRIES]
    return entries, truncated


def entry_text(entry):
    """Return an entry's body as text, and whether it was truncated."""
    contents = entry.get("contents")
    if contents in (None, "", [], {}):
        contents = entry.get("readableContents") or ""
    if not isinstance(contents, str):
        try:
            contents = json.dumps(contents, indent=2, default=str)
        except Exception:
            contents = str(contents)
    contents = contents.strip()
    if len(contents) > MAX_ENTRY_CHARS:
        cut = len(contents) - MAX_ENTRY_CHARS
        return (contents[:MAX_ENTRY_CHARS]
                + f"\n\n[... {cut} characters omitted from this entry. "
                  f"The full text is in the War Room on the issue.]"), True
    return contents, False


def esc(value):
    """Escape for HTML text content.

    Entry bodies are full of angle brackets, ampersands and raw JSON. Anything
    unescaped either vanishes from the rendered page or corrupts the markup
    after it - in a document whose only job is to be complete, a silently
    dropped line is the worst possible failure.
    """
    return html.escape("" if value is None else str(value), quote=True)


def ts(value):
    """Render an XSOAR timestamp as UTC, or hand back whatever was there."""
    if not value:
        return "(no timestamp)"
    try:
        cleaned = str(value).replace("Z", "+00:00")
        return (datetime.fromisoformat(cleaned).astimezone(timezone.utc)
                .strftime("%Y-%m-%d %H:%M:%S UTC"))
    except Exception:
        return str(value)


def current_user():
    """Who pressed the button. Best effort - the export is valid without it."""
    try:
        res = unwrap(demisto.executeCommand("getUsers", {"current": "true"}))
        contents = res.get("Contents")
        if isinstance(contents, list) and contents:
            u = contents[0]
            return u.get("email") or u.get("username") or u.get("name") or "unknown"
    except Exception as e:
        demisto.debug(f"SOCFWPrintWarRoom: current user unreadable: {e}")
    return "unknown"


def header(inc, entries, truncated, exported_at, exported_by):
    """The cover block. Everything a reader needs to place the document."""
    rows = [
        ("Issue ID", inc.get("id")),
        ("Severity", inc.get("severity")),
        ("Status", inc.get("status")),
        ("Owner", inc.get("owner") or "unassigned"),
        ("Opened", ts(inc.get("created"))),
        ("Closed", ts(inc.get("closed")) if inc.get("closed") else "not closed"),
        ("Entries", len(entries)),
        ("Exported", exported_at),
        ("Exported by", exported_by),
    ]
    out = [
        "<h1>War Room Record</h1>",
        f"<p class=\"subtitle\">{esc(inc.get('name') or '(unnamed issue)')}</p>",
        "<table class=\"meta\">",
    ]
    out += [f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in rows]
    out += [
        "</table>",
        "<p class=\"statement\">This is a verbatim export of the War Room for "
        "the issue above, in the order events were recorded. Nothing has been "
        "summarised, reordered, or removed except where an omission is stated "
        "inline.</p>",
    ]
    if truncated:
        out.append(f"<div class=\"warn\"><strong>INCOMPLETE EXPORT.</strong> "
                   f"{esc(truncated)}</div>")
    out.append("<hr>")
    return out


def render(inc, entries, truncated):
    exported_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    exported_by = current_user()

    body = []
    for i, e in enumerate(entries, 1):
        text, cut = entry_text(e)

        kind = ENTRY_TYPES.get(e.get("type"), f"type {e.get('type')}")
        cat = e.get("category")
        if cat and cat not in kind:
            kind = f"{kind}, {cat}"

        # Most entries carry no user - they are the platform acting, not a
        # person. Naming the playbook and task that produced them is the
        # attribution a reader actually needs; "system" on forty lines is not.
        task = e.get("entryTask") or {}
        who = e.get("user") or e.get("modified_by")
        if not who:
            pb, tn = task.get("playbookName"), task.get("taskName")
            who = (f"{pb} / {tn}" if pb and tn else pb or tn or "automation")

        # Short entries are kept whole across a page break; tall ones cannot be
        # and are marked so the rule does not push a mostly-empty page.
        long_cls = " long" if text.count("\n") > 30 or len(text) > 2500 else ""

        body.append(f"<section class=\"entry{long_cls}\">")
        body.append(f"<h2><span class=\"num\">{i}.</span>{esc(ts(e.get('created')))}"
                    f" &mdash; {esc(who)} <span class=\"kind\">({esc(kind)})</span></h2>")
        tags = e.get("tags") or []
        if tags:
            body.append("<p class=\"tags\">tags: "
                        f"{esc(', '.join(str(t) for t in tags))}</p>")
        body.append(f"<pre>{esc(text)}</pre>" if text
                    else "<p class=\"empty\">(empty entry)</p>")
        if cut:
            body.append("<p class=\"note\">This entry was truncated for length. "
                        "See note above.</p>")
        body.append("</section>")

    title = f"War Room Record - Issue {inc.get('id')}"
    return "\n".join([
        "<!DOCTYPE html>",
        "<html lang=\"en\">",
        "<head>",
        "<meta charset=\"utf-8\">",
        f"<title>{esc(title)}</title>",
        f"<style>{CSS}</style>",
        "</head>",
        "<body>",
        *header(inc, entries, truncated, exported_at, exported_by),
        *body,
        f"<footer>{esc(title)} &mdash; {len(entries)} entries &mdash; "
        f"exported {esc(exported_at)} by {esc(exported_by)}.</footer>",
        "</body>",
        "</html>",
        "",
    ])


def main():
    try:
        inc = demisto.incident() or {}
        issue_id = inc.get("id")
        if not issue_id:
            return_results(CommandResults(readable_output=(
                "⚫ **Print War Room** - no issue in scope.\n\n"
                "This script reads the War Room of the issue it is run from. "
                "Run it from the button on an issue layout, not from the "
                "Playground.")))
            return

        entries, truncated = fetch_entries(issue_id)
        if not entries:
            return_results(CommandResults(readable_output=(
                f"⚫ **Print War Room** - issue {issue_id} returned no "
                "entries.\n\nThe investigation read succeeded but carried no "
                "entries, so nothing was written - this is not an empty "
                "export, it is no export. Check that the Core REST API "
                "integration instance is enabled and that its API key carries "
                "investigation read access.")))
            return

        content = render(inc, entries, truncated)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"WarRoom_Issue-{issue_id}_{stamp}.html"

        note = (f"✅ **Print War Room** - {len(entries)} entries exported to "
                f"`{filename}`, attached to this issue.\n\n"
                "Download it, open it in a browser, and print to PDF.")
        if truncated:
            note += f"\n\n🟠 {truncated}"

        demisto.results(fileResult(filename, content.encode("utf-8")))
        return_results(CommandResults(readable_output=note))

    except Exception as e:
        return_error(f"SOCFWPrintWarRoom failed: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
