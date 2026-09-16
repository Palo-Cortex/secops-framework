"""Layout button handler. Exports the issue War Room to a markdown file.

The War Room is already the complete record of what the SOC did - who acted,
when, through which vendor command, and what came back. What it is not is
portable: it lives behind a tenant login and truncates on screen. This renders
it to a file an analyst can hand to legal, who print it to PDF themselves.

Scope is the issue the button was pressed on, not the case it belongs to.

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

import json
import re
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


def fence(text):
    """Wrap in a code fence long enough to survive backticks in the content."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    bar = "`" * max(3, longest + 1)
    return f"{bar}\n{text}\n{bar}"


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


def header(inc, entries, truncated):
    """The cover block. Everything a reader needs to place the document."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    opened = ts(inc.get("created"))
    closed = ts(inc.get("closed")) if inc.get("closed") else "not closed"

    lines = [
        f"# War Room Record - Issue {inc.get('id')}",
        "",
        f"**{inc.get('name') or '(unnamed issue)'}**",
        "",
        "| | |",
        "|---|---|",
        f"| Issue ID | {inc.get('id')} |",
        f"| Severity | {inc.get('severity')} |",
        f"| Status | {inc.get('status')} |",
        f"| Owner | {inc.get('owner') or 'unassigned'} |",
        f"| Opened | {opened} |",
        f"| Closed | {closed} |",
        f"| Entries | {len(entries)} |",
        f"| Exported | {now} |",
        f"| Exported by | {current_user()} |",
        "",
        "This is a verbatim export of the War Room for the issue above, in the "
        "order events were recorded. Nothing has been summarised, reordered, or "
        "removed except where an omission is stated inline.",
        "",
    ]

    if truncated:
        lines += [f"> **INCOMPLETE EXPORT.** {truncated}", ""]


    lines += ["---", ""]
    return lines


def render(inc, entries, truncated):
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
        tags = e.get("tags") or []

        body.append(f"### {i}. {ts(e.get('created'))} - {who} ({kind})")
        if tags:
            body.append(f"*tags: {', '.join(str(t) for t in tags)}*")
        body.append("")
        body.append(fence(text) if text else "*(empty entry)*")
        if cut:
            body.append("")
            body.append("> This entry was truncated for length. See note above.")
        body.append("")

    return "\n".join(header(inc, entries, truncated) + body)


def main():
    try:
        inc = demisto.incident() or {}
        issue_id = inc.get("id")
        if not issue_id:
            return_results(CommandResults(readable_output=(
                "⚫ **Print War Room** - no issue in scope.\n\n"
                "This script reads the War Room of the issue it is run from. Run "
                "it from the button on an issue layout, not from the Playground.")))
            return

        entries, truncated = fetch_entries(issue_id)
        if not entries:
            return_results(CommandResults(readable_output=(
                f"⚫ **Print War Room** - issue {issue_id} returned no "
                "entries.\n\n"
                "The investigation read succeeded but carried no entries, so "
                "nothing was written - this is not an empty export, it is no "
                "export. Check that the Core REST API integration instance is "
                "enabled and that its API key carries investigation read "
                "access.")))
            return

        content = render(inc, entries, truncated)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"WarRoom_Issue-{issue_id}_{stamp}.md"

        note = (f"✅ **Print War Room** - {len(entries)} entries exported to "
                f"`{filename}`, attached to this issue.\n\n"
                "Open the attachment and print to PDF from your browser or "
                "editor.")
        if truncated:
            note += f"\n\n🟠 {truncated}"

        demisto.results(fileResult(filename, content.encode("utf-8")))
        return_results(CommandResults(readable_output=note))

    except Exception as e:
        return_error(f"SOCFWPrintWarRoom failed: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
