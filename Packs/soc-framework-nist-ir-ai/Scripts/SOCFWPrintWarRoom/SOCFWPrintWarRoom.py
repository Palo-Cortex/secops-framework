"""Layout button handler. Exports the case War Room to a markdown file.

The War Room is already the complete record of what the SOC did - who acted,
when, through which vendor command, and what came back. What it is not is
portable: it lives behind a tenant login and truncates on screen. This renders
it to a file an analyst can hand to legal, who print it to PDF themselves.

Deliberately lifecycle-agnostic and read-only. It reads entries and writes a
file. It executes nothing, so there is no Shadow Mode gate on it and no
SOCCommandWrapper call - printing a record is not an action against the
environment.

Shadow Mode does matter for what the file SAYS. During a PoV every C/E/R action
is simulated, and a record that renders those as actions taken is a document
asserting containment that never happened. Rather than infer the tenant's mode,
this counts the wrapper's own shadow markers in the entries and banners the file
accordingly. The evidence for the banner is the same evidence the reader sees.
"""

import json
import re
from datetime import datetime, timezone

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

# The string SOCCommandWrapper writes when it declines to call the vendor. If
# the wrapper's wording changes this banner goes quiet, so it is matched loosely
# on the two words that carry the meaning rather than the full sentence.
SHADOW_MARKER = re.compile(r"shadow\s+mode", re.IGNORECASE)
EXECUTED_MARKER = re.compile(r"execution_mode['\"\s:=]+production", re.IGNORECASE)

PAGE_SIZE = 200
MAX_PAGES = 50          # 10,000 entries. Past this the case is not a document.
MAX_ENTRY_CHARS = 20000  # Per entry. Anything larger is a payload dump.

# Entry type -> label. XSOAR/XSIAM numeric entry types; unknown types fall
# through to the raw number rather than being dropped, because an unlabelled
# entry in a legal record is better than a missing one.
ENTRY_TYPES = {
    1: "note",
    2: "download",
    3: "file",
    4: "error",
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


def fetch_entries(case_id):
    """Return every War Room entry for the case, oldest first.

    Paginated because the API caps a page and a worked case runs to hundreds of
    entries. Returns the entries plus a note when the page cap was hit, so the
    file can say it is partial instead of quietly being partial.
    """
    inv = f"INCIDENT-{case_id}"
    entries = []
    truncated = None
    for page in range(MAX_PAGES):
        res = unwrap(api(f"/xsoar/public/v1/investigation/{inv}",
                         {"pageSize": PAGE_SIZE, "page": page}))
        batch = (demisto.get(res, "Contents.response.entries")
                 or demisto.get(res, "response.entries") or [])
        if not batch:
            break
        entries.extend(batch)
        if len(batch) < PAGE_SIZE:
            break
    else:
        truncated = (f"Entry cap reached: only the first {MAX_PAGES * PAGE_SIZE} "
                     f"entries were retrieved. This export is incomplete.")

    entries.sort(key=lambda e: e.get("created") or "")
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
                  f"The full text is in the War Room on the case.]"), True
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


def plural(n, one, many):
    return f"{n} {one if n == 1 else many}"


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


def header(inc, entries, shadow_count, executed_count, truncated):
    """The cover block. Everything a reader needs to place the document."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    opened = ts(inc.get("created"))
    closed = ts(inc.get("closed")) if inc.get("closed") else "not closed"

    lines = [
        f"# War Room Record - Case {inc.get('id')}",
        "",
        f"**{inc.get('name') or '(unnamed case)'}**",
        "",
        "| | |",
        "|---|---|",
        f"| Case ID | {inc.get('id')} |",
        f"| Severity | {inc.get('severity')} |",
        f"| Status | {inc.get('status')} |",
        f"| Owner | {inc.get('owner') or 'unassigned'} |",
        f"| Opened | {opened} |",
        f"| Closed | {closed} |",
        f"| Entries | {len(entries)} |",
        f"| Exported | {now} |",
        f"| Exported by | {current_user()} |",
        "",
        "This is a verbatim export of the War Room for the case above, in the "
        "order events were recorded. Nothing has been summarised, reordered, or "
        "removed except where an omission is stated inline.",
        "",
    ]

    if truncated:
        lines += [f"> **INCOMPLETE EXPORT.** {truncated}", ""]

    if shadow_count:
        lines += [
            "> ## SIMULATED RESPONSE - NOT A RECORD OF ACTIONS TAKEN",
            ">",
            f"> {plural(shadow_count, 'entry', 'entries')} in this record "
            f"{'carries' if shadow_count == 1 else 'carry'} the platform's "
            "Shadow Mode marker. Shadow Mode means the response action was "
            "evaluated and logged but **the vendor command was never sent** - "
            "no host was isolated, no account was disabled, no file was "
            "removed.",
            ">",
            "> Entries so marked describe what the platform would have done. "
            "They must not be read, cited, or forwarded as evidence that the "
            "action occurred."
            + (f" {plural(executed_count, 'entry', 'entries')} in this record "
               f"{'is' if executed_count == 1 else 'are'} marked as executed "
               "against production; those are actions actually taken."
               if executed_count else
               " No entry in this record is marked as executed against "
               "production."),
            "",
        ]

    lines += ["---", ""]
    return lines


def render(inc, entries, truncated):
    shadow_count = 0
    executed_count = 0
    body = []

    for i, e in enumerate(entries, 1):
        text, cut = entry_text(e)
        if SHADOW_MARKER.search(text):
            shadow_count += 1
        elif EXECUTED_MARKER.search(text):
            executed_count += 1

        kind = ENTRY_TYPES.get(e.get("type"), f"type {e.get('type')}")
        who = e.get("user") or e.get("modified_by") or "system"
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

    return "\n".join(header(inc, entries, shadow_count, executed_count, truncated)
                     + body), shadow_count


def main():
    try:
        inc = demisto.incident() or {}
        case_id = inc.get("id")
        if not case_id:
            return_results(CommandResults(readable_output=(
                "⚫ **Print War Room** - no case in scope.\n\n"
                "This script reads the War Room of the case it is run from. Run "
                "it from the button on a case layout, not from the Playground.")))
            return

        entries, truncated = fetch_entries(case_id)
        if not entries:
            return_results(CommandResults(readable_output=(
                f"⚫ **Print War Room** - case {case_id} returned no entries.\n\n"
                "The case exists but the investigation read came back empty. "
                "Check that the Core REST API integration instance is enabled "
                "and its API key carries investigation read access.")))
            return

        content, shadow_count = render(inc, entries, truncated)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"WarRoom_Case-{case_id}_{stamp}.md"

        note = (f"✅ **Print War Room** - {len(entries)} entries exported to "
                f"`{filename}`, attached to this case.\n\n"
                "Open the attachment and print to PDF from your browser or "
                "editor.")
        if shadow_count:
            note += (f"\n\n🟠 **{shadow_count} Shadow Mode entr"
                     f"{'y' if shadow_count == 1 else 'ies'}** — the export is "
                     "bannered as a simulation. Response actions in it were "
                     "logged, not executed.")
        if truncated:
            note += f"\n\n🟠 {truncated}"

        demisto.results(fileResult(filename, content.encode("utf-8")))
        return_results(CommandResults(readable_output=note))

    except Exception as e:
        return_error(f"SOCFWPrintWarRoom failed: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
