"""Close mail sent to an abuse/report mailbox at the issue, before anything is spent on it.

A tenant lists its report mailboxes with !SOCFWConfig command=mailboxes. Mail
delivered to one of them is an employee forwarding something suspicious, not a
user at risk, so the entry playbook skips the assessment for it and this script
asks the Universal Command to close that one issue with a note saying why.

The close is the action soc-close-issue-report-mailbox. It ships in shadow, so
until a tenant turns it on the close is recorded and the issue stays open. The
case is never closed.

Acts only when all three hold:
  - the tenant has listed at least one report mailbox
  - every recipient on the issue is a listed mailbox
  - the issue carries no click (a permitted click is always assessed)

Anything else, including a failure in this script, leaves SOCFramework.ReportMailbox.skip
unset and the playbook goes on to the assessment as it always has. With an empty
list the script writes nothing at all.
"""

import json
import re
from datetime import datetime, timezone

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

TENANT_CONFIG_LIST = "SOCFWTenantConfig"
MAILBOXES_KEY = "report_mailboxes"
SKIP_KEY = "SOCFramework.ReportMailbox.skip"
NOTES_KEY = "SOCFramework.ReportMailbox.close_notes"
CLOSE_ACTION = "soc-close-issue-report-mailbox"
ACTOR = "automation"
RECIPIENT_KEYS = ("SOCFramework.Email.recipient", "SOCFramework.Artifacts.Email.To")
CLICK_KEYS = ("SOCFramework.Email.click_time", "SOCFramework.Email.click_ip")
ADDRESS = re.compile(r"[\w.%+-]+@[\w-]+(?:\.[\w-]+)+")
ABSENT = (None, "", [], {}, "None", "null")


def report_mailboxes():
    """The tenant's listed mailboxes, lower-cased. Empty when none are set or the list is unreadable."""
    res = demisto.executeCommand("getList", {"listName": TENANT_CONFIG_LIST})
    entry = res[0] if isinstance(res, list) and res and isinstance(res[0], dict) else {}
    raw = entry.get("Contents")
    if entry.get("Type") == 4 or not raw:
        return set()
    try:
        doc = raw if isinstance(raw, dict) else json.loads(raw)
    except (ValueError, TypeError):
        return set()
    listed = doc.get(MAILBOXES_KEY) if isinstance(doc, dict) else None
    if not isinstance(listed, list):
        return set()
    return {str(m).strip().lower() for m in listed if str(m).strip()}


def recipients(ctx):
    """Every address on the issue's normalized recipient, lower-cased."""
    for key in RECIPIENT_KEYS:
        value = demisto.get(ctx, key)
        if value in ABSENT:
            continue
        text = " ".join(str(v) for v in value) if isinstance(value, list) else str(value)
        found = {a.lower() for a in ADDRESS.findall(text)}
        if found:
            return found
    return set()


def has_click(ctx):
    return any(demisto.get(ctx, key) not in ABSENT for key in CLICK_KEYS)


def decide(listed, to, click):
    """not_assessed, assessed_click, or None when the recipient is not a report mailbox."""
    if not listed or not to or not to <= listed:
        return None
    return "assessed_click" if click else "not_assessed"


def case_id(incident):
    value = (incident or {}).get("parentXDRIncident")
    if value in ABSENT:
        return None
    cid = str(value).strip()
    if cid.upper().startswith("INCIDENT-"):
        cid = cid.split("-", 1)[1].strip()
    return cid if cid.isdigit() else None


def record(status, incident, ctx, to):
    """One report_mailbox_decision row. No phase, so the value dashboards do not pick it up."""
    cid = case_id(incident)
    row = {"event_type": "report_mailbox_decision", "status": status,
           "incident_id": str((incident or {}).get("id") or ""),
           "recipient": ", ".join(sorted(to)),
           "lifecycle": demisto.get(ctx, "SOCFramework.lifecycle"),
           "decided_at": datetime.now(timezone.utc).isoformat()}
    if cid:
        row.update({"case_id": cid, "parent_xdr_incident": cid})
    row = {k: v for k, v in row.items() if v not in ABSENT}
    try:
        demisto.executeCommand("socfw-post-to-dataset",
                               {"using": "socfw_ir_execution_writer", "JSON": json.dumps(row)})
    except Exception as e:  # noqa: BLE001 - the record must never change the decision
        demisto.debug(f"SOCFWReportMailboxCheck: report_mailbox_decision row not written: {e}")


def close_issue(ctx, to):
    """Ask the Universal Command to close this issue. Shadow mode on the action decides whether it does.

    A wrapper that cannot be called leaves the issue open and nothing else changes.
    """
    demisto.setContext(NOTES_KEY, (
        f"Closed by SOC Framework: recipient {', '.join(sorted(to))} is a report mailbox on this "
        "tenant (SOCFWConfig command=mailboxes). Mail to a report mailbox is not assessed."))
    args = {"action": CLOSE_ACTION, "Phase": "triage", "Action_Actor": ACTOR}
    lifecycle = demisto.get(ctx, "SOCFramework.lifecycle")
    if lifecycle not in ABSENT:
        args["LifeCycle"] = lifecycle
    try:
        demisto.executeCommand("SOCCommandWrapper", args)
    except Exception as e:  # noqa: BLE001 - a failed close leaves the issue open, nothing more
        demisto.debug(f"SOCFWReportMailboxCheck: {CLOSE_ACTION} not dispatched: {e}")


def main():
    try:
        listed = report_mailboxes()
        if not listed:
            return_results(CommandResults(readable_output=""))
            return
        ctx = demisto.context() or {}
        to = recipients(ctx)
        status = decide(listed, to, has_click(ctx))
    except Exception as e:  # noqa: BLE001 - on any doubt the issue is assessed
        demisto.debug(f"SOCFWReportMailboxCheck: check failed, the issue is assessed: {e}")
        return_results(CommandResults(readable_output=""))
        return

    if status is None:
        return_results(CommandResults(readable_output=""))
        return

    record(status, demisto.incident(), ctx, to)
    if status == "assessed_click":
        return_results(CommandResults(
            readable_output=f"Recipient {', '.join(sorted(to))} is a report mailbox, but the issue "
                            "carries a click: assessed as usual."))
        return

    demisto.setContext(SKIP_KEY, "true")
    close_issue(ctx, to)
    return_results(CommandResults(
        readable_output=f"Recipient {', '.join(sorted(to))} is a report mailbox: not assessed. "
                        f"Close requested through {CLOSE_ACTION}; whether the issue closes depends "
                        "on shadow mode for that action."))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
