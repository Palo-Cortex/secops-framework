"""Decide whether an issue should be closed without an assessment.

Some issues do not need a verdict to be closed: the tenant has already said what
they are. This script runs before anything is collected for the assessment,
checks the issue against the reasons the tenant has set with
!SOCFWConfig command=close, and tells the entry playbook whether to close it.

It only decides. The close itself is the playbook's last step, the action
soc-close-issue-unassessed, which ships in shadow: until a tenant turns it on
the close is recorded and the issue stays open. The case is never closed.

Reasons
  report_mailbox  Mail delivered to an abuse/report mailbox the tenant listed
                  (close.report_mailboxes). Every recipient must be listed, and a
                  permitted click is always assessed.

Each reason is one function in REASONS and takes its setting from the tenant's
'close' section. A reason with nothing set is off. Adding one is a function here
and an argument on SOCFWConfig command=close; the playbook does not change.

Anything else, including a failure in this script, leaves
SOCFramework.CloseWithoutAssessment unset and the playbook goes on to the
assessment as it always has. With nothing set the script writes nothing at all.
"""

import json
import re
from datetime import datetime, timezone

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

TENANT_CONFIG_LIST = "SOCFWTenantConfig"
SECTION = "close"
CONTEXT_KEY = "SOCFramework.CloseWithoutAssessment"
CLOSE_ACTION = "soc-close-issue-unassessed"
RECIPIENT_KEYS = ("SOCFramework.Email.recipient", "SOCFramework.Artifacts.Email.To")
CLICK_KEYS = ("SOCFramework.Email.click_time", "SOCFramework.Email.click_ip")
ADDRESS = re.compile(r"[\w.%+-]+@[\w-]+(?:\.[\w-]+)+")
ABSENT = (None, "", [], {}, "None", "null")


def close_settings():
    """The tenant's 'close' section, or {} when there is none or the list is unreadable."""
    res = demisto.executeCommand("getList", {"listName": TENANT_CONFIG_LIST})
    entry = res[0] if isinstance(res, list) and res and isinstance(res[0], dict) else {}
    raw = entry.get("Contents")
    if entry.get("Type") == 4 or not raw:
        return {}
    try:
        doc = raw if isinstance(raw, dict) else json.loads(raw)
    except (ValueError, TypeError):
        return {}
    section = doc.get(SECTION) if isinstance(doc, dict) else None
    return section if isinstance(section, dict) else {}


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


def report_mailbox(ctx, settings):
    """Mail delivered to a listed report mailbox closes; a click to one is assessed."""
    listed = settings.get("report_mailboxes")
    if not isinstance(listed, list):
        return None
    listed = {str(m).strip().lower() for m in listed if str(m).strip()}
    to = recipients(ctx)
    if not listed or not to or not to <= listed:
        return None
    who = ", ".join(sorted(to))
    if any(demisto.get(ctx, key) not in ABSENT for key in CLICK_KEYS):
        return {"close": False, "status": "assessed_click", "subject": who,
                "note": f"Recipient {who} is a report mailbox, but the issue carries a click"}
    return {"close": True, "status": "close", "subject": who,
            "note": f"Recipient {who} is a report mailbox on this tenant"}


# name -> check(ctx, settings). A check returns None when its reason does not apply,
# otherwise {"close": bool, "status": str, "subject": str, "note": str}. The first
# reason that applies decides.
REASONS = (("report_mailbox", report_mailbox),)


def decide(ctx, settings):
    """(reason, decision) for the first reason that applies, or (None, None)."""
    for name, check in REASONS:
        decision = check(ctx, settings)
        if decision:
            return name, decision
    return None, None


def case_id(incident):
    value = (incident or {}).get("parentXDRIncident")
    if value in ABSENT:
        return None
    cid = str(value).strip()
    if cid.upper().startswith("INCIDENT-"):
        cid = cid.split("-", 1)[1].strip()
    return cid if cid.isdigit() else None


def record(reason, decision, incident, ctx):
    """One close_without_assessment row. No phase, so the value dashboards do not pick it up."""
    cid = case_id(incident)
    row = {"event_type": "close_without_assessment", "reason": reason, "status": decision["status"],
           "incident_id": str((incident or {}).get("id") or ""),
           "subject": decision.get("subject"),
           "lifecycle": demisto.get(ctx, "SOCFramework.lifecycle"),
           "decided_at": datetime.now(timezone.utc).isoformat()}
    if cid:
        row.update({"case_id": cid, "parent_xdr_incident": cid})
    row = {k: v for k, v in row.items() if v not in ABSENT}
    try:
        demisto.executeCommand("socfw-post-to-dataset",
                               {"using": "socfw_ir_execution_writer", "JSON": json.dumps(row)})
    except Exception as e:  # noqa: BLE001 - the record must never change the decision
        demisto.debug(f"SOCFWCloseWithoutAssessment: close_without_assessment row not written: {e}")


def close_note(reason, decision, settings):
    """The note the close carries: what matched, then the tenant's own comment if it set one."""
    note = (f"Closed by SOC Framework without assessment ({reason}): {decision['note']} "
            "(SOCFWConfig command=close).")
    comment = settings.get("comment")
    if isinstance(comment, str) and comment.strip():
        note += " " + comment.strip()
    return note


def main():
    try:
        settings = close_settings()
        if not settings:
            return_results(CommandResults(readable_output=""))
            return
        ctx = demisto.context() or {}
        reason, decision = decide(ctx, settings)
    except Exception as e:  # noqa: BLE001 - on any doubt the issue is assessed
        demisto.debug(f"SOCFWCloseWithoutAssessment: check failed, the issue is assessed: {e}")
        return_results(CommandResults(readable_output=""))
        return

    if not decision:
        return_results(CommandResults(readable_output=""))
        return

    record(reason, decision, demisto.incident(), ctx)
    if not decision["close"]:
        return_results(CommandResults(readable_output=f"{decision['note']}: assessed as usual."))
        return

    demisto.setContext(CONTEXT_KEY, {"close": "true", "reason": reason,
                                     "note": close_note(reason, decision, settings)})
    return_results(CommandResults(
        readable_output=f"{decision['note']}: not assessed. The playbook closes the issue with "
                        f"{CLOSE_ACTION}; whether it actually closes depends on shadow mode for "
                        "that action."))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
