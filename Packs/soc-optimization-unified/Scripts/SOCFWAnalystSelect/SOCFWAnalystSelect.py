"""Give unassigned cases an owner from whoever is on duty, least loaded first.

On duty is the socfw_on_duty lookup, kept current by SOCFWOnDutySync. Load is
each analyst's count of open assigned cases, read live from the cases API at
the start of the run and counted up as this run assigns, so one run spreads its
cases rather than handing them all to whoever started lowest.

Ranking today: least loaded, ties by email. A ranking step that weighs skill or
case category goes in rank(); everything around it stays the same.

Each assignment goes through the Universal Command as soc-assign-case, so shadow
mode decides whether it happens. Right before each one the case is read again,
and a case that gained an owner since the run started is left alone.

Each decision is recorded to the execution dataset as an analyst_assignment row,
with every on-duty analyst's load at that moment and no incident_id or phase,
so the value dashboards skip it.
"""

import json
import re
import time
from datetime import datetime, timezone

LOOKUP = "socfw_on_duty"
# Each assignment is a nested Universal Command call, several seconds apiece.
# No new case starts after this budget, which keeps a run inside the job's
# 5-minute schedule so runs do not overlap; cases left over go to the next run.
MAX_RUNTIME_SECONDS = 240
ACTION = "soc-assign-case"
KNOWN_DOMAINS = ("security", "posture", "health")
# How rank() orders the on-duty analysts. One method today.
METHODS = ("least_loaded",)
OPEN_STATUSES = ["New", "In Progress"]
PAGE = 100
EXECUTION_DATASET = "xsiam_socfw_ir_execution_raw"
# A case the framework assigned this recently is not assigned again. Covers two
# runs overlapping and the case search lagging behind a fresh assignment.
RECENT_MINUTES = 15
RECENT_REFRESH_SECONDS = 60
XQL_POLLS = 45
LOAD_MAX_PAGES = 50
MAX_PAGES = 10

DATASET_COMMAND = "socfw-post-to-dataset"
DATASET_INSTANCE = "socfw_ir_execution_writer"


class SelectError(Exception):
    pass


def _is_error(res):
    return any(isinstance(e, dict) and e.get("Type") == 4 for e in (res or []))


def _error_text(res):
    return "; ".join(str(e.get("Contents")) for e in (res or [])
                     if isinstance(e, dict) and e.get("Type") == 4)


def core_post(uri, body):
    res = demisto.executeCommand("core-api-post", {"uri": uri, "body": json.dumps(body)})
    if _is_error(res):
        return False, _error_text(res)
    for e in res or []:
        contents = e.get("Contents") if isinstance(e, dict) else None
        if isinstance(contents, dict) and "response" in contents:
            return True, contents["response"]
    return False, f"{uri} returned nothing readable"


def read_on_duty():
    """On-duty emails, or None when the lookup does not exist yet."""
    ok, resp = core_post("/public_api/v1/xql/lookups/get_data", {"request_data": {"dataset_name": LOOKUP}})
    if not ok:
        if "not found" in str(resp).lower():
            return None
        raise SelectError(f"could not read {LOOKUP}: {resp}")
    rows = ((resp or {}).get("reply") or {}).get("data") or []
    return sorted({str(r.get("email")).strip().lower() for r in rows if isinstance(r, dict) and r.get("email")})


def online_users():
    """Emails of users logged in to the tenant now, or None when that cannot be read."""
    try:
        res = demisto.executeCommand("getUsers", {"online": "true"})
    except Exception as e:  # noqa: BLE001
        demisto.debug(f"SOCFWAnalystSelect: getUsers online failed: {e}")
        return None
    if _is_error(res):
        return None
    emails = set()
    for e in res or []:
        contents = e.get("Contents") if isinstance(e, dict) else None
        for u in contents if isinstance(contents, list) else []:
            if isinstance(u, dict) and u.get("email"):
                emails.add(str(u["email"]).strip().lower())
    return emails


def recent_assignments(sleep=time.sleep):
    """Case ids the framework assigned in the last RECENT_MINUTES, from the execution dataset.

    Runs the query through the XQL API and polls for the result: the
    xdr-xql-generic-query command answers "still running" to a script and
    never returns rows. Returns (ids, None), or (set(), why) when the dataset
    cannot be read in time; the run then relies on the case recheck alone.
    """
    query = (f"dataset = {EXECUTION_DATASET}"
             ' | filter event_type = "analyst_assignment" and action_status = "assigned"'
             " | fields case_id | limit 1000")
    ok, resp = core_post("/public_api/v1/xql/start_xql_query", {"request_data": {
        "query": query, "timeframe": {"relativeTime": RECENT_MINUTES * 60 * 1000}}})
    query_id = (resp or {}).get("reply") if ok and isinstance(resp, dict) else None
    if not query_id:
        return set(), f"recent-assignment check failed to start: {str(resp)[:200]}"
    for _ in range(XQL_POLLS):
        ok, resp = core_post("/public_api/v1/xql/get_query_results", {"request_data": {
            "query_id": query_id, "pending_flag": True, "limit": 1000, "format": "json"}})
        reply = (resp or {}).get("reply") if ok and isinstance(resp, dict) else None
        if not isinstance(reply, dict):
            return set(), f"recent-assignment check failed: {str(resp)[:200]}"
        if reply.get("status") == "PENDING":
            sleep(1)
            continue
        if reply.get("status") != "SUCCESS":
            return set(), f"recent-assignment check ended {reply.get('status')}"
        results = reply.get("results") or {}
        rows = results.get("data") if isinstance(results, dict) else results
        return {str(r["case_id"]) for r in rows or [] if isinstance(r, dict) and r.get("case_id") not in (None, "")}, None
    return set(), f"recent-assignment check did not finish in {XQL_POLLS}s"


def search_cases(filters, start=0, size=PAGE):
    ok, resp = core_post("/public_api/v1/case/search", {"request_data": {
        "filters": filters, "search_from": start, "search_to": start + size,
        "sort": {"field": "creation_time", "keyword": "asc"}}})
    if not ok:
        raise SelectError(f"case search failed: {resp}")
    reply = (resp or {}).get("reply") or {}
    return reply.get("DATA") or [], reply.get("FILTER_COUNT")


def parse_domains(raw):
    """Case domains to assign, as the cases API names them, or None for every domain.

    Same values as Auto Triage's TriageDomains: security, posture, health, a
    DOMAIN_* value, a comma list of these, or all. Empty means security.
    """
    tokens = raw if isinstance(raw, list) else re.split(r"[,\s]+", str(raw or "").strip())
    tokens = [str(t).strip() for t in tokens if str(t).strip()] or ["security"]
    out = []
    for tok in tokens:
        low = tok.lower()
        if low == "all":
            return None
        low = low[len("domain_"):] if low.startswith("domain_") else low
        if low not in KNOWN_DOMAINS:
            raise SelectError(f"unknown domain {tok!r}: use all, " + ", ".join(KNOWN_DOMAINS)
                              + " or a DOMAIN_* value, comma-separated for several")
        if low.capitalize() not in out:
            out.append(low.capitalize())
    return out


WINDOW_UNITS = {"hour": 3600, "day": 86400, "month": 30 * 86400}


def parse_window(raw, now=None):
    """Earliest case creation time to assign, in epoch ms, or None for all time.

    "24 hours", "7 days", "3 months" (30-day months) or "all". Empty means 24 hours.
    """
    text = str(raw or "24 hours").strip().lower()
    if text in ("all", "all time"):
        return None
    m = re.fullmatch(r"(\d+)\s*(hour|day|month)s?", text)
    if not m or int(m.group(1)) < 1:
        raise SelectError(f"unknown window {raw!r}: use a number of hours, days or months "
                          "(24 hours, 7 days, 3 months) or all")
    now = time.time() if now is None else now
    return int((now - int(m.group(1)) * WINDOW_UNITS[m.group(2)]) * 1000)


def open_filters(domains):
    filters = [{"field": "status_progress", "operator": "in", "value": OPEN_STATUSES}]
    if domains:
        filters.append({"field": "case_domain", "operator": "in", "value": domains})
    return filters


def loads_of(emails, domains):
    """{email: open assigned cases} for every on-duty analyst, in one paged search.

    One call per analyst would grow with the roster (a role fallback can put
    dozens on duty); this grows with the open cases they already hold.
    """
    loads = {e: 0 for e in emails}
    filters = open_filters(domains) + [{"field": "assigned_user", "operator": "in", "value": sorted(emails)}]
    for page in range(LOAD_MAX_PAGES):
        rows, _ = search_cases(filters, start=page * PAGE)
        for r in rows:
            owner = str(r.get("assigned_user_mail") or "").strip().lower()
            if owner in loads:
                loads[owner] += 1
        if len(rows) < PAGE:
            return loads
    raise SelectError(f"on-duty analysts hold more than {LOAD_MAX_PAGES * PAGE} open cases; "
                      "load could not be counted, nothing assigned")


def unassigned_cases(domains, limit, case_id=None, since=None):
    """Open cases with no owner created since `since` (epoch ms), oldest first, up to limit.

    An explicit case_id is assigned whatever its age.
    """
    if case_id:
        rows, _ = search_cases([{"field": "case_id", "operator": "in", "value": [int(case_id)]}], size=1)
        return [r for r in rows if not r.get("assigned_user_mail")
                and r.get("status_progress") in OPEN_STATUSES]
    found = []
    for page in range(MAX_PAGES):
        filters = open_filters(domains)
        if since is not None:
            filters.append({"field": "creation_time", "operator": "gte", "value": since})
        rows, _ = search_cases(filters, start=page * PAGE)
        found += [r for r in rows if not r.get("assigned_user_mail")]
        if len(found) >= limit or len(rows) < PAGE:
            break
    return found[:limit]


def current_owner(case_id):
    rows, _ = search_cases([{"field": "case_id", "operator": "in", "value": [int(case_id)]}], size=1)
    return (rows[0].get("assigned_user_mail") or "") if rows else ""


DEFAULT_CAP = 20


def parse_cap(raw):
    """Most open cases one analyst may hold, or None for no limit ("unlimited" or "0").

    Empty means the shipped 20, so a tenant whose detached SOCOptimizationConfig_V3
    lacks the setting gets the default, not an open-ended cap.
    """
    text = str(raw if raw is not None else "").strip().lower()
    if not text:
        return DEFAULT_CAP
    if text in ("0", "unlimited", "none", "no limit"):
        return None
    if not text.isdigit():
        raise ValueError(f"max_per_analyst must be a whole number or unlimited, not {raw!r}")
    return int(text)


def rank(loads, case=None):
    """On-duty analysts best first: least loaded, ties by email.

    The place for a later step that weighs skill or the case's category; it
    receives the case and returns the same ordering shape.
    """
    return sorted(loads, key=lambda email: (loads[email], email))


def assign(case_id, email, actor):
    """(status, note) for one dispatch of soc-assign-case."""
    body = {"request_data": {"incident_id": str(case_id), "update_data": {"assigned_user_mail": email}}}
    try:
        entries = demisto.executeCommand("SOCCommandWrapper", {
            "action": ACTION, "Action_Actor": actor, "tags": "Assignment",
            # One JSON object: the wrapper keeps it whole as a single target.
            "target": json.dumps(body)})
    except Exception as e:  # noqa: BLE001
        return "failed", f"the wrapper raised: {e}"
    for e in entries or []:
        contents = e.get("Contents") if isinstance(e, dict) else None
        title = str((e or {}).get("HumanReadable") or "").split("\n", 1)[0] if isinstance(e, dict) else ""
        if isinstance(e, dict) and e.get("Type") == 4:
            return "failed", str(contents)[:300]
        if isinstance(contents, dict) and contents.get("action") == ACTION:
            if "skipped" in title:
                return "skipped", str(contents.get("reason") or title)
            if contents.get("shadow_mode") is True:
                return "simulated", "shadow mode: not assigned"
            if "success" in contents:
                return ("assigned", "") if contents.get("success") else ("failed", str(contents.get("error"))[:300])
    return "failed", "the wrapper reported nothing"


def record(row):
    row = dict({"event_type": "analyst_assignment", "timestamp": datetime.now(timezone.utc).isoformat(),
                "action_taken": ACTION}, **row)
    try:
        demisto.executeCommand(DATASET_COMMAND, {"using": DATASET_INSTANCE, "JSON": json.dumps(row)})
    except Exception as e:  # noqa: BLE001
        demisto.debug(f"SOCFWAnalystSelect: row not recorded: {e}")


def record_decision(d, actor):
    record({"case_id": d["case_id"], "assignee": d["assignee"], "action_status": d["status"],
            "assignment_reason": d["reason"], "error_message": d["note"] if d["status"] == "failed" else "",
            "has_error": d["status"] == "failed", "action_actor": actor,
            "on_duty_loads": json.dumps(d["loads"], sort_keys=True)})


def run(cases, loads, actor, owner_now, deadline=None, on_decision=None, clock=time.monotonic,
        cap=None, recently=lambda: set()):
    """Assign each case in turn; returns (decisions, cases left for the next run).

    Calls out only through owner_now and recently (the two re-checks), assign()
    and on_decision, which records each decision as it is made so a run cut
    short loses nothing. No new case is started after deadline (a clock()
    value). An analyst holding cap or more open cases is not picked; once
    everyone on duty is at the cap the run stops.
    """
    decisions = []
    for i, case in enumerate(cases):
        if deadline is not None and clock() >= deadline:
            return decisions, len(cases) - i
        cid = case.get("case_id")
        ranked = [e for e in rank(loads, case) if cap is None or loads[e] < cap]
        snapshot = dict(loads)
        pick = ranked[0] if ranked else ""
        if not ranked:
            status, note = "skipped", f"everyone on duty holds {cap} or more open cases"
        elif str(cid) in recently():
            status, note, pick = "skipped", f"assigned by the framework in the last {RECENT_MINUTES} minutes", ""
        elif owner_now(cid):
            status, note, pick = "skipped", "assigned by someone else since the run started", ""
        else:
            status, note = assign(cid, pick, actor)
            if status in ("assigned", "simulated"):
                loads[pick] += 1
        decision = {"case_id": cid, "case_name": case.get("case_name") or "", "assignee": pick,
                    "status": status, "reason": "least_loaded" if pick else "", "note": note,
                    "loads": snapshot}
        decisions.append(decision)
        if on_decision:
            on_decision(decision)
        if not ranked:
            return decisions, 0
    return decisions, 0


def render(decisions, on_duty, loads, notes):
    lines = ["### Analyst assignment"]
    lines += notes
    if on_duty:
        lines.append("**Open cases per on-duty analyst at start:** "
                     + ", ".join(f"{e} {loads[e]}" for e in sorted(loads)))
    if decisions:
        lines.append("| Case | Name | Assignee | Outcome | Note |")
        lines.append("|---|---|---|---|---|")
        for d in decisions:
            lines.append(f"| {d['case_id']} | {d['case_name']} | {d['assignee'] or '-'} | {d['status']} | {d['note']} |")
    return "\n".join(lines)


def main():
    started = time.monotonic()
    args = demisto.args() or {}
    actor = (args.get("actor") or "automation").strip()
    method = (args.get("method") or "least_loaded").strip().lower()
    if method not in METHODS:
        return_error(f"SOCFWAnalystSelect: unknown method {method!r}; use " + ", ".join(METHODS)
                     + ". Nothing was assigned.")
        return
    try:
        limit = max(1, int(args.get("max_cases") or 50))
        cap = parse_cap(args.get("max_per_analyst"))
    except ValueError as e:
        return_error(f"SOCFWAnalystSelect: {e}")
        return
    online_only = str(args.get("online_only") or "true").strip().lower() in ("true", "yes", "1")
    notes, decisions, loads = [], [], {}
    try:
        domains = parse_domains(args.get("domains"))
        since = parse_window(args.get("window"))
        on_duty = read_on_duty()
        if on_duty is None:
            notes.append(f"{LOOKUP} does not exist yet: run SOCFWOnDutySync first. Nothing assigned.")
            on_duty = []
        elif not on_duty:
            notes.append(f"Nobody is on duty in {LOOKUP}. Nothing assigned; cases stay unassigned.")
        elif online_only:
            online = online_users()
            if online is None:
                raise SelectError("could not read who is online; nothing assigned")
            offline = [e for e in on_duty if e not in online]
            on_duty = [e for e in on_duty if e in online]
            if offline:
                notes.append(f"{len(offline)} on duty but not online, left out: " + ", ".join(offline))
            if not on_duty:
                notes.append("Nobody on duty is online. Nothing assigned; cases stay unassigned.")
        if on_duty:
            cases = unassigned_cases(domains, limit, args.get("case_id"), since)
            if not cases:
                notes.append("No unassigned open cases" + ("" if since is None or args.get("case_id")
                                                            else f" in the last {args.get('window') or '24 hours'}") + ".")
            loads = loads_of(on_duty, domains)
            recent = {"ids": set(), "at": None}

            def recently():
                # Refreshed during the run so a run that overlaps another sees its assignments.
                if recent["at"] is None or time.monotonic() - recent["at"] >= RECENT_REFRESH_SECONDS:
                    ids, why = recent_assignments()
                    recent.update(ids=ids, at=time.monotonic())
                    if why and why not in notes:
                        notes.append(why + "; relying on the case recheck alone.")
                return recent["ids"]

            decisions, left = run(cases, loads, actor, current_owner, deadline=started + MAX_RUNTIME_SECONDS,
                                  on_decision=lambda d: record_decision(d, actor), cap=cap, recently=recently)
            if decisions and decisions[-1]["note"].startswith("everyone on duty holds"):
                notes.append(f"Stopped: everyone on duty holds {cap} or more open cases "
                             "(AssignmentMaxPerAnalyst); the rest stay unassigned until someone has room.")
            if left:
                notes.append(f"Stopped at the {MAX_RUNTIME_SECONDS}s run budget with {left} case(s) left; "
                             "the next run picks them up.")
    except SelectError as e:
        return_error(f"SOCFWAnalystSelect: {e}")
        return

    start_loads = decisions[0]["loads"] if decisions else loads
    return_results(CommandResults(
        readable_output=render(decisions, on_duty, start_loads, notes),
        outputs_prefix="SOCFramework.Assignment",
        outputs={"on_duty": on_duty, "loads": start_loads, "decisions": decisions, "notes": notes},
        replace_existing=True,
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
