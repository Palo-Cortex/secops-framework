"""Keep the on-duty lookup in step with whoever the customer's sources say is on duty.

Sources are the responses of the soc-sync-on-duty action, run through the
Universal Command with dispatch all_applicable: every source with a configured
integration answers, and each response row says where its people are
(output_map) and which of their fields are the email and name (roster_fields).
analysts= is the manual source, for a customer with no schedule system: those
people become this run's manual set and no other source is called.

roles= and groups= are the fallback when no schedule source is set up at all:
tenant users whose role is one of roles, or who are in one of groups, are on
duty, as source xsiam_role. A source that is
set up but fails does not trigger it - the last roster stands - and once a
schedule source answers, the xsiam_role rows are removed.

The lookup holds a snapshot, never the schedule itself:
  - created on first sync, never wiped
  - each source owns its own rows; a source that answers replaces its set
  - a source that errors, is not configured, or returns nobody changes nothing
  - an email that is not a user on this tenant is reported and left out,
    because a case cannot be assigned to it

Every source's outcome is recorded to the execution dataset as an
on_duty_sync row with no incident_id or phase, so the value dashboards skip it.
"""

import json
from datetime import datetime, timezone

LOOKUP = "socfw_on_duty"
SCHEMA = {"email": "text", "name": "text", "source": "text", "updated_at": "text"}
ACTION = "soc-sync-on-duty"
ACTIONS_LIST = "SOCFrameworkActions_V3"
MANUAL = "manual"
ROLE_SOURCE = "xsiam_role"
# Outcomes that mean a source is not set up on this tenant, as opposed to set up and failing.
NOT_SET_UP = ("not_configured", "unavailable")

DATASET_COMMAND = "socfw-post-to-dataset"
DATASET_INSTANCE = "socfw_ir_execution_writer"


class SyncError(Exception):
    pass


def _is_error(res):
    return any(isinstance(e, dict) and e.get("Type") == 4 for e in (res or []))


def _error_text(res):
    return "; ".join(str(e.get("Contents")) for e in (res or [])
                     if isinstance(e, dict) and e.get("Type") == 4)


def core_post(uri, body):
    """(ok, response or error text) for a POST through the Core REST API integration."""
    res = demisto.executeCommand("core-api-post", {"uri": uri, "body": json.dumps(body)})
    if _is_error(res):
        return False, _error_text(res)
    for e in res or []:
        contents = e.get("Contents") if isinstance(e, dict) else None
        if isinstance(contents, dict) and "response" in contents:
            return True, contents["response"]
    return False, f"{uri} returned nothing readable"


# ── Lookup ───────────────────────────────────────────────────────────────────

def read_lookup():
    """Rows in the lookup, or None when it does not exist yet."""
    ok, resp = core_post("/public_api/v1/xql/lookups/get_data", {"request_data": {"dataset_name": LOOKUP}})
    if not ok:
        if "not found" in str(resp).lower():
            return None
        raise SyncError(f"could not read {LOOKUP}: {resp}")
    rows = ((resp or {}).get("reply") or {}).get("data") or []
    return [{k: r.get(k) for k in SCHEMA} for r in rows if isinstance(r, dict)]


def create_lookup():
    ok, resp = core_post("/public_api/v1/xql/add_dataset", {"request_data": {
        "dataset_name": LOOKUP, "dataset_type": "lookup", "dataset_schema": SCHEMA}})
    if not ok and "already exists" not in str(resp).lower():
        raise SyncError(f"could not create {LOOKUP}: {resp}")


def upsert(rows):
    if not rows:
        return
    # Full rows only: add_data sets any field a row leaves out to empty.
    ok, resp = core_post("/public_api/v1/xql/lookups/add_data", {"request_data": {
        "dataset_name": LOOKUP, "key_fields": ["email"],
        "data": [{k: r.get(k, "") for k in SCHEMA} for r in rows]}})
    if not ok:
        raise SyncError(f"could not update {LOOKUP}: {resp}")


def remove(emails):
    if not emails:
        return
    ok, resp = core_post("/public_api/v1/xql/lookups/remove_data", {"request_data": {
        "dataset_name": LOOKUP, "filters": [{"email": e} for e in emails]}})
    if not ok:
        raise SyncError(f"could not remove rows from {LOOKUP}: {resp}")


# ── Sources ──────────────────────────────────────────────────────────────────

def load_responses():
    """The soc-sync-on-duty response rows, by source name."""
    res = demisto.executeCommand("getList", {"listName": ACTIONS_LIST})
    raw = res[0].get("Contents") if res and isinstance(res[0], dict) else None
    try:
        actions = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except ValueError:
        actions = {}
    responses = (actions.get(ACTION) or {}).get("responses") or {}
    return {k: v for k, v in responses.items() if isinstance(v, dict)}


def entry_context(entries):
    """Every entry's EntryContext merged, with DT suffixes stripped from the keys."""
    merged = {}
    for e in entries or []:
        ec = e.get("EntryContext") if isinstance(e, dict) else None
        if isinstance(ec, dict):
            for key, value in ec.items():
                merged[key.split("(", 1)[0]] = value
    return merged


def wrapper_outcomes(entries):
    """{source: (status, reason)} from the wrapper's records in its War Room entries.

    Read from the entries because what a nested script writes to context is not
    visible to its caller until the caller finishes.
    """
    out = {}
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        contents = e.get("Contents")
        title = str(e.get("HumanReadable") or "").split("\n", 1)[0]
        if not isinstance(contents, dict) or contents.get("action", ACTION) != ACTION:
            continue
        vendor = contents.get("vendor")
        if not vendor:
            continue
        if "skipped" in title:
            status = "not_configured" if "not configured" in title else "skipped"
            out[vendor] = (status, str(contents.get("reason") or title))
        elif "success" in contents:
            if contents.get("success") is True:
                out[vendor] = ("answered", "")
            else:
                err = str(contents.get("error") or "")
                unavailable = "Unsupported Command" in err or "(23)" in err
                out[vendor] = ("unavailable" if unavailable else "failed", err[:300])
    return out


def people_from(ec, response):
    """[{email, name}] from one source's output, using its roster_fields."""
    paths = list((response.get("output_map") or {}).values())
    fields = response.get("roster_fields") or {}
    if not paths or not fields.get("email"):
        return []
    found = ec.get(paths[0])
    if found is None:
        for key, value in ec.items():
            if paths[0].startswith(key + ".") and isinstance(value, dict):
                found = value.get(paths[0][len(key) + 1:])
    items = found if isinstance(found, list) else ([found] if isinstance(found, dict) else [])
    people = []
    for item in items:
        if not isinstance(item, dict):
            continue
        email = item.get(fields["email"])
        if isinstance(email, list):
            email = email[0] if email else ""
        email = str(email or "").strip().lower()
        if email:
            people.append({"email": email, "name": str(item.get(fields.get("name", "")) or "").strip()})
    return people


def call_sources(responses):
    """{source: {"status", "reason", "people"}} for every source the action names."""
    entries = demisto.executeCommand("SOCCommandWrapper", {
        "action": ACTION, "Action_Actor": "automation", "tags": "On Duty Sync"})
    ec = entry_context(entries)
    outcomes = wrapper_outcomes(entries)
    result = {}
    for source, response in sorted(responses.items()):
        status, reason = outcomes.get(source, ("no_record", "the wrapper recorded nothing for this source"))
        people = people_from(ec, response) if status == "answered" else []
        if status == "answered" and not people:
            status, reason = "empty", "the source answered with nobody on duty; nothing changed"
        result[source] = {"status": status, "reason": reason, "people": people}
    return result


def parse_roles(raw):
    items = raw if isinstance(raw, list) else str(raw or "").split(",")
    return [str(r).strip() for r in items if str(r).strip()]


def role_users(roles, groups=()):
    """[{email, name}] for tenant users whose role is one of roles or who are in one of groups.

    get_users lists each user's directly assigned role and the user groups they
    are in, so one call answers both.
    """
    ok, resp = core_post("/public_api/v1/rbac/get_users", {"request_data": {}})
    if not ok:
        raise SyncError(f"could not read tenant users for the role fallback: {resp}")
    wanted = {r.lower() for r in roles}
    wanted_groups = {g.lower() for g in groups}
    people = []
    for u in (resp or {}).get("reply") or []:
        if not isinstance(u, dict) or not u.get("user_email"):
            continue
        in_group = any(str(g).strip().lower() in wanted_groups for g in (u.get("groups") or []))
        if in_group or str(u.get("role_name") or "").strip().lower() in wanted:
            name = " ".join(x for x in (u.get("user_first_name"), u.get("user_last_name")) if x)
            people.append({"email": str(u["user_email"]).strip().lower(), "name": name})
    return sorted(people, key=lambda p: p["email"])


def add_role_fallback(gathered, roles, existing, groups=()):
    """Add the xsiam_role source to gathered, or mark it superseded. Mutates gathered."""
    has_role_rows = any(r.get("source") == ROLE_SOURCE for r in existing)
    if any(g["status"] == "answered" for g in gathered.values()):
        if not has_role_rows:
            return
        gathered[ROLE_SOURCE] = {"status": "superseded", "people": [],
                                 "reason": "a schedule source answered; role fallback rows removed"}
    elif (roles or groups) and all(g["status"] in NOT_SET_UP for g in gathered.values()):
        people = role_users(roles, groups)
        what = "; ".join(x for x in ("roles " + ", ".join(roles) if roles else "",
                                     "groups " + ", ".join(groups) if groups else "") if x)
        gathered[ROLE_SOURCE] = (
            {"status": "answered", "reason": "no schedule source set up; " + what, "people": people}
            if people else
            {"status": "empty", "people": [], "reason": "no tenant user matches " + what})


def parse_analysts(raw):
    items = raw if isinstance(raw, list) else str(raw or "").replace(";", ",").split(",")
    seen, out = set(), []
    for item in items:
        email = str(item).strip().lower()
        if email and email not in seen:
            seen.add(email)
            out.append({"email": email, "name": ""})
    return out


def load_users():
    """{email: name} for the tenant's users, or None when they cannot be read."""
    try:
        res = demisto.executeCommand("getUsers", {})
    except Exception as e:  # noqa: BLE001
        demisto.debug(f"SOCFWOnDutySync: getUsers failed: {e}")
        return None
    if _is_error(res):
        return None
    users = {}
    for e in res or []:
        if not isinstance(e, dict):
            continue
        found = list(e.get("Contents")) if isinstance(e.get("Contents"), list) else []
        if not found:
            for value in (e.get("EntryContext") or {}).values():
                found += value if isinstance(value, list) else [value]
        for u in found:
            if isinstance(u, dict) and u.get("email"):
                users[str(u["email"]).strip().lower()] = str(u.get("name") or "").strip()
    return users or None


# ── Plan ─────────────────────────────────────────────────────────────────────

def plan(existing, answered, users, now):
    """(rows to upsert, emails to remove, per-source detail) - pure, no calls.

    existing: lookup rows. answered: {source: [people]} for sources that answered
    with at least one person. users: {email: name}, or None when unchecked.
    Only rows owned by an answering source can be removed. An email two sources
    both return stays with the first source alphabetically. An email already
    owned by a source that is not answering this run stays with that source, so
    a later sync of one source never removes someone another source put there.
    The manual source is the exception: analysts= claims its people from any source.
    """
    owner = {r["email"]: r.get("source") for r in existing if r.get("email")}
    claimed, upserts, detail = {}, [], {}
    for source in sorted(answered):
        keep, not_users, held = [], [], []
        for p in answered[source]:
            email = p["email"]
            if users is not None and email not in users:
                not_users.append(email)
                continue
            if email in claimed:
                continue
            # analysts= is an explicit instruction, so the manual source always claims its people.
            if source != MANUAL and owner.get(email) not in (None, source) and owner[email] not in answered:
                held.append(email)
                continue
            claimed[email] = source
            name = p.get("name") or (users or {}).get(email) or ""
            upserts.append({"email": email, "name": name, "source": source, "updated_at": now})
            keep.append(email)
        detail[source] = {"on_duty": len(keep), "added": sorted(e for e in keep if owner.get(e) != source),
                          "removed": [], "not_tenant_users": sorted(not_users),
                          "held_by_other_source": sorted(held)}
    removals = sorted(e for e, src in owner.items() if src in answered and e not in claimed)
    for e in removals:
        detail[owner[e]]["removed"].append(e)
    return upserts, removals, detail


def roster_after(existing, upserts, removals):
    """The lookup's rows once this run's changes are applied."""
    changed = {u["email"] for u in upserts} | set(removals)
    kept = [r for r in existing if r.get("email") and r["email"] not in changed]
    return sorted(kept + upserts, key=lambda r: r["email"])


def record(rows):
    now = datetime.now(timezone.utc).isoformat()
    for row in rows:
        row = dict({"event_type": "on_duty_sync", "timestamp": now, "action_taken": ACTION}, **row)
        try:
            demisto.executeCommand(DATASET_COMMAND, {"using": DATASET_INSTANCE, "JSON": json.dumps(row)})
        except Exception as e:  # noqa: BLE001
            demisto.debug(f"SOCFWOnDutySync: row not recorded: {e}")


def render(sources, roster, created):
    lines = [f"### On-duty sync - {LOOKUP}"]
    if created:
        lines.append(f"Created {LOOKUP} on this run.")
    lines.append("| Source | Outcome | On duty | Added | Removed | Not tenant users | Note |")
    lines.append("|---|---|---|---|---|---|---|")
    for s in sources:
        lines.append(f"| {s['source']} | {s['status']} | {s.get('on_duty', '-')} | "
                     f"{', '.join(s.get('added') or []) or '-'} | {', '.join(s.get('removed') or []) or '-'} | "
                     f"{', '.join(s.get('not_tenant_users') or []) or '-'} | {s.get('reason') or ''} |")
    lines.append(f"\n**{len(roster)} on duty now:** " + (", ".join(r["email"] for r in roster) or "nobody"))
    return "\n".join(lines)


def main():
    args = demisto.args() or {}
    analysts = parse_analysts(args.get("analysts"))
    try:
        existing = read_lookup()
        created = existing is None
        if created:
            create_lookup()
            existing = []

        if analysts:
            gathered = {MANUAL: {"status": "answered", "reason": "", "people": analysts}}
        else:
            responses = load_responses()
            if not responses:
                raise SyncError(f"{ACTION} has no responses in {ACTIONS_LIST}")
            gathered = call_sources(responses)
            add_role_fallback(gathered, parse_roles(args.get("roles")), existing,
                              parse_roles(args.get("groups")))

        # superseded hands the role source an empty set, which removes its rows.
        answered = {s: g["people"] for s, g in gathered.items() if g["status"] in ("answered", "superseded")}
        users = load_users() if answered else None
        now = datetime.now(timezone.utc).isoformat()
        upserts, removals, detail = plan(existing, answered, users, now)
        upsert(upserts)
        remove(removals)
    except SyncError as e:
        record([{"vendor": "-", "action_status": "failed", "has_error": True, "error_message": str(e)}])
        return_error(f"SOCFWOnDutySync: {e}")
        return

    sources, rows = [], []
    for source, g in sorted(gathered.items()):
        d = detail.get(source, {})
        status = g["status"] if g["status"] == "superseded" else "synced" if source in answered else g["status"]
        sources.append({"source": source, "status": status, "reason": g["reason"], **d})
        rows.append({"vendor": source, "action_status": status,
                     "has_error": status in ("failed", "no_record"), "error_message": g["reason"],
                     "on_duty_count": d.get("on_duty", 0), "on_duty_added": d.get("added", []),
                     "on_duty_removed": d.get("removed", []),
                     "not_tenant_users": d.get("not_tenant_users", [])})
    if answered and users is None:
        sources.append({"source": "-", "status": "warning",
                        "reason": "tenant users could not be read; emails were not checked"})
    record(rows)

    roster = roster_after(existing, upserts, removals)
    return_results(CommandResults(
        readable_output=render(sources, roster, created),
        outputs_prefix="SOCFramework.OnDuty",
        outputs={"lookup": LOOKUP, "created": created, "sources": sources, "roster": roster},
        replace_existing=True,
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
