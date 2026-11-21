import pytest
import sys
import types

# The functions under test are pure, so stub the platform modules before import.
if "demistomock" not in sys.modules:
    mock = types.ModuleType("demistomock")
    mock.args = lambda: {}
    mock.debug = lambda *a, **k: None
    mock.executeCommand = lambda *a, **k: []
    sys.modules["demistomock"] = mock
import demistomock  # noqa: E402

import SOCFWOnDutySync as s  # noqa: E402

s.demisto = demistomock

PD = {"output_map": {"SOCFramework.OnDuty.Sources.PagerDuty": "PagerDutyUser"},
      "roster_fields": {"email": "Email", "name": "DisplayName"}}
USERS = {"a@example.com": "A", "b@example.com": "B", "c@example.com": "C", "d@example.com": "D"}
NOW = "2026-10-30T00:00:00+00:00"


def row(email, source):
    return {"email": email, "name": "", "source": source, "updated_at": "old"}


def test_people_from_reads_every_user_not_just_the_first():
    ec = s.entry_context([{"EntryContext": {"PagerDutyUser(val.ID == obj.ID)": [
        {"Email": "A@Example.com", "DisplayName": "A"}, {"Email": "b@example.com", "DisplayName": "B"}]}}])
    assert s.people_from(ec, PD) == [{"email": "a@example.com", "name": "A"}, {"email": "b@example.com", "name": "B"}]


def test_people_from_without_roster_fields_finds_nobody():
    assert s.people_from({"PagerDutyUser": [{"Email": "a@example.com"}]}, {"output_map": {"k": "PagerDutyUser"}}) == []


def test_wrapper_outcomes_reads_success_skip_and_unavailable():
    entries = [
        {"HumanReadable": "### SOC Framework - Universal Command Resolved",
         "Contents": {"action": s.ACTION, "vendor": "PagerDuty v2", "shadow_mode": False}},
        {"HumanReadable": "### SOC Framework - Command Success",
         "Contents": {"action": s.ACTION, "vendor": "PagerDuty v2", "success": True}},
        {"HumanReadable": "### SOC Framework - soc-sync-on-duty: skipped (vendor not configured)",
         "Contents": {"action": s.ACTION, "vendor": "Other", "reason": "not configured: set x"}},
        {"HumanReadable": "### SOC Framework - Command Failure",
         "Contents": {"action": s.ACTION, "vendor": "Third", "success": False,
                      "error": "Unsupported Command: x"}},
    ]
    out = s.wrapper_outcomes(entries)
    assert out["PagerDuty v2"][0] == "answered"
    assert out["Other"][0] == "not_configured"
    assert out["Third"][0] == "unavailable"


def test_plan_upserts_answering_source_and_removes_only_its_missing_rows():
    existing = [row("a@example.com", "PagerDuty v2"), row("b@example.com", "PagerDuty v2"), row("c@example.com", "manual")]
    up, rm, detail = s.plan(existing, {"PagerDuty v2": [{"email": "a@example.com"}, {"email": "d@example.com"}]}, USERS, NOW)
    assert sorted(u["email"] for u in up) == ["a@example.com", "d@example.com"]
    assert rm == ["b@example.com"]  # c@example.com belongs to manual, which did not answer
    assert detail["PagerDuty v2"]["added"] == ["d@example.com"]
    assert detail["PagerDuty v2"]["removed"] == ["b@example.com"]


def test_plan_leaves_out_non_tenant_users_and_never_removes_for_a_silent_source():
    existing = [row("a@example.com", "manual")]
    up, rm, detail = s.plan(existing, {"PagerDuty v2": [{"email": "z@example.com"}]}, USERS, NOW)
    assert up == [] and rm == []
    assert detail["PagerDuty v2"]["not_tenant_users"] == ["z@example.com"]


def test_plan_with_no_answering_source_changes_nothing():
    assert s.plan([row("a@example.com", "PagerDuty v2")], {}, USERS, NOW) == ([], [], {})


def test_plan_unchecked_users_keeps_everyone():
    up, _, _ = s.plan([], {"manual": [{"email": "z@example.com"}]}, None, NOW)
    assert [u["email"] for u in up] == ["z@example.com"]


def test_plan_email_in_two_sources_stays_with_one():
    up, rm, _ = s.plan([], {"manual": [{"email": "a@example.com"}], "PagerDuty v2": [{"email": "a@example.com"}]}, USERS, NOW)
    assert [(u["email"], u["source"]) for u in up] == [("a@example.com", "PagerDuty v2")]
    assert rm == []


def test_roster_after_applies_changes():
    existing = [row("a@example.com", "manual"), row("b@example.com", "manual")]
    up = [{"email": "c@example.com", "name": "C", "source": "manual", "updated_at": NOW}]
    assert [r["email"] for r in s.roster_after(existing, up, ["b@example.com"])] == ["a@example.com", "c@example.com"]


def test_parse_analysts_dedupes_and_lowercases():
    assert [p["email"] for p in s.parse_analysts("A@example.com, b@example.com;a@example.com,,")] == ["a@example.com", "b@example.com"]


ADMINS = [{"email": "a@example.com", "name": "A"}]


def _role_users(monkeypatch, people=ADMINS):
    calls = []
    monkeypatch.setattr(s, "role_users", lambda roles, groups=(): calls.append(roles) or list(people))
    return calls


def test_role_fallback_when_no_source_is_set_up(monkeypatch):
    calls = _role_users(monkeypatch)
    g = {"PagerDuty v2": {"status": "not_configured", "reason": "", "people": []}}
    s.add_role_fallback(g, ["Account Admin"], [])
    assert calls == [["Account Admin"]]
    assert g[s.ROLE_SOURCE]["status"] == "answered" and g[s.ROLE_SOURCE]["people"] == ADMINS


def test_no_role_fallback_when_a_source_is_set_up_but_failed(monkeypatch):
    calls = _role_users(monkeypatch)
    g = {"PagerDuty v2": {"status": "failed", "reason": "boom", "people": []}}
    s.add_role_fallback(g, ["Account Admin"], [])
    assert calls == [] and s.ROLE_SOURCE not in g


def test_no_role_fallback_without_roles(monkeypatch):
    calls = _role_users(monkeypatch)
    g = {"PagerDuty v2": {"status": "not_configured", "reason": "", "people": []}}
    s.add_role_fallback(g, [], [])
    assert calls == [] and s.ROLE_SOURCE not in g


def test_role_rows_removed_once_a_source_answers(monkeypatch):
    _role_users(monkeypatch)
    existing = [row("a@example.com", s.ROLE_SOURCE), row("b@example.com", s.ROLE_SOURCE)]
    g = {"PagerDuty v2": {"status": "answered", "reason": "", "people": [{"email": "c@example.com"}]}}
    s.add_role_fallback(g, ["Account Admin"], existing)
    assert g[s.ROLE_SOURCE]["status"] == "superseded"
    answered = {k: v["people"] for k, v in g.items() if v["status"] in ("answered", "superseded")}
    up, rm, _ = s.plan(existing, answered, USERS, NOW)
    assert [u["email"] for u in up] == ["c@example.com"] and rm == ["a@example.com", "b@example.com"]


def test_nothing_superseded_when_there_were_no_role_rows(monkeypatch):
    _role_users(monkeypatch)
    g = {"PagerDuty v2": {"status": "answered", "reason": "", "people": [{"email": "c@example.com"}]}}
    s.add_role_fallback(g, ["Account Admin"], [row("d@example.com", "manual")])
    assert s.ROLE_SOURCE not in g


def test_role_fallback_with_nobody_matching_removes_its_rows(monkeypatch):
    """Zero matches is the tenant's answer: a group that matches no one must not leave
    the previous fallback roster (e.g. the admin roles) in place."""
    _role_users(monkeypatch, people=[])
    g = {"PagerDuty v2": {"status": "unavailable", "reason": "", "people": []}}
    s.add_role_fallback(g, ["Analyst"], [{"email": "admin@example.com", "source": s.ROLE_SOURCE}], ["SOC Analysts"])
    assert g[s.ROLE_SOURCE]["status"] == "answered" and g[s.ROLE_SOURCE]["people"] == []
    assert "nobody on duty" in g[s.ROLE_SOURCE]["reason"]


def test_parse_roles():
    assert s.parse_roles("Instance Administrator, Account Admin,,") == ["Instance Administrator", "Account Admin"]


def test_a_row_stays_with_the_source_that_owns_it():
    existing = [row("a@example.com", "manual")]
    up, rm, detail = s.plan(existing, {s.ROLE_SOURCE: [{"email": "a@example.com"}, {"email": "b@example.com"}]}, USERS, NOW)
    assert [(u["email"], u["source"]) for u in up] == [("b@example.com", s.ROLE_SOURCE)]
    assert rm == [] and detail[s.ROLE_SOURCE]["held_by_other_source"] == ["a@example.com"]
    # Superseding the role source later removes only its own rows.
    existing = [row("a@example.com", "manual"), row("b@example.com", s.ROLE_SOURCE)]
    _, rm, _ = s.plan(existing, {s.ROLE_SOURCE: [], "PagerDuty v2": [{"email": "c@example.com"}]}, USERS, NOW)
    assert rm == ["b@example.com"]


def test_manual_claims_its_people_from_another_source():
    up, rm, _ = s.plan([row("a@example.com", s.ROLE_SOURCE)], {"manual": [{"email": "a@example.com"}]}, USERS, NOW)
    assert [(u["email"], u["source"]) for u in up] == [("a@example.com", "manual")] and rm == []


def test_groups_alone_turn_on_the_fallback(monkeypatch):
    calls = _role_users(monkeypatch)
    g = {"PagerDuty v2": {"status": "not_configured", "reason": "", "people": []}}
    s.add_role_fallback(g, [], [], ["SOC Analysts"])
    assert calls == [[]] and g[s.ROLE_SOURCE]["status"] == "answered"
    assert "groups SOC Analysts" in g[s.ROLE_SOURCE]["reason"]


def test_role_users_matches_a_role_or_a_group(monkeypatch):
    reply = {"reply": [
        {"user_email": "A@example.com", "role_name": "Account Admin", "groups": []},
        {"user_email": "b@example.com", "role_name": None, "groups": ["SOC Analysts"]},
        {"user_email": "c@example.com", "role_name": None, "groups": ["Other"]},
        {"user_email": "d@example.com", "role_name": "Viewer"}]}
    monkeypatch.setattr(s, "core_post", lambda uri, body: (True, reply))
    assert [p["email"] for p in s.role_users(["account admin"], ["soc analysts"])] == ["a@example.com", "b@example.com"]
    assert [p["email"] for p in s.role_users([], ["SOC Analysts"])] == ["b@example.com"]


def test_tenant_roles_and_groups_override_the_job_and_none_means_empty():
    args, taken = s.apply_tenant_overrides({"roles": "Instance Administrator,Account Admin", "groups": ""},
                                           {"roles": "none", "groups": "SOC Analysts, SOC Leads"})
    assert args == {"roles": "", "groups": "SOC Analysts, SOC Leads"} and taken == ["roles", "groups"]
    assert s.parse_roles(args["roles"]) == [] and s.parse_roles(args["groups"]) == ["SOC Analysts", "SOC Leads"]


def test_lookup_write_retries_once_then_reports(monkeypatch):
    calls = []

    def flaky(uri, body):
        calls.append(uri)
        return (False, "HTTP 500") if len(calls) == 1 else (True, {})

    monkeypatch.setattr(s, "core_post", flaky)
    s.lookup_write("/x", {}, "update", sleep=lambda n: None)
    assert len(calls) == 2
    monkeypatch.setattr(s, "core_post", lambda uri, body: (False, "HTTP 500"))
    with pytest.raises(s.SyncError, match="could not update"):
        s.lookup_write("/x", {}, "update", sleep=lambda n: None)
