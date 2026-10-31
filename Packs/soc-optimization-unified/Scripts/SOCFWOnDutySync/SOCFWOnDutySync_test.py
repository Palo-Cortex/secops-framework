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
USERS = {"a@x.com": "A", "b@x.com": "B", "c@x.com": "C", "d@x.com": "D"}
NOW = "2026-10-30T00:00:00+00:00"


def row(email, source):
    return {"email": email, "name": "", "source": source, "updated_at": "old"}


def test_people_from_reads_every_user_not_just_the_first():
    ec = s.entry_context([{"EntryContext": {"PagerDutyUser(val.ID == obj.ID)": [
        {"Email": "A@X.com", "DisplayName": "A"}, {"Email": "b@x.com", "DisplayName": "B"}]}}])
    assert s.people_from(ec, PD) == [{"email": "a@x.com", "name": "A"}, {"email": "b@x.com", "name": "B"}]


def test_people_from_without_roster_fields_finds_nobody():
    assert s.people_from({"PagerDutyUser": [{"Email": "a@x.com"}]}, {"output_map": {"k": "PagerDutyUser"}}) == []


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
    existing = [row("a@x.com", "PagerDuty v2"), row("b@x.com", "PagerDuty v2"), row("c@x.com", "manual")]
    up, rm, detail = s.plan(existing, {"PagerDuty v2": [{"email": "a@x.com"}, {"email": "d@x.com"}]}, USERS, NOW)
    assert sorted(u["email"] for u in up) == ["a@x.com", "d@x.com"]
    assert rm == ["b@x.com"]  # c@x.com belongs to manual, which did not answer
    assert detail["PagerDuty v2"]["added"] == ["d@x.com"]
    assert detail["PagerDuty v2"]["removed"] == ["b@x.com"]


def test_plan_leaves_out_non_tenant_users_and_never_removes_for_a_silent_source():
    existing = [row("a@x.com", "manual")]
    up, rm, detail = s.plan(existing, {"PagerDuty v2": [{"email": "z@x.com"}]}, USERS, NOW)
    assert up == [] and rm == []
    assert detail["PagerDuty v2"]["not_tenant_users"] == ["z@x.com"]


def test_plan_with_no_answering_source_changes_nothing():
    assert s.plan([row("a@x.com", "PagerDuty v2")], {}, USERS, NOW) == ([], [], {})


def test_plan_unchecked_users_keeps_everyone():
    up, _, _ = s.plan([], {"manual": [{"email": "z@x.com"}]}, None, NOW)
    assert [u["email"] for u in up] == ["z@x.com"]


def test_plan_email_in_two_sources_stays_with_one():
    up, rm, _ = s.plan([], {"manual": [{"email": "a@x.com"}], "PagerDuty v2": [{"email": "a@x.com"}]}, USERS, NOW)
    assert [(u["email"], u["source"]) for u in up] == [("a@x.com", "PagerDuty v2")]
    assert rm == []


def test_roster_after_applies_changes():
    existing = [row("a@x.com", "manual"), row("b@x.com", "manual")]
    up = [{"email": "c@x.com", "name": "C", "source": "manual", "updated_at": NOW}]
    assert [r["email"] for r in s.roster_after(existing, up, ["b@x.com"])] == ["a@x.com", "c@x.com"]


def test_parse_analysts_dedupes_and_lowercases():
    assert [p["email"] for p in s.parse_analysts("A@x.com, b@x.com;a@x.com,,")] == ["a@x.com", "b@x.com"]


ADMINS = [{"email": "a@x.com", "name": "A"}]


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
    existing = [row("a@x.com", s.ROLE_SOURCE), row("b@x.com", s.ROLE_SOURCE)]
    g = {"PagerDuty v2": {"status": "answered", "reason": "", "people": [{"email": "c@x.com"}]}}
    s.add_role_fallback(g, ["Account Admin"], existing)
    assert g[s.ROLE_SOURCE]["status"] == "superseded"
    answered = {k: v["people"] for k, v in g.items() if v["status"] in ("answered", "superseded")}
    up, rm, _ = s.plan(existing, answered, USERS, NOW)
    assert [u["email"] for u in up] == ["c@x.com"] and rm == ["a@x.com", "b@x.com"]


def test_nothing_superseded_when_there_were_no_role_rows(monkeypatch):
    _role_users(monkeypatch)
    g = {"PagerDuty v2": {"status": "answered", "reason": "", "people": [{"email": "c@x.com"}]}}
    s.add_role_fallback(g, ["Account Admin"], [row("d@x.com", "manual")])
    assert s.ROLE_SOURCE not in g


def test_role_fallback_with_nobody_in_the_roles_changes_nothing(monkeypatch):
    _role_users(monkeypatch, people=[])
    g = {"PagerDuty v2": {"status": "unavailable", "reason": "", "people": []}}
    s.add_role_fallback(g, ["Analyst"], [])
    assert g[s.ROLE_SOURCE]["status"] == "empty"


def test_parse_roles():
    assert s.parse_roles("Instance Administrator, Account Admin,,") == ["Instance Administrator", "Account Admin"]


def test_a_row_stays_with_the_source_that_owns_it():
    existing = [row("a@x.com", "manual")]
    up, rm, detail = s.plan(existing, {s.ROLE_SOURCE: [{"email": "a@x.com"}, {"email": "b@x.com"}]}, USERS, NOW)
    assert [(u["email"], u["source"]) for u in up] == [("b@x.com", s.ROLE_SOURCE)]
    assert rm == [] and detail[s.ROLE_SOURCE]["held_by_other_source"] == ["a@x.com"]
    # Superseding the role source later removes only its own rows.
    existing = [row("a@x.com", "manual"), row("b@x.com", s.ROLE_SOURCE)]
    _, rm, _ = s.plan(existing, {s.ROLE_SOURCE: [], "PagerDuty v2": [{"email": "c@x.com"}]}, USERS, NOW)
    assert rm == ["b@x.com"]


def test_manual_claims_its_people_from_another_source():
    up, rm, _ = s.plan([row("a@x.com", s.ROLE_SOURCE)], {"manual": [{"email": "a@x.com"}]}, USERS, NOW)
    assert [(u["email"], u["source"]) for u in up] == [("a@x.com", "manual")] and rm == []


def test_groups_alone_turn_on_the_fallback(monkeypatch):
    calls = _role_users(monkeypatch)
    g = {"PagerDuty v2": {"status": "not_configured", "reason": "", "people": []}}
    s.add_role_fallback(g, [], [], ["SOC Analysts"])
    assert calls == [[]] and g[s.ROLE_SOURCE]["status"] == "answered"
    assert "groups SOC Analysts" in g[s.ROLE_SOURCE]["reason"]


def test_role_users_matches_a_role_or_a_group(monkeypatch):
    reply = {"reply": [
        {"user_email": "A@x.com", "role_name": "Account Admin", "groups": []},
        {"user_email": "b@x.com", "role_name": None, "groups": ["SOC Analysts"]},
        {"user_email": "c@x.com", "role_name": None, "groups": ["Other"]},
        {"user_email": "d@x.com", "role_name": "Viewer"}]}
    monkeypatch.setattr(s, "core_post", lambda uri, body: (True, reply))
    assert [p["email"] for p in s.role_users(["account admin"], ["soc analysts"])] == ["a@x.com", "b@x.com"]
    assert [p["email"] for p in s.role_users([], ["SOC Analysts"])] == ["b@x.com"]
