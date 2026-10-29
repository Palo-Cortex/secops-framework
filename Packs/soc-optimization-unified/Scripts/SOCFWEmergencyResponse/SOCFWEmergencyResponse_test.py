"""
SOCFWEmergencyResponse_test.py

The shipped emergency policies and actions, against a fake tenant whose
SOCCommandWrapper returns the same entries the real one does (contract tests at
the bottom hold that shape to the real wrapper). Covers which policies fire, which
hosts and accounts may be contained, the role coalesce, the EDR status skip,
escalation (star + raise-only severity, as automation), the status write-back
after a real isolate, and the contained close.

Run: pytest Scripts/SOCFWEmergencyResponse/SOCFWEmergencyResponse_test.py -v
"""
import copy
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)
LISTS = os.path.join(HERE, "..", "..", "Lists")
POLICY = json.load(open(os.path.join(LISTS, "SOCFrameworkPhasePolicy_V3", "SOCFrameworkPhasePolicy_V3_data.json")))
ACTIONS = json.load(open(os.path.join(LISTS, "SOCFrameworkActions_V3", "SOCFrameworkActions_V3_data.json")))
IDENTITY = ["soc-clear-sessions", "soc-revoke-tokens"]


def _get(data, path, default=None):
    cur = data
    for part in str(path).split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return default
        if cur is None:
            return default
    return cur


def _set(data, path, value):
    parts = str(path).split(".")
    cur = data
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


if "demistomock" not in sys.modules:
    mock = types.ModuleType("demistomock")
    for name in ("args", "context", "incident", "debug", "executeCommand", "setContext"):
        setattr(mock, name, lambda *a, **k: None)
    mock.get = _get
    sys.modules["demistomock"] = mock
if "CommonServerPython" not in sys.modules:
    csp = types.ModuleType("CommonServerPython")
    csp.isError = lambda *a, **k: False
    csp.return_results = lambda *a, **k: None
    csp.return_error = lambda *a, **k: None
    csp.CommandResults = object
    sys.modules["CommonServerPython"] = csp

sys.path.insert(0, HERE)
import SOCFWEmergencyResponse as er  # noqa: E402


class Results:
    def __init__(self, readable_output=None, **kw):
        self.readable_output = readable_output


WORKSTATION = {"hostname": "hobgoblin", "os": "Windows 10", "ip": "10.20.20.5"}
DC = {"hostname": "bannik", "os": "Windows Server 2019", "ip": "10.20.10.9"}


class Tenant:
    """Lists, one issue's context, a case, and a wrapper whose outcome is set per action."""

    def __init__(self, assessment=None, category="Identity", key="ds_okta_systemlog",
                 name="Okta - suspicious sign-in", ruleid=None, tenant=None, policy=None,
                 outcome="shadow", host=None, role=None, status=None, case_severity="medium",
                 user="gunter@skt.local", lists=None):
        self.lists = {"SOCFrameworkPhasePolicy_V3": copy.deepcopy(policy or POLICY),
                      "SOCFrameworkActions_V3": copy.deepcopy(ACTIONS)}
        self.lists.update(lists or {})
        if tenant is not None:
            self.lists["SOCFWTenantConfig"] = tenant
        self.ctx = {"SOCFramework": {"Product": {"category": category, "key": key},
                                     "Artifacts": {"Identity": {"User": {"UPN": user}}}}}
        if host:
            self.ctx["SOCFramework"]["Artifacts"]["Endpoint"] = {
                "Hostname": host["hostname"], "OSVersion": host.get("os"), "IPAddress": host.get("ip"),
                "AgentID": "aid-1"}
            self.ctx["SOCFramework"]["Endpoint"] = {"hostname": host["hostname"]}
            if role:
                self.ctx["SOCFramework"]["Endpoint"]["role"] = role
            if status:
                self.ctx["SOCFramework"]["Endpoint"]["containment_status"] = status
        if assessment is not None:
            self.ctx["Assessment"] = {"AI": assessment}
        self.incident = {"id": "100", "name": name, "parentXDRIncident": "INCIDENT-500"}
        if ruleid is not None:
            self.incident["ruleid"] = ruleid
        self.case_severity = case_severity
        self.outcome = outcome if isinstance(outcome, dict) else {}
        self.default_outcome = outcome if isinstance(outcome, str) else "shadow"
        self.calls, self.rows, self.out, self.set_issue = [], [], [], []

    def execute(self, command, args):
        if command == "getList":
            name = args["listName"]
            if name not in self.lists:
                return [{"Type": 4, "Contents": f" - Item not found (8) on list [{name}] (2609)"}]
            v = self.lists[name]
            return [{"Type": 1, "Contents": v if isinstance(v, str) else json.dumps(v)}]
        if command == "socfw-post-to-dataset":
            self.rows.append(json.loads(args["JSON"]))
            return [{"Type": 1, "Contents": "ok"}]
        if command == "setIssue":
            self.set_issue.append(dict(args))
            return [{"Type": 1, "Contents": "done"}]
        if command == "core-api-post":
            if self.case_severity is None:
                return [{"Type": 4, "Contents": "boom"}]
            return [{"Type": 1, "Contents": {"response": {"reply": {"DATA": [
                {"case_id": 500, "severity": self.case_severity}]}}}}]
        if command == "SOCCommandWrapper":
            self.calls.append(dict(args))
            action = args["action"]
            mode = self.outcome.get(action, self.default_outcome)
            rec = {"action": action, "vendor": "Okta v2", "command": "x", "args": {}}
            resolved = {"Type": 1, "ContentsFormat": "json",
                        "Contents": dict(rec, shadow_mode=mode == "shadow"),
                        "HumanReadable": "### SOC Framework - Universal Command Resolved\n```json"}
            if mode == "shadow":
                return [resolved, {"Type": 1, "ContentsFormat": "json",
                                   "Contents": dict(rec, shadow_mode=True, success=False),
                                   "HumanReadable": "### SOC Framework - SHADOW MODE (Command Not Executed)"}]
            if mode == "executed":
                return [resolved, {"Type": 1, "ContentsFormat": "json",
                                   "Contents": dict(rec, shadow_mode=False, success=True),
                                   "HumanReadable": "### SOC Framework - Command Success"}]
            if mode == "skipped":
                return [{"Type": 1, "ContentsFormat": "json",
                         "Contents": {"reason": "all context-derived command args resolved empty"},
                         "HumanReadable": f"### SOC Framework - {action}: skipped (no artifact to act on)"},
                        {"Type": 1, "Contents": f"{action} skipped - no non-empty artifact for x"}]
            if mode == "failed":
                return [resolved, {"Type": 1, "ContentsFormat": "json",
                                   "Contents": dict(rec, shadow_mode=False, success=False,
                                                    error="401 Unauthorized"),
                                   "HumanReadable": "### SOC Framework - Command Failure"}]
            if mode == "error":
                return [{"Type": 4, "Contents": f"{action} takes no target"}]
            return [{"Type": 1, "Contents": "done"}]
        return []

    def run(self):
        d = er.demisto   # the module the script imported; the contract tests swap sys.modules
        d.args = lambda: {}
        d.context = lambda: copy.deepcopy(self.ctx)
        d.incident = lambda: self.incident
        d.executeCommand = self.execute
        d.setContext = lambda k, v: _set(self.ctx, k, v)
        er.isError = lambda res: any(isinstance(e, dict) and e.get("Type") == 4 for e in (res or []))
        er.CommandResults = Results
        er.return_results = self.out.append
        er.main()
        return self

    def dispatched(self, actor=None):
        return [c["action"] for c in self.calls if actor is None or c["Action_Actor"] == actor]

    def decision(self):
        return [r for r in self.rows if r["event_type"] == "emergency_decision"][-1]

    def statuses(self):
        return dict(p.split("=", 1) for p in self.decision().get("action_status", "").split("; ") if p)


MAL_HIGH = {"verdict": "malicious", "confidence": "high", "exposure": "executed",
            "already_contained": False, "primary_entity_type": "identity"}


def a(**kw):
    return dict(MAL_HIGH, **kw)


def endpoint(host=WORKSTATION, **kw):
    kw.setdefault("category", "Endpoint")
    kw.setdefault("key", "ds_crowdstrike_falcon_event")
    return Tenant(a(primary_entity_type="endpoint"), host=host, **kw)


# ── Which policies fire ──────────────────────────────────────────────────────

def test_identity_issue_runs_the_identity_containment_as_issue_emergency():
    t = Tenant(a()).run()
    assert t.dispatched(er.ACTOR) == IDENTITY
    assert [c["Phase"] for c in t.calls if c["Action_Actor"] == er.ACTOR] == ["containment", "containment"]


def test_about_is_the_category_not_the_entity():
    """An email click whose user the model names is not an identity compromise."""
    t = Tenant(a(primary_entity_type="identity", exposure="executed"), category="Email",
               key="ds_proofpoint_tap_v2_generic_alert").run()
    assert "identity_compromise" not in t.decision()["policy"]
    assert t.dispatched(er.ACTOR) == ["soc-retract-email"]
    # No domain on the issue: nothing to block, and nothing to escalate for it.
    assert t.statuses()["soc-block-domain"] == "none"


def test_entity_type_narrows_when_a_policy_names_it():
    tenant = {"emergency": {"policies": {"identity_compromise": {"entity_type": ["identity"]}}}}
    assert Tenant(a(primary_entity_type="ip"), tenant=tenant).run().dispatched(er.ACTOR) == []
    assert Tenant(a(), tenant=tenant).run().dispatched(er.ACTOR) == IDENTITY


def test_endpoint_policy_needs_execution():
    t = Tenant(a(primary_entity_type="endpoint", exposure="attempted"), category="Endpoint",
               key="ds_crowdstrike_falcon_event", host=WORKSTATION).run()
    assert t.dispatched() == [] and t.decision()["status"] == "no_match"


@pytest.mark.parametrize("change", [{"verdict": "suspicious"}, {"confidence": "medium"},
                                    {"verdict": None}, {"confidence": ""}])
def test_shipped_gate_is_malicious_at_high_confidence(change):
    assert Tenant(a(**change)).run().dispatched() == []


def test_already_contained_is_never_acted_on():
    t = Tenant(a(already_contained=True)).run()
    assert t.dispatched() == [] and t.decision()["status"] == "already_contained"


def test_no_assessment_does_nothing():
    t = Tenant(None).run()
    assert t.dispatched() == [] and t.decision()["status"] == "unavailable"


def test_section_off_does_nothing():
    policy = copy.deepcopy(POLICY)
    policy["phases"]["triage"]["emergency"]["enabled"] = False
    t = Tenant(a(), policy=policy).run()
    assert t.dispatched() == [] and t.decision()["status"] == "disabled"


# ── Tenant policies ──────────────────────────────────────────────────────────

SPAMHAUS = {"rule_id": ["345"], "verdict": ["any"], "confidence": "any", "actions": IDENTITY}


def test_tenant_lowers_the_gate_on_a_shipped_policy_by_its_label():
    tenant = {"emergency": {"policies": {"identity_compromise": {"confidence": "medium"}}}}
    assert Tenant(a(confidence="medium"), tenant=tenant).run().dispatched(er.ACTOR) == IDENTITY


def test_tenant_turns_a_shipped_policy_off():
    tenant = {"emergency": {"policies": {"identity_compromise": {"enabled": False}}}}
    assert Tenant(a(), tenant=tenant).run().dispatched() == []


def test_rule_id_policy_fires_on_its_detection_whatever_the_verdict():
    tenant = {"emergency": {"policies": {"okta_spamhaus": SPAMHAUS,
                                         "identity_compromise": {"enabled": False}}}}
    t = Tenant(a(verdict="suspicious", confidence="low"), ruleid="345", tenant=tenant).run()
    assert t.dispatched(er.ACTOR) == IDENTITY and t.decision()["policy"] == "okta_spamhaus"
    assert Tenant(a(verdict="suspicious"), ruleid="346", tenant=tenant).run().dispatched() == []


def test_rule_id_is_read_from_custom_fields_too():
    tenant = {"emergency": {"policies": {"okta_spamhaus": SPAMHAUS}}}
    t = Tenant(a(verdict="suspicious"), tenant=tenant)
    t.incident["CustomFields"] = {"ruleid": "345"}
    assert t.run().dispatched(er.ACTOR) == IDENTITY


def test_name_contains_is_case_insensitive():
    tenant = {"emergency": {"policies": {"okta_spamhaus": {"name_contains": ["spamhaus"], "actions": IDENTITY}}}}
    assert "okta_spamhaus" in Tenant(a(), name="TDE – OKTA Spamhaus", tenant=tenant).run().decision()["policy"]


def test_source_narrows_to_one_data_source():
    tenant = {"emergency": {"policies": {"identity_compromise": {"source": ["ds_okta_systemlog"]}}}}
    assert Tenant(a(), tenant=tenant).run().dispatched(er.ACTOR) == IDENTITY
    assert Tenant(a(), key="ds_msft_azure_ad", tenant=tenant).run().dispatched() == []


def test_matching_policies_run_each_action_once():
    tenant = {"emergency": {"policies": {"okta_spamhaus": dict(SPAMHAUS, actions=["soc-revoke-tokens",
                                                                                  "soc-disable-user"])}}}
    assert Tenant(a(), ruleid="345", tenant=tenant).run().dispatched(er.ACTOR) == IDENTITY + ["soc-disable-user"]


def test_only_containment_runs_here():
    """Reset password is eradication: excluded, not dispatched, and not a reason to escalate."""
    tenant = {"emergency": {"policies": {"identity_compromise": {"actions": IDENTITY + ["soc-reset-password"]}}}}
    t = Tenant(a(), tenant=tenant, outcome="executed").run()
    assert "soc-reset-password" not in t.dispatched()
    assert t.statuses()["soc-reset-password"] == "excluded"
    assert er.STAR_ACTION not in t.dispatched()
    assert er.CLOSE_ACTION in t.dispatched()


@pytest.mark.parametrize("bad", [{"actions": IDENTITY}, {"rule_id": ["345"]}])
def test_a_policy_with_no_subject_or_no_actions_never_fires(bad):
    tenant = {"emergency": {"policies": {"identity_compromise": {"enabled": False}, "x": bad}}}
    assert Tenant(a(), ruleid="345", tenant=tenant).run().dispatched() == []


# ── Which hosts may be contained ─────────────────────────────────────────────

def test_a_workstation_is_isolated():
    assert endpoint().run().dispatched(er.ACTOR) == ["soc-isolate-endpoint"]


def test_the_domain_controller_is_never_isolated_and_is_escalated():
    t = endpoint(host=DC).run()
    assert "soc-isolate-endpoint" not in t.dispatched()
    assert t.statuses()["soc-isolate-endpoint"] == "blocked"
    assert "role server (operating system" in t.decision()["blocked_reason"]
    assert t.dispatched(er.TRIAGE_ACTOR) == [er.STAR_ACTION, er.SEVERITY_ACTION]
    assert [c.get("target") for c in t.calls if c["action"] == er.SEVERITY_ACTION] == ["critical"]


def test_the_edr_role_wins_over_the_os():
    assert endpoint(role="server").run().statuses()["soc-isolate-endpoint"] == "blocked"


def test_the_tenant_role_entry_wins_over_everything():
    tenant = {"emergency": {"role": ["host:bannik:workstation"]}}
    assert endpoint(host=DC, role="server", tenant=tenant).run().dispatched(er.ACTOR) == ["soc-isolate-endpoint"]


@pytest.mark.parametrize("os_text, isolated", [("macOS 14.2", True), ("Windows 11 Pro", True),
                                               ("Ubuntu 22.04", False), (None, False)])
def test_role_from_the_os_when_no_one_reports_it(os_text, isolated):
    t = endpoint(host={"hostname": "box1", "os": os_text}).run()
    assert (t.dispatched(er.ACTOR) == ["soc-isolate-endpoint"]) is isolated
    if not isolated:
        assert "role unknown" in t.decision()["blocked_reason"]


def test_containable_roles_any_turns_the_role_check_off():
    tenant = {"emergency": {"containable_roles": ["any"]}}
    assert endpoint(host={"hostname": "box1", "os": "Ubuntu"}, tenant=tenant).run().dispatched(er.ACTOR) == \
        ["soc-isolate-endpoint"]


@pytest.mark.parametrize("entry", ["host:BANNIK", "host:bann*", "ip:10.20.10.9", "cidr:10.20.10.0/24",
                                   "10.20.10.9", "bannik"])
def test_protect_by_name_pattern_ip_or_range(entry):
    tenant = {"emergency": {"protect": [entry], "containable_roles": ["any"]}}
    t = endpoint(host=DC, tenant=tenant).run()
    assert t.statuses()["soc-isolate-endpoint"] == "blocked"
    assert "protected (this tenant" in t.decision()["blocked_reason"]


def test_protect_ignores_the_domain_on_the_host_name():
    tenant = {"emergency": {"protect": ["host:hobgoblin"]}}
    t = endpoint(host={"hostname": "HOBGOBLIN.skt.local", "os": "Windows 10"}, tenant=tenant).run()
    assert t.statuses()["soc-isolate-endpoint"] == "blocked"


def test_protect_from_an_xsiam_list():
    tenant = {"emergency": {"protect": ["list:CriticalServers"], "containable_roles": ["any"]}}
    t = endpoint(tenant=tenant, lists={"CriticalServers": "# servers\nexchange01\n10.20.20.0/24\n"}).run()
    assert t.statuses()["soc-isolate-endpoint"] == "blocked"


def test_containable_hosts_replaces_the_role_check():
    tenant = {"emergency": {"containable_hosts": ["host:box*"]}}
    assert endpoint(host={"hostname": "box1", "os": "Ubuntu"}, tenant=tenant).run().dispatched(er.ACTOR) == \
        ["soc-isolate-endpoint"]
    assert "not in containable_hosts" in endpoint(tenant=tenant).run().decision()["blocked_reason"]


def test_protect_wins_over_containable_hosts():
    tenant = {"emergency": {"containable_hosts": ["host:*"], "protect": ["host:bannik"]}}
    assert endpoint(host=DC, tenant=tenant).run().statuses()["soc-isolate-endpoint"] == "blocked"


def test_a_protected_account_is_never_contained():
    tenant = {"emergency": {"protect": ["account:breakglass*"]}}
    t = Tenant(a(), user="BREAKGLASS01@corp.example", tenant=tenant).run()
    assert t.dispatched(er.ACTOR) == []
    assert set(t.statuses().values()) == {"blocked"}
    assert er.STAR_ACTION in t.dispatched(er.TRIAGE_ACTOR)


def test_host_settings_do_not_touch_account_actions():
    tenant = {"emergency": {"containable_roles": ["server"]}}
    assert Tenant(a(), tenant=tenant).run().dispatched(er.ACTOR) == IDENTITY


# ── Contain once ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("status", ["contained", "containment_pending"])
def test_a_host_the_edr_reports_contained_is_not_isolated_again(status):
    t = endpoint(status=status, outcome="executed").run()
    assert "soc-isolate-endpoint" not in t.dispatched()
    assert t.statuses()["soc-isolate-endpoint"] == "already"
    assert er.STAR_ACTION not in t.dispatched()
    assert er.CLOSE_ACTION in t.dispatched()


def test_a_real_isolate_marks_the_host_pending_for_the_next_issue():
    t = endpoint(outcome="executed").run()
    assert t.set_issue == [{"endpointisolationstatus": "containment_pending"}]
    assert t.ctx["SOCFramework"]["Endpoint"]["containment_status"] == "containment_pending"


def test_a_shadowed_isolate_writes_no_status():
    t = endpoint(outcome="shadow").run()
    assert t.set_issue == [] and "containment_status" not in t.ctx["SOCFramework"]["Endpoint"]


# ── Escalation ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("held", ["skipped", "failed", "error", "none"])
def test_containment_that_did_not_happen_is_escalated(held):
    t = Tenant(a(), outcome={"soc-clear-sessions": held, "soc-revoke-tokens": "executed"}).run()
    assert t.dispatched(er.TRIAGE_ACTOR)[:1] == [er.STAR_ACTION]
    assert t.decision()["contained"] is False


def test_a_shadowed_action_is_not_escalated():
    t = Tenant(a(), outcome="shadow").run()
    assert t.dispatched(er.TRIAGE_ACTOR) == []
    assert "escalation" not in t.decision()


@pytest.mark.parametrize("current, raised", [("low", True), ("medium", True), ("high", True), ("critical", False)])
def test_severity_is_raised_only(current, raised):
    t = endpoint(host=DC, case_severity=current).run()
    assert (er.SEVERITY_ACTION in t.dispatched()) is raised
    assert er.STAR_ACTION in t.dispatched()


def test_unreadable_case_severity_stars_but_never_raises_blind():
    t = endpoint(host=DC, case_severity=None).run()
    assert t.dispatched(er.TRIAGE_ACTOR) == [er.STAR_ACTION]
    assert "not raising blind" in t.decision()["escalation"]


def test_the_tenant_sets_the_escalation_severity():
    t = endpoint(host=DC, tenant={"emergency": {"escalate_severity": "high"}}).run()
    assert [c.get("target") for c in t.calls if c["action"] == er.SEVERITY_ACTION] == ["high"]


# ── Closing ──────────────────────────────────────────────────────────────────

def test_shadowed_actions_never_close_the_issue():
    t = Tenant(a(), outcome="shadow").run()
    assert er.CLOSE_ACTION not in t.dispatched()
    assert t.decision()["contained"] is False and "did not run for real" in t.decision()["decision_reason"]
    assert t.ctx["SOCFramework"]["Emergency"]["closed"] is False


def test_closes_as_contained_as_automation_only_when_every_action_really_ran():
    t = Tenant(a(), outcome="executed").run()
    assert t.dispatched(er.ACTOR) == IDENTITY
    assert t.dispatched(er.TRIAGE_ACTOR) == [er.CLOSE_ACTION]
    notes = t.ctx["SOCFramework"]["Emergency"]["close_notes"]
    assert "identity_compromise" in notes and "soc-revoke-tokens" in notes
    assert t.decision()["close_status"] == "executed" and t.ctx["SOCFramework"]["Emergency"]["closed"] is True


def test_a_blocked_host_keeps_the_issue_open():
    t = endpoint(host=DC, outcome="executed").run()
    assert er.CLOSE_ACTION not in t.dispatched() and t.decision()["contained"] is False


def test_a_shadowed_close_is_recorded_as_shadow():
    t = Tenant(a(), outcome={**{x: "executed" for x in IDENTITY}, er.CLOSE_ACTION: "shadow"}).run()
    assert t.decision()["close_status"] == "shadow" and t.ctx["SOCFramework"]["Emergency"]["closed"] is False


def test_closing_off_in_policy_never_closes():
    policy = copy.deepcopy(POLICY)
    policy["phases"]["triage"]["emergency"]["close_when_contained"] = False
    assert er.CLOSE_ACTION not in Tenant(a(), outcome="executed", policy=policy).run().dispatched()


def test_a_wrapper_that_raises_reads_as_failed():
    t = Tenant(a(), outcome="executed")
    real = t.execute

    def boom(command, args):
        if command == "SOCCommandWrapper" and args["action"] == "soc-revoke-tokens":
            raise RuntimeError("docker died")
        return real(command, args)
    t.execute = boom
    t.run()
    assert t.statuses()["soc-revoke-tokens"] == "failed" and t.decision()["contained"] is False


# ── What ships ───────────────────────────────────────────────────────────────

def test_every_shipped_policy_runs_only_containment():
    section = POLICY["phases"]["triage"]["emergency"]
    assert section["enabled"] is True
    assert section["containable_roles"] == ["workstation"] and section["escalate_severity"] == "critical"
    assert section["protect"] == [] and section["containable_hosts"] == [] and section["role"] == []
    for p in section["policies"]:
        assert p["about"], p["policy"]
        assert not {"rule_id", "name_contains", "source"} & set(p), p["policy"]
        for name in p["actions"]:
            assert ACTIONS[name]["phase"] == "containment", name


def test_triage_rows_never_carry_issue_emergency():
    for name in (er.CLOSE_ACTION, er.SEVERITY_ACTION):
        assert set(ACTIONS[name]["shadow_mode_by_actor"]) == {"analyst", "ai", "automation"}
        assert all(ACTIONS[name]["shadow_mode_by_actor"].values())


def test_close_and_severity_rows():
    close = ACTIONS[er.CLOSE_ACTION]["responses"]["Builtin"]["inline_args"]
    assert close["closeReason"] == "Resolved - True Positive"
    assert close["closeNotes"] == "${" + er.NOTES_KEY + "}"
    sev = ACTIONS[er.SEVERITY_ACTION]
    assert sev["target_arg"] == "manual_severity"
    assert sev["responses"]["Builtin"] == {"command": "setParentIncidentFields",
                                           "inline_args": {"manual_severity": ""}}


def test_merges_are_the_same_ones_socfwconfig_shows():
    import builtins
    import importlib
    sys.path.insert(0, os.path.join(HERE, "..", "SOCFWConfig"))
    for n in ("demisto", "CommandResults", "return_results", "return_error"):
        setattr(builtins, n, getattr(builtins, n, None))
    cfg_mod = importlib.import_module("SOCFWConfig")
    section = POLICY["phases"]["triage"]["emergency"]
    for tenant in (None, {}, {"emergency": {"policies": {"identity_compromise": {"enabled": False}}}},
                   {"emergency": {"policies": {"okta_spamhaus": SPAMHAUS}, "protect": ["host:bannik"],
                                  "containable_roles": ["any"], "escalate_severity": "high"}},
                   {"emergency": {"policies": "garbled"}}):
        assert er.merge_policies(section, tenant) == cfg_mod.merge_policies(section, tenant)
        assert er.merge_settings(section, tenant) == cfg_mod.merge_settings(section, tenant)


# ── The wrapper's entries, from the real wrapper ─────────────────────────────

def _wrapper(action, tenant_cfg, ctx_user="00u1"):
    sys.path.insert(0, os.path.join(HERE, "..", "SOCCommandWrapper"))
    from SOCCommandWrapper_test import load_script
    script, demisto = load_script()
    demisto._args = {"action": action, "list_name": "SOCFrameworkActions_V3",
                     "output_key": er.DISPATCH_KEY, "Action_Actor": "issue_emergency"}
    demisto._context = {"SOCFramework": {"RunID": "r", "Artifacts": (
        {"Identity": {"User": {"ID": ctx_user}}} if ctx_user else {}),
        "Product": {"key": "ds_okta_systemlog", "category": "Identity", "response": "Okta v2"}}}

    def _route(args):
        name = (args or {}).get("listName")
        if name == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps({action: ACTIONS[action]})}]
        if name == "SOCFWTenantConfig":
            return [{"Contents": json.dumps(tenant_cfg)}]
        return [{"Type": 4, "Contents": f" - Item not found (8) on list [{name}] (2609)"}]

    demisto._command_responses = {
        "getList": _route,
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "okta-clear-user-sessions": [{"Type": 1, "Contents": "ok"}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }
    script.main()
    return er.records_from(action, demisto._results)


def test_real_wrapper_shadowed_reads_as_shadow():
    assert er.outcome_of("soc-clear-sessions", _wrapper("soc-clear-sessions", {}))[0] == "shadow"


def test_real_wrapper_live_reads_as_executed():
    recs = _wrapper("soc-clear-sessions", {"shadow": {"soc-clear-sessions": {"issue_emergency": False}}})
    assert er.outcome_of("soc-clear-sessions", recs)[0] == "executed"


def test_real_wrapper_skip_reads_as_skipped():
    recs = _wrapper("soc-clear-sessions", {"shadow": {"soc-clear-sessions": {"issue_emergency": False}}},
                    ctx_user=None)
    assert er.outcome_of("soc-clear-sessions", recs)[0] == "skipped"


def test_not_configured_skip_reads_as_skipped():
    entries = [{"Type": 1, "ContentsFormat": "json",
                "Contents": {"reason": "list_id not configured", "action": "soc-block-domain"},
                "HumanReadable": "### SOC Framework - soc-block-domain: skipped (vendor not configured)\n```json"}]
    assert er.outcome_of("soc-block-domain", er.records_from("soc-block-domain", entries))[0] == "skipped"


def test_a_record_for_another_action_is_not_this_actions_outcome():
    entries = [{"Type": 1, "Contents": {"action": "soc-revoke-tokens", "success": True, "shadow_mode": False},
                "HumanReadable": "### x"}]
    assert er.outcome_of("soc-clear-sessions", er.records_from("soc-clear-sessions", entries))[0] == "no_record"


def test_the_resolved_entry_alone_is_not_an_outcome():
    entries = [{"Type": 1, "Contents": {"action": "a", "shadow_mode": False},
                "HumanReadable": "### SOC Framework - Universal Command Resolved"}]
    assert er.outcome_of("a", er.records_from("a", entries))[0] == "no_record"


# ── Blocking a C2 destination ────────────────────────────────────────────────

NETWORK_BLOCKS = ["soc-block-network-indicator", "soc-block-domain"]


def c2(ips=("176.59.15.33",), domains=("anto-int.com",), scores=None, tactic="TA0011",
       host=WORKSTATION, **kw):
    """A CrowdStrike C2 issue: tactic on the issue, destinations in context, reputation."""
    t = endpoint(host=host, **kw)
    # Where the NIST IR map puts them for an endpoint issue - not the block keys.
    ep = t.ctx["SOCFramework"]["Endpoint"]
    if ips:
        ep["remote_ips"] = list(ips)
    if domains:
        ep["dns_queries"] = list(domains)
    if scores is None:
        scores = {v: 3 for v in list(ips or []) + list(domains or [])}
    t.ctx["DBotScore"] = [{"Indicator": k, "Score": v, "Type": "ip", "Vendor": "VirusTotal"}
                          for k, v in scores.items()]
    t.incident["CustomFields"] = {"mitretacticid": [tactic], "mitretacticname": ["Command and Control"]}
    return t


def blocks(t):
    return [(c["action"], c.get("target")) for c in t.calls
            if c["Action_Actor"] == er.ACTOR and c["action"] in NETWORK_BLOCKS]


def test_c2_blocks_each_malicious_destination_as_issue_emergency():
    t = c2().run()
    assert "endpoint_c2" in t.decision()["policy"]
    assert blocks(t) == [("soc-block-network-indicator", "176.59.15.33"),
                         ("soc-block-domain", "anto-int.com")]
    assert all(c["Phase"] == "containment" for c in t.calls if c["action"] in NETWORK_BLOCKS)


def test_the_tactic_decides_not_the_issue_name():
    t = c2(tactic="TA0008").run()
    assert "endpoint_c2" not in t.decision()["policy"]
    assert blocks(t) == []


def test_tactic_by_name_in_a_tenant_policy():
    tenant = {"emergency": {"policies": {"endpoint_c2": {"tactic": ["command and control"]}}}}
    t = c2(tactic="T-unknown", tenant=tenant).run()
    assert "endpoint_c2" in t.decision()["policy"]


def test_a_tactic_alone_is_a_subject():
    policy = {"policy": "any_c2", "tactic": ["TA0011"], "actions": ["soc-block-domain"]}
    assert er.evaluate(policy, er.facts_for(MAL_HIGH, {}, {"CustomFields": {"mitretacticid": ["TA0011"]}}))[0]


def test_no_malicious_reputation_is_escalated_not_blocked():
    t = c2(scores={"176.59.15.33": 2}).run()
    st = t.statuses()
    assert blocks(t) == []
    assert st["soc-block-network-indicator 176.59.15.33"] == "blocked"
    assert "score 2" in t.decision()["blocked_reason"]
    assert "not scored" in t.decision()["blocked_reason"]
    assert er.STAR_ACTION in t.dispatched(er.TRIAGE_ACTOR)


@pytest.mark.parametrize("ip", ["10.20.20.102", "192.168.1.7", "127.0.0.1", "169.254.1.1", "fd00::1"])
def test_an_internal_address_is_left_to_a_person(ip):
    t = c2(ips=(ip,), domains=(), scores={ip: 3}).run()
    assert blocks(t) == []
    assert t.statuses()[f"soc-block-network-indicator {ip}"] == "blocked"
    assert "internal destination" in t.decision()["blocked_reason"]
    assert er.STAR_ACTION in t.dispatched(er.TRIAGE_ACTOR)


@pytest.mark.parametrize("name", ["skt.local", "dc01", "files.corp", "x.internal"])
def test_an_internal_domain_is_left_to_a_person(name):
    t = c2(ips=(), domains=(name,), scores={name: 3}).run()
    assert blocks(t) == []
    assert "internal destination" in t.decision()["blocked_reason"]


@pytest.mark.parametrize("entry,value", [("domain:anto-int.com", "anto-int.com"),
                                         ("domain:*.example.com", "c2.example.com"),
                                         ("domain:example.com", "deep.c2.example.com"),
                                         ("ip:176.59.15.33", "176.59.15.33"),
                                         ("cidr:176.59.0.0/16", "176.59.15.33")])
def test_protect_covers_destinations(entry, value):
    ip = value[0].isdigit()
    t = c2(ips=(value,) if ip else (), domains=() if ip else (value,),
           tenant={"emergency": {"protect": [entry]}}).run()
    assert blocks(t) == []
    assert "protected" in t.decision()["blocked_reason"]


def test_each_destination_is_checked_on_its_own():
    t = c2(ips=("176.59.15.33", "91.52.62.64", "10.20.20.102"), domains=(),
           scores={"176.59.15.33": 3, "91.52.62.64": 1, "10.20.20.102": 3}).run()
    st = t.statuses()
    assert blocks(t) == [("soc-block-network-indicator", "176.59.15.33")]
    assert st["soc-block-network-indicator 91.52.62.64"] == "blocked"
    assert st["soc-block-network-indicator 10.20.20.102"] == "blocked"


def test_reputation_is_matched_regardless_of_case():
    t = c2(ips=(), domains=("Anto-Int.COM",), scores={"anto-int.com": 3}).run()
    assert blocks(t) == [("soc-block-domain", "Anto-Int.COM")]


def test_a_c2_issue_with_no_destination_is_none_not_an_escalation():
    t = c2(ips=(), domains=()).run()
    st = t.statuses()
    assert st["soc-block-network-indicator"] == "none" and st["soc-block-domain"] == "none"
    assert blocks(t) == []
    assert er.STAR_ACTION not in t.dispatched(er.TRIAGE_ACTOR)


def test_a_dc_still_gets_its_c2_blocked_though_isolation_is_refused():
    t = c2(host=DC).run()
    st = t.statuses()
    assert st["soc-isolate-endpoint"] == "blocked"
    assert blocks(t) == [("soc-block-network-indicator", "176.59.15.33"),
                         ("soc-block-domain", "anto-int.com")]


def test_executed_blocks_count_toward_the_close():
    t = c2(outcome="executed").run()
    assert t.decision()["contained"] is True
    assert er.CLOSE_ACTION in t.dispatched(er.TRIAGE_ACTOR)


def test_an_unblocked_destination_keeps_the_issue_open():
    t = c2(scores={"176.59.15.33": 3}, outcome="executed").run()   # domain not scored
    assert t.decision()["contained"] is False
    assert er.CLOSE_ACTION not in t.dispatched(er.TRIAGE_ACTOR)


def test_the_block_keys_are_read_too():
    t = c2(ips=(), domains=())
    t.ctx["SOCFramework"]["Artifacts"]["Network"] = {"Destination": {"IP": ["176.59.15.33"]}}
    t.ctx["DBotScore"] = [{"Indicator": "176.59.15.33", "Score": 3}]
    assert blocks(t.run()) == [("soc-block-network-indicator", "176.59.15.33")]


def test_a_value_in_both_places_is_blocked_once():
    t = c2(domains=())
    t.ctx["SOCFramework"]["Artifacts"]["Network"] = {"Destination": {"IP": ["176.59.15.33"]}}
    assert blocks(t.run()) == [("soc-block-network-indicator", "176.59.15.33")]


def test_only_network_blocks_get_the_destination_check():
    assert er.network_paths(ACTIONS["soc-block-network-indicator"]) == [
        "SOCFramework.Artifacts.Network.Destination.IP"]
    assert er.network_paths(ACTIONS["soc-block-domain"]) == ["SOCFramework.Artifacts.Network.DNS.Query"]
    for other in ("soc-retract-email", "soc-quarantine-files", "soc-block-sender", "soc-isolate-endpoint"):
        assert er.network_paths(ACTIONS[other]) == []


def test_every_block_response_names_its_target_arg():
    for action in NETWORK_BLOCKS:
        for vendor, data in ACTIONS[action]["responses"].items():
            arg = data.get("target_arg") or ACTIONS[action].get("target_arg")
            assert arg and str(data["inline_args"][arg]).startswith("${SOCFramework.Artifacts.Network."), vendor
