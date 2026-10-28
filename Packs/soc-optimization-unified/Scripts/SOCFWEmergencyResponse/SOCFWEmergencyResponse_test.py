"""
SOCFWEmergencyResponse_test.py

The shipped emergency policies and the shipped actions, against a fake tenant whose
SOCCommandWrapper appends the same records the real one does (a contract test at the
bottom holds that shape to the real wrapper). Every outcome the wrapper can report -
shadow, executed, skipped, failed, nothing - is driven per action.

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
IDENTITY = ["soc-clear-sessions", "soc-revoke-tokens", "soc-reset-password"]


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


class Tenant:
    """Lists, one issue's context, and a wrapper whose outcome is set per action."""

    def __init__(self, assessment=None, category="Identity", key="ds_okta_systemlog",
                 name="Okta - suspicious sign-in", ruleid=None, tenant=None, policy=None,
                 outcome="shadow"):
        self.lists = {"SOCFrameworkPhasePolicy_V3": copy.deepcopy(policy or POLICY),
                      "SOCFrameworkActions_V3": copy.deepcopy(ACTIONS)}
        if tenant is not None:
            self.lists["SOCFWTenantConfig"] = tenant
        self.ctx = {"SOCFramework": {"Product": {"category": category, "key": key}}}
        if assessment is not None:
            self.ctx["Assessment"] = {"AI": assessment}
        self.incident = {"id": "100", "name": name}
        if ruleid is not None:
            self.incident["ruleid"] = ruleid
        self.outcome = outcome if isinstance(outcome, dict) else {}
        self.default_outcome = outcome if isinstance(outcome, str) else "shadow"
        self.calls, self.rows, self.out = [], [], []

    def execute(self, command, args):
        if command == "getList":
            name = args["listName"]
            if name not in self.lists:
                return [{"Type": 4, "Contents": f" - Item not found (8) on list [{name}] (2609)"}]
            return [{"Type": 1, "Contents": json.dumps(self.lists[name])}]
        if command == "socfw-post-to-dataset":
            self.rows.append(json.loads(args["JSON"]))
            return [{"Type": 1, "Contents": "ok"}]
        if command == "SOCCommandWrapper":
            # Entries shaped like the real wrapper's (see the contract tests below).
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
        d = sys.modules["demistomock"]
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

    def dispatched(self):
        return [c["action"] for c in self.calls]

    def decision(self):
        return [r for r in self.rows if r["event_type"] == "emergency_decision"][-1]


MAL_HIGH = {"verdict": "malicious", "confidence": "high", "exposure": "executed",
            "already_contained": False, "primary_entity_type": "identity"}


def a(**kw):
    return dict(MAL_HIGH, **kw)


# ── Which policies fire ──────────────────────────────────────────────────────

def test_identity_issue_runs_the_identity_actions_as_issue_emergency_in_order():
    t = Tenant(a()).run()
    assert t.dispatched() == IDENTITY
    assert {c["Action_Actor"] for c in t.calls} == {"issue_emergency"}
    assert [c["Phase"] for c in t.calls] == ["containment", "containment", "eradication"]


def test_okta_issue_where_the_model_names_the_ip_is_still_about_identity():
    t = Tenant(a(primary_entity_type="ip")).run()
    assert t.dispatched() == IDENTITY


def test_edr_credential_theft_is_about_the_identity_too():
    """CrowdStrike source, category Endpoint, entity identity: both policies, each action once."""
    t = Tenant(a(), category="Endpoint", key="ds_crowdstrike_falcon_event").run()
    assert t.dispatched() == IDENTITY + ["soc-isolate-endpoint"]
    assert t.decision()["policy"] == "identity_compromise, endpoint_execution"


def test_endpoint_policy_needs_execution():
    t = Tenant(a(primary_entity_type="endpoint", exposure="attempted"),
               category="Endpoint", key="ds_crowdstrike_falcon_event").run()
    assert t.dispatched() == []
    assert t.decision()["status"] == "no_match"


def test_email_delivered_retracts():
    t = Tenant(a(primary_entity_type="email", exposure="delivered"), category="Email",
               key="ds_proofpoint_tap_v2_generic_alert").run()
    assert t.dispatched() == ["soc-retract-email"]


@pytest.mark.parametrize("change", [{"verdict": "suspicious"}, {"confidence": "medium"},
                                    {"verdict": None}, {"confidence": ""}])
def test_shipped_gate_is_malicious_at_high_confidence(change):
    t = Tenant(a(**change)).run()
    assert t.dispatched() == []


def test_already_contained_is_never_acted_on():
    t = Tenant(a(already_contained=True)).run()
    assert t.dispatched() == []
    assert t.decision()["status"] == "already_contained"


def test_no_assessment_does_nothing():
    t = Tenant(None).run()
    assert t.dispatched() == [] and t.decision()["status"] == "unavailable"


def test_section_off_does_nothing():
    policy = copy.deepcopy(POLICY)
    policy["phases"]["triage"]["emergency"]["enabled"] = False
    t = Tenant(a(), policy=policy).run()
    assert t.dispatched() == [] and t.decision()["status"] == "disabled"


# ── Tenant policies ──────────────────────────────────────────────────────────

def test_tenant_lowers_the_gate_on_a_shipped_policy_by_its_label():
    tenant = {"emergency": {"policies": {"identity_compromise": {"confidence": "medium"}}}}
    assert Tenant(a(confidence="medium"), tenant=tenant).run().dispatched() == IDENTITY


def test_tenant_turns_a_shipped_policy_off():
    tenant = {"emergency": {"policies": {"identity_compromise": {"enabled": False}}}}
    assert Tenant(a(), tenant=tenant).run().dispatched() == []


SPAMHAUS = {"rule_id": ["345"], "verdict": ["any"], "confidence": "any",
            "actions": IDENTITY}


def test_rule_id_policy_fires_on_its_detection_whatever_the_verdict():
    tenant = {"emergency": {"policies": {"okta_spamhaus": SPAMHAUS,
                                         "identity_compromise": {"enabled": False}}}}
    t = Tenant(a(verdict="suspicious", confidence="low"), ruleid="345", tenant=tenant).run()
    assert t.dispatched() == IDENTITY
    assert t.decision()["policy"] == "okta_spamhaus"


def test_rule_id_policy_leaves_other_detections_alone():
    tenant = {"emergency": {"policies": {"okta_spamhaus": SPAMHAUS,
                                         "identity_compromise": {"enabled": False}}}}
    assert Tenant(a(verdict="suspicious"), ruleid="346", tenant=tenant).run().dispatched() == []
    assert Tenant(a(verdict="suspicious"), tenant=tenant).run().dispatched() == []


def test_rule_id_is_read_from_custom_fields_too():
    tenant = {"emergency": {"policies": {"okta_spamhaus": SPAMHAUS}}}
    t = Tenant(a(verdict="suspicious"), tenant=tenant)
    t.incident["CustomFields"] = {"ruleid": "345"}
    assert t.run().dispatched() == IDENTITY


def test_name_contains_is_case_insensitive():
    tenant = {"emergency": {"policies": {"okta_spamhaus": {
        "name_contains": ["spamhaus"], "actions": IDENTITY}}}}
    t = Tenant(a(), name="TDE – OKTA Spamhaus", tenant=tenant).run()
    assert "okta_spamhaus" in t.decision()["policy"]


def test_source_narrows_to_one_data_source():
    tenant = {"emergency": {"policies": {
        "identity_compromise": {"source": ["ds_okta_systemlog"]}}}}
    assert Tenant(a(), tenant=tenant).run().dispatched() == IDENTITY
    assert Tenant(a(), key="ds_msft_azure_ad", tenant=tenant).run().dispatched() == []


def test_matching_policies_run_each_action_once():
    tenant = {"emergency": {"policies": {"okta_spamhaus": dict(SPAMHAUS, actions=[
        "soc-reset-password", "soc-disable-user"])}}}
    t = Tenant(a(), ruleid="345", tenant=tenant).run()
    assert t.dispatched() == IDENTITY + ["soc-disable-user"]


@pytest.mark.parametrize("bad", [{"actions": IDENTITY}, {"rule_id": ["345"]},
                                 {"about": [], "actions": IDENTITY}])
def test_a_policy_with_no_subject_or_no_actions_never_fires(bad):
    tenant = {"emergency": {"policies": {"identity_compromise": {"enabled": False}, "x": bad}}}
    assert Tenant(a(), ruleid="345", tenant=tenant).run().dispatched() == []


def test_unknown_action_in_a_policy_is_skipped_not_dispatched():
    tenant = {"emergency": {"policies": {"identity_compromise": {"actions": ["soc-made-up"]}}}}
    t = Tenant(a(), tenant=tenant).run()
    assert t.dispatched() == []
    assert "soc-made-up=skipped" in t.decision()["action_status"]


# ── Closing ──────────────────────────────────────────────────────────────────

def test_shadowed_actions_never_close_the_issue():
    t = Tenant(a(), outcome="shadow").run()
    assert "soc-close-issue-contained" not in t.dispatched()
    row = t.decision()
    assert row["contained"] is False and row["close_status"] == "not_attempted"
    assert "did not run for real" in row["decision_reason"]
    assert t.ctx["SOCFramework"]["Emergency"]["closed"] is False


def test_closes_as_contained_only_when_every_action_really_ran():
    t = Tenant(a(), outcome="executed").run()
    assert t.dispatched() == IDENTITY + ["soc-close-issue-contained"]
    notes = t.ctx["SOCFramework"]["Emergency"]["close_notes"]
    assert "identity_compromise" in notes and "soc-reset-password" in notes
    assert t.decision()["contained"] is True and t.decision()["close_status"] == "executed"
    assert t.ctx["SOCFramework"]["Emergency"]["closed"] is True


@pytest.mark.parametrize("held", ["skipped", "failed", "shadow", "none", "error"])
def test_one_action_that_did_not_run_keeps_the_issue_open(held):
    t = Tenant(a(), outcome={"soc-clear-sessions": "executed", "soc-revoke-tokens": held,
                             "soc-reset-password": "executed"}).run()
    assert "soc-close-issue-contained" not in t.dispatched()
    assert t.decision()["contained"] is False


def test_a_shadowed_close_is_recorded_as_shadow():
    t = Tenant(a(), outcome={**{x: "executed" for x in IDENTITY},
                             "soc-close-issue-contained": "shadow"}).run()
    assert t.decision()["close_status"] == "shadow"
    assert t.ctx["SOCFramework"]["Emergency"]["closed"] is False


def test_a_record_for_another_action_is_not_this_actions_outcome():
    entries = [{"Type": 1, "Contents": {"action": "soc-revoke-tokens", "success": True,
                                        "shadow_mode": False}, "HumanReadable": "### x"}]
    assert er.outcome_of("soc-clear-sessions", er.records_from("soc-clear-sessions", entries))[0] == "no_record"


def test_the_resolved_entry_alone_is_not_an_outcome():
    """Resolved carries shadow_mode but no success: it says what will happen, not what did."""
    entries = [{"Type": 1, "Contents": {"action": "a", "shadow_mode": False},
                "HumanReadable": "### SOC Framework - Universal Command Resolved"}]
    assert er.outcome_of("a", er.records_from("a", entries))[0] == "no_record"


def test_a_wrapper_that_raises_reads_as_failed():
    t = Tenant(a(), outcome="executed")
    real = t.execute

    def boom(command, args):
        if command == "SOCCommandWrapper" and args["action"] == "soc-revoke-tokens":
            raise RuntimeError("docker died")
        return real(command, args)
    t.execute = boom
    t.run()
    assert "soc-revoke-tokens=failed" in t.decision()["action_status"]
    assert t.decision()["contained"] is False


def test_closing_off_in_policy_never_closes():
    policy = copy.deepcopy(POLICY)
    policy["phases"]["triage"]["emergency"]["close_when_contained"] = False
    t = Tenant(a(), outcome="executed", policy=policy).run()
    assert "soc-close-issue-contained" not in t.dispatched()


# ── What ships ───────────────────────────────────────────────────────────────

def test_every_shipped_policy_names_real_mutating_actions():
    section = POLICY["phases"]["triage"]["emergency"]
    assert section["enabled"] is True
    for p in section["policies"]:
        assert p["about"], p["policy"]
        assert not {"rule_id", "name_contains", "source"} & set(p), \
            f"{p['policy']}: tenant-local matching does not belong in the shipped list"
        for name in p["actions"]:
            assert name in ACTIONS, name
            assert ACTIONS[name]["phase"] in ("containment", "eradication"), name


def test_close_row_is_shadowed_for_every_actor_and_takes_its_notes_from_this_script():
    row = ACTIONS["soc-close-issue-contained"]
    assert row["shadow_mode_by_actor"] == {"analyst": True, "ai": True, "automation": True,
                                           "issue_emergency": True}
    args = row["responses"]["Builtin"]["inline_args"]
    # The display wording: closeInvestigation stores it as RESOLVED_TRUE_POSITIVE, while
    # the enum string itself is stored as RESOLVED_OTHER (deathstar, 28 Oct 2026).
    assert args["closeReason"] == "Resolved - True Positive"
    assert args["closeNotes"] == "${" + er.NOTES_KEY + "}"


def test_merge_is_the_same_one_socfwconfig_shows():
    sys.path.insert(0, os.path.join(HERE, "..", "SOCFWConfig"))
    import importlib
    import builtins
    for n in ("demisto", "CommandResults", "return_results", "return_error"):
        setattr(builtins, n, getattr(builtins, n, None))
    cfg_mod = importlib.import_module("SOCFWConfig")
    section = POLICY["phases"]["triage"]["emergency"]
    for tenant in (None, {}, {"emergency": {"policies": {"identity_compromise": {"enabled": False}}}},
                   {"emergency": {"policies": {"okta_spamhaus": SPAMHAUS,
                                               "email_delivered": {"confidence": "medium"}}}},
                   {"emergency": {"policies": "garbled"}}):
        assert er.merge_policies(section, tenant) == cfg_mod.merge_policies(section, tenant)


# ── The wrapper's record shape, from the real wrapper ────────────────────────

def _wrapper_records(tenant_cfg, ctx_user="00u1"):
    sys.path.insert(0, os.path.join(HERE, "..", "SOCCommandWrapper"))
    from SOCCommandWrapper_test import load_script
    script, demisto = load_script()
    demisto._args = {"action": "soc-clear-sessions", "list_name": "SOCFrameworkActions_V3",
                     "output_key": er.DISPATCH_KEY, "Action_Actor": "issue_emergency"}
    demisto._context = {"SOCFramework": {"RunID": "r", "Artifacts": (
        {"Identity": {"User": {"ID": ctx_user}}} if ctx_user else {}),
        "Product": {"key": "ds_okta_systemlog", "category": "Identity", "response": "Okta v2"}}}

    def _route(args):
        name = (args or {}).get("listName")
        if name == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps({"soc-clear-sessions": ACTIONS["soc-clear-sessions"]})}]
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
    return er.records_from("soc-clear-sessions", demisto._results)


def test_real_wrapper_shadowed_reads_as_shadow():
    recs = _wrapper_records({})
    assert er.outcome_of("soc-clear-sessions", recs)[0] == "shadow"


def test_real_wrapper_live_reads_as_executed():
    recs = _wrapper_records({"shadow": {"soc-clear-sessions": {"issue_emergency": False}}})
    assert er.outcome_of("soc-clear-sessions", recs)[0] == "executed"


def test_real_wrapper_skip_reads_as_skipped():
    recs = _wrapper_records({"shadow": {"soc-clear-sessions": {"issue_emergency": False}}}, ctx_user=None)
    assert er.outcome_of("soc-clear-sessions", recs)[0] == "skipped"


def test_not_configured_skip_reads_as_skipped():
    """A vendor branch whose required tenant value is missing logs this title."""
    entries = [{"Type": 1, "ContentsFormat": "json",
                "Contents": {"reason": "list_id not configured", "action": "soc-block-domain"},
                "HumanReadable": "### SOC Framework - soc-block-domain: skipped (vendor not configured)\n```json"}]
    assert er.outcome_of("soc-block-domain", er.records_from("soc-block-domain", entries))[0] == "skipped"
