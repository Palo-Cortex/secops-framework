"""
SOCFWEmergencyResponse_test_main.py

Characterisation tests for main(): which policies match, which hosts, accounts
and destinations may be contained, every wrapper dispatch and what it returned,
the escalation, the close, the dataset rows, the context writes and the War Room
output, in order, compared with a golden file captured from the code before it
was restructured. The scenarios reach every branch of gate, evaluate and main.

The lists are defined here, not read from the pack, so a shipped-list change
does not move the golden file. The tenant is the one SOCFWEmergencyResponse_test
uses, whose wrapper returns the entries the real one does.

Regenerate the golden file only for an intended behaviour change, never to make
a refactor pass:

    SOCFW_UPDATE_GOLDEN=1 pytest SOCFWEmergencyResponse_test_main.py
"""

import copy
import json
import os
from pathlib import Path

import pytest

from SOCFWEmergencyResponse_test import DC, WORKSTATION, Results, Tenant, _set, er

GOLDEN = Path(__file__).parent / "test_data" / "main_golden.json"
UPDATE = os.environ.get("SOCFW_UPDATE_GOLDEN") == "1"
DOMAIN_PATH = "SOCFramework.Artifacts.Network.DNS.Query"
IP_PATH = "SOCFramework.Artifacts.Network.Destination.IP"
ERROR_ENTRY = 4


def _action(phase, scope, **extra):
    return dict({"phase": phase, "entity_scope": scope,
                 "responses": {"Vendor": {"command": "vendor-command", "inline_args": {"id": "${x}"}}}}, **extra)


ACTIONS = {
    "soc-isolate-endpoint": _action("containment", "host"),
    "soc-clear-sessions": _action("containment", "identity"),
    "soc-retract-email": _action("containment", "artifact"),
    "soc-block-domain": {"phase": "containment", "entity_scope": "artifact", "target_arg": "domain",
                         "responses": {"Zscaler": {"command": "zscaler-block", "target_arg": "url",
                                                   "inline_args": {"url": "${" + DOMAIN_PATH + "}"}}}},
    "soc-block-network-indicator": {"phase": "containment", "entity_scope": "artifact",
                                    "responses": {"FW": {"command": "fw-block", "target_arg": "ip",
                                                         "inline_args": {"ip": "${" + IP_PATH + "}"}}}},
    "soc-kill-process": _action("eradication", "host"),
    "soc-close-issue-contained": _action("triage", "issue"),
    "soc-star-case": _action("triage", "case"),
    "soc-raise-case-severity": _action("triage", "case"),
    "not-an-action": "text",
}

SECTION = {
    "enabled": True, "close_when_contained": True,
    "containable_roles": ["workstation"], "protect": ["host:dc*", "account:svc_*", "domain:partner.example"],
    "escalate_severity": "high",
    "policies": [
        {"policy": "identity", "about": ["identity"], "actions": ["soc-clear-sessions"]},
        {"policy": "endpoint", "about": ["endpoint"], "exposure": ["executed"],
         "actions": ["soc-isolate-endpoint", "soc-kill-process", "soc-missing"]},
        {"policy": "c2", "about": ["endpoint"], "tactic": ["TA0011"], "verdict": ["malicious", "suspicious"],
         "confidence": "medium", "actions": ["soc-block-domain", "soc-block-network-indicator"]},
        {"policy": "mail", "about": ["email"], "verdict": ["any"], "confidence": "any", "exposure": ["any"],
         "actions": ["soc-retract-email", "soc-block-domain"]},
        {"policy": "by_rule", "rule_id": ["r-1"], "entity_type": ["user"], "source": ["ds_okta_systemlog"],
         "actions": ["soc-clear-sessions"]},
        {"policy": "by_name", "name_contains": ["Ransom"], "actions": ["soc-isolate-endpoint"]},
        {"policy": "off", "about": ["identity"], "enabled": False, "actions": ["soc-clear-sessions"]},
        {"policy": "off_text", "about": ["identity"], "enabled": "false", "actions": ["soc-clear-sessions"]},
        {"policy": "no_subject", "actions": ["soc-clear-sessions"]},
        {"policy": "no_actions", "about": ["identity"]},
        {"policy": "empty"},
        {"policy": "bad_confidence", "about": ["identity"], "confidence": "certain",
         "actions": ["soc-clear-sessions"]},
        "not a policy",
    ],
}
POLICY = {"phases": {"triage": {"emergency": SECTION}}}

MALICIOUS = {"verdict": "malicious", "confidence": "high", "exposure": "executed", "primary_entity_type": "host"}
USER_MALICIOUS = dict(MALICIOUS, primary_entity_type="user", exposure="attempted")
EMAIL = {"verdict": "benign", "confidence": "low", "exposure": "delivered", "primary_entity_type": "email"}


def s(**spec):
    """One scenario: the Tenant's arguments plus source_key, ctx, custom fields, lists and no_case."""
    return spec


def section_with(**changes):
    """The fixture policy list with its emergency section changed."""
    return {"phases": {"triage": {"emergency": dict(copy.deepcopy(SECTION), **changes)}}}


SCENARIOS = {
    # stops before any action
    "disabled": s(policy=section_with(enabled=False), assessment=USER_MALICIOUS),
    "enabled_not_true": s(policy=section_with(enabled="yes"), assessment=USER_MALICIOUS),
    "policy_list_missing": s(lists={"SOCFrameworkPhasePolicy_V3": None}, assessment=USER_MALICIOUS),
    "no_assessment": s(),
    "assessment_as_text": s(assessment=json.dumps(USER_MALICIOUS), source_key="Assessment.Text"),
    "assessment_not_json": s(assessment="not json", source_key="Assessment.Text"),
    "already_contained": s(assessment=dict(USER_MALICIOUS, already_contained="True")),
    "no_match": s(assessment=dict(USER_MALICIOUS, verdict="benign")),
    "no_match_low_confidence": s(assessment=dict(USER_MALICIOUS, confidence="low")),
    "no_match_no_verdict": s(assessment={"primary_entity_type": "user"}),

    # identity
    "identity_shadow": s(assessment=USER_MALICIOUS),
    "identity_executed_and_closed": s(assessment=USER_MALICIOUS, outcome="executed"),
    "identity_protected_account": s(assessment=USER_MALICIOUS, user="svc_backup@lab.local"),
    "identity_failed_escalates": s(assessment=USER_MALICIOUS, outcome="failed"),
    "identity_wrapper_error": s(assessment=USER_MALICIOUS, outcome="error"),
    "identity_skipped": s(assessment=USER_MALICIOUS, outcome="skipped"),
    "identity_no_record": s(assessment=USER_MALICIOUS, outcome="nothing"),
    "identity_duplicate_live": s(assessment=USER_MALICIOUS, outcome="duplicate_live"),
    "identity_duplicate_shadow": s(assessment=USER_MALICIOUS, outcome="duplicate_shadow"),
    "by_rule_and_identity": s(assessment=USER_MALICIOUS, ruleid="r-1", outcome="executed"),
    "by_rule_from_custom_fields": s(assessment=USER_MALICIOUS, custom={"ruleid": "r-1"}),
    "rule_id_other": s(assessment=USER_MALICIOUS, ruleid="r-2"),
    "source_other": s(assessment=USER_MALICIOUS, ruleid="r-1", key="ds_azure_signin"),
    "entity_other": s(assessment=dict(USER_MALICIOUS, primary_entity_type="host"), ruleid="r-1"),

    # endpoint
    "endpoint_workstation_executed": s(assessment=MALICIOUS, category="Endpoint", key="ds_crowdstrike",
                                       host=WORKSTATION, outcome="executed"),
    "endpoint_workstation_shadow": s(assessment=MALICIOUS, category="Endpoint", key="ds_crowdstrike",
                                     host=WORKSTATION),
    "endpoint_dc_protected": s(assessment=MALICIOUS, category="Endpoint", host=DC, outcome="executed"),
    "endpoint_server_role_refused": s(assessment=MALICIOUS, category="Endpoint",
                                      host={"hostname": "app01", "os": "Windows Server 2022", "ip": "10.1.1.9"}),
    "endpoint_unknown_role": s(assessment=MALICIOUS, category="Endpoint",
                               host={"hostname": "tux01", "os": "Ubuntu 24.04", "ip": "10.1.1.10"}),
    "endpoint_edr_role_wins": s(assessment=MALICIOUS, category="Endpoint", host=WORKSTATION, role="server"),
    "endpoint_tenant_role_entry": s(assessment=MALICIOUS, category="Endpoint", host=DC, outcome="executed",
                                    tenant={"emergency": {"protect": [], "role": ["host:bannik:workstation"]}}),
    "endpoint_roles_any": s(assessment=MALICIOUS, category="Endpoint", outcome="executed",
                            host={"hostname": "tux01", "os": "Ubuntu 24.04", "ip": "10.1.1.10"},
                            tenant={"emergency": {"containable_roles": ["any"]}}),
    "endpoint_containable_hosts_hit": s(assessment=MALICIOUS, category="Endpoint", host=WORKSTATION,
                                        outcome="executed",
                                        tenant={"emergency": {"containable_hosts": ["cidr:10.20.20.0/24"]}}),
    "endpoint_containable_hosts_miss": s(assessment=MALICIOUS, category="Endpoint", host=WORKSTATION,
                                         tenant={"emergency": {"containable_hosts": ["host:other*"]}}),
    "endpoint_containable_hosts_list_missing": s(assessment=MALICIOUS, category="Endpoint", host=WORKSTATION,
                                                 tenant={"emergency": {"containable_hosts": ["list:Gone"]}}),
    "endpoint_protect_ip": s(assessment=MALICIOUS, category="Endpoint", host=WORKSTATION,
                             tenant={"emergency": {"protect": ["ip:10.20.20.5"]}}),
    "endpoint_protect_list": s(assessment=MALICIOUS, category="Endpoint", host=WORKSTATION,
                               tenant={"emergency": {"protect": ["list:VIPs"]}},
                               lists={"VIPs": "# never contain\nhobgoblin\n192.0.2.7\n"}),
    "endpoint_protect_list_unreadable": s(assessment=MALICIOUS, category="Endpoint", host=WORKSTATION,
                                          tenant={"emergency": {"protect": ["list:VIPs"]}},
                                          lists={"VIPs": RuntimeError("denied")}),
    "endpoint_already_contained_by_edr": s(assessment=MALICIOUS, category="Endpoint", host=WORKSTATION,
                                           status="containment_pending"),
    "endpoint_not_executed_exposure": s(assessment=dict(MALICIOUS, exposure="attempted"), category="Endpoint",
                                        host=WORKSTATION),
    "endpoint_by_name": s(assessment=dict(MALICIOUS, exposure="attempted"), category="Endpoint", host=WORKSTATION,
                          name="ransom note dropped", outcome="executed"),

    # c2 blocks
    "c2_malicious_destinations": s(assessment=dict(MALICIOUS, verdict="suspicious", confidence="medium"),
                                   category="Endpoint", host=WORKSTATION, custom={"mitretacticid": ["TA0011"]},
                                   ctx={"SOCFramework.Endpoint.dns_queries": ["bad.example.com", "c2.example.net",
                                                                              "printer", "files.partner.example"],
                                        IP_PATH: ["203.0.113.7", "10.20.20.99"],
                                        "DBotScore": [{"Indicator": "bad.example.com", "Score": 3},
                                                      {"Indicator": "C2.example.net", "Score": 2},
                                                      {"Indicator": "203.0.113.7", "Score": "3"},
                                                      {"Indicator": "", "Score": 3},
                                                      {"Indicator": "x", "Score": "n/a"}, "junk"]},
                                   outcome="executed"),
    "c2_nothing_to_block": s(assessment=dict(MALICIOUS, exposure="attempted"), category="Endpoint", host=WORKSTATION,
                             custom={"mitretacticname": ["TA0011"]}),
    "c2_tactic_other": s(assessment=dict(MALICIOUS, exposure="attempted"), category="Endpoint", host=WORKSTATION,
                         custom={"mitretacticid": ["TA0001"]}),
    "c2_protect_unreadable": s(assessment=dict(MALICIOUS, exposure="attempted"), category="Endpoint",
                               host=WORKSTATION, custom={"mitretacticid": ["TA0011"]},
                               ctx={DOMAIN_PATH: ["bad.example.com"],
                                    "DBotScore": {"Indicator": "bad.example.com", "Score": 3}},
                               tenant={"emergency": {"protect": ["list:Gone"]}}),

    # email
    "email_retract_and_block": s(assessment=EMAIL, category="Email", key="ds_proofpoint", outcome="executed",
                                 ctx={DOMAIN_PATH: "bad.example.com",
                                      "DBotScore": {"Indicator": "bad.example.com", "Score": 3}}),
    "email_no_close_action": s(assessment=EMAIL, category="Email", outcome="executed",
                               lists={"SOCFrameworkActions_V3": {k: v for k, v in ACTIONS.items()
                                                                 if k != "soc-close-issue-contained"}}),
    "email_close_off": s(assessment=EMAIL, category="Email", outcome="executed",
                         policy=section_with(close_when_contained=False)),

    # tenant config
    "tenant_config_unreadable": s(assessment=USER_MALICIOUS, tenant=RuntimeError("denied")),
    "tenant_config_not_json": s(assessment=USER_MALICIOUS, tenant="{not json"),
    "tenant_config_not_object": s(assessment=USER_MALICIOUS, tenant="[1]"),
    "tenant_config_empty": s(assessment=USER_MALICIOUS, tenant="  ", outcome="executed"),
    "tenant_policy_edit_and_own": s(assessment=USER_MALICIOUS, outcome="executed",
                                    tenant={"emergency": {"policies": {
                                        "identity": {"enabled": False},
                                        "lab_own": {"source": ["ds_okta_systemlog"],
                                                    "actions": ["soc-clear-sessions", "soc-kill-process"]},
                                        "broken": "x"}}}),
    "tenant_policies_not_object": s(assessment=USER_MALICIOUS, tenant={"emergency": {"policies": [1]}}),

    # escalation
    "escalate_case_already_higher": s(assessment=USER_MALICIOUS, outcome="failed", case_severity="critical"),
    "escalate_case_unreadable": s(assessment=USER_MALICIOUS, outcome="failed", case_severity=None),
    "escalate_no_case": s(assessment=USER_MALICIOUS, outcome="failed", no_case=True),
    "escalate_bad_severity": s(assessment=USER_MALICIOUS, outcome="failed",
                               tenant={"emergency": {"escalate_severity": "informational"}}),
    "escalate_default_severity": s(assessment=USER_MALICIOUS, outcome="failed",
                                   policy=section_with(escalate_severity=None)),
    "wrapper_raises": s(assessment=USER_MALICIOUS, outcome="raise"),
    "wrapper_success_unconfirmed": s(assessment=USER_MALICIOUS, outcome="unconfirmed"),
}

TENANT_ARGS = ("assessment", "category", "key", "name", "ruleid", "tenant", "policy", "outcome", "host",
               "role", "status", "case_severity", "user", "lists")


def _wrapper_reply(action, mode):
    """Entries for the wrapper outcomes the shared Tenant has no mode for."""
    if mode in ("duplicate_live", "duplicate_shadow"):
        prior = {"m": "shadow" if mode == "duplicate_shadow" else "production", "by": "case response"}
        return [{"Type": 1, "ContentsFormat": "json",
                 "Contents": {"action": action, "success": True, "duplicate": True, "duplicate_of": prior},
                 "HumanReadable": "### SOC Framework - Duplicate"}]
    if mode == "nothing":
        return []
    if mode == "unconfirmed":
        return [{"Type": 1, "ContentsFormat": "json",
                 "Contents": {"action": action, "success": False, "shadow_mode": False},
                 "HumanReadable": "### SOC Framework - Command Result"}]
    raise RuntimeError("the wrapper is down")


def _normalise(command, args):
    args = copy.deepcopy(args)
    if command == "socfw-post-to-dataset":
        row = json.loads(args["JSON"])
        row["decided_at"] = "<now>"
        args["JSON"] = row
    return [command, args]


def _tenant_for(name):
    """(tenant, source_key): the shared Tenant set up as the scenario says."""
    spec = dict(SCENARIOS[name])
    policy = spec.pop("policy", POLICY)
    lists = dict({"SOCFrameworkActions_V3": ACTIONS}, **spec.pop("lists", {}))
    source_key = spec.pop("source_key", None)
    ctx_extra = spec.pop("ctx", {})
    custom = spec.pop("custom", None)
    no_case = spec.pop("no_case", False)
    assessment = spec.get("assessment")
    if source_key:
        spec.pop("assessment")
    tenant = Tenant(policy=policy, lists={k: v for k, v in lists.items() if v is not None},
                    **{k: v for k, v in spec.items() if k in TENANT_ARGS})
    if lists.get("SOCFrameworkPhasePolicy_V3", "") is None:
        tenant.lists.pop("SOCFrameworkPhasePolicy_V3")
    if source_key:
        _set(tenant.ctx, source_key, assessment)
    for path, value in ctx_extra.items():
        _set(tenant.ctx, path, value)
    if custom:
        tenant.incident["CustomFields"] = custom
    if no_case:
        tenant.incident.pop("parentXDRIncident")
    return tenant, source_key


def _run(name):
    """Run main on the scenario's issue and return what it did, in order."""
    tenant, source_key = _tenant_for(name)
    events = []
    own_modes = ("duplicate_live", "duplicate_shadow", "nothing", "unconfirmed", "raise")

    def execute(command, args):
        events.append(_normalise(command, args))
        if command == "SOCCommandWrapper" and tenant.default_outcome in own_modes \
                and args["action"] in ("soc-clear-sessions", "soc-isolate-endpoint"):
            return _wrapper_reply(args["action"], tenant.default_outcome)
        if command == "SOCCommandWrapper" and tenant.default_outcome in own_modes:
            return _shadow_reply(tenant, args)
        return tenant.execute(command, args)

    d = er.demisto
    d.args = lambda: {"source_key": source_key} if source_key else {}
    d.context = lambda: copy.deepcopy(tenant.ctx)
    d.incident = lambda: tenant.incident
    d.executeCommand = execute

    def set_context(key, value):
        events.append(["setContext", key, copy.deepcopy(value)])
        _set(tenant.ctx, key, value)
    d.setContext = set_context
    er.isError = lambda res: any(isinstance(e, dict) and e.get("Type") == ERROR_ENTRY for e in (res or []))
    er.CommandResults = Results
    out = []
    er.return_results = out.append
    er.main()
    got = {"events": events, "war_room": [r.readable_output for r in out]}
    return json.loads(json.dumps(got, default=repr))


def _shadow_reply(tenant, args):
    """Every other action, in a scenario that sets its own mode, runs as a shadow."""
    mode = tenant.default_outcome
    tenant.default_outcome = "shadow"
    try:
        return tenant.execute("SOCCommandWrapper", args)
    finally:
        tenant.default_outcome = mode


def _golden():
    return json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_main_matches_golden(name):
    """
    Given one issue, its assessment and a tenant in a known state
    When emergency response runs on it
    Then every dispatch, list and case read, dataset row, context write and War Room entry matches the golden file
    """
    got = _run(name)
    if UPDATE:
        golden = _golden()
        golden[name] = got
        GOLDEN.write_text(json.dumps(golden, indent=1, ensure_ascii=False) + "\n")
        return
    assert name in _golden(), f"no golden for {name}; generate it from main with SOCFW_UPDATE_GOLDEN=1"
    assert json.dumps(got, ensure_ascii=False) == json.dumps(_golden()[name], ensure_ascii=False)


def test_golden_has_no_stale_scenarios():
    """
    Given the golden file
    When its scenario names are compared with this file's
    Then each golden entry still has a scenario that produces it
    """
    assert set(_golden()) <= set(SCENARIOS)
