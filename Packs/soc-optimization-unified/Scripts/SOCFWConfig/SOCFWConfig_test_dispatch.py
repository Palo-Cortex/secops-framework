"""
SOCFWConfig_test_dispatch.py

Characterisation tests for the command dispatch: every command, run through
main() against a tenant built from fixed lists, with every list read and write,
JOB call, user lookup and dataset row recorded in order, then the result or the
error, then what the tenant config list and the JOBs hold afterwards. The
golden file was captured from the code before it was restructured.

The scenarios reach every branch of status, shadow, set_value, load_users,
_settings_from_args, _edit_from_args, emergency, assignment_value and mode.
The lists are defined here, not read from the pack, so a shipped-list change
does not move the golden file.

Regenerate the golden file only for an intended behaviour change, never to make
a refactor pass:

    SOCFW_UPDATE_GOLDEN=1 pytest SOCFWConfig_test_dispatch.py
"""

import builtins
import copy
import importlib
import json
import os
import sys
import types
from pathlib import Path

import pytest

from SOCFWConfig_test import Results, Tenant

HERE = Path(__file__).parent
GOLDEN = HERE / "test_data" / "dispatch_golden.json"
UPDATE = os.environ.get("SOCFW_UPDATE_GOLDEN") == "1"

CONFIG = "SOCFWTenantConfig"
READ_ERROR = object()   # a list the tenant refuses to read (an error entry that is not "not found")
ANA = "ana@example.com"

ACTIONS = {
    "soc-star-case": {"phase": "triage",
                      "shadow_mode_by_actor": {"analyst": False, "ai": True, "automation": True},
                      "responses": {"Builtin": {"command": "setParentIncidentFields"}}},
    "soc-isolate-endpoint": {"phase": "containment", "shadow_mode": True,
                             "shadow_mode_by_actor": {"analyst": False, "soar": True},
                             "responses": {"CrowdStrike Falcon": {"command": "cs-falcon-contain-host",
                                                                  "inline_args": {"ids": "${x}", "using": ""}}}},
    "soc-block-domain": {"phase": "containment", "shadow_mode": True, "target_arg": "domain",
                         "responses": {
                             "Zscaler": {"command": "zscaler-category-add-url", "target_arg": "url",
                                         "inline_args": {"url": "", "category-id": "", "using": ""},
                                         "required_args": ["category-id"]},
                             "ThreatStopv2": {"command": "threatstop-add", "required_args": ["list_id"],
                                              "inline_args": {"domain": "", "list_id": None}},
                             "Note": "not a branch"}},
    "soc-kill-process": {"phase": "eradication",
                         "responses": {"Cortex Core - IR": {"command": "core-run-script",
                                                            "inline_args": {"script_uid": ""},
                                                            "required_args": ["script_uid"]}}},
    "soc-close-issue": {"phase": "recovery", "shadow_mode": "false",
                        "responses": {"Builtin": {"command": "closeInvestigation"}}},
    "soc-clear-sessions": {"phase": "containment", "shadow_mode_by_actor": {"issue_emergency": True},
                           "responses": {"Okta v2": {"command": "okta-clear-user-sessions",
                                                     "inline_args": {"using": ""}}}},
    "soc-odd": {"phase": "containment", "shadow_mode": "maybe", "responses": {}},
    "soc-enrich-domain": {"phase": "enrichment", "responses": {"Builtin": {"command": "domain"}}},
    "not-an-action": "text",
    "no-responses": {"phase": "containment"},
}

POLICY = {"phases": {"triage": {"emergency": {
    "enabled": True,
    "containable_roles": ["workstation"],
    "protect": ["host:dc01"],
    "policies": [
        {"policy": "endpoint_execution", "about": ["endpoint"], "verdict": ["malicious"], "confidence": "high",
         "exposure": ["executed"], "actions": ["soc-isolate-endpoint"]},
        {"policy": "name_watch", "name_contains": ["ransom"], "confidence": "any",
         "actions": ["soc-isolate-endpoint", "soc-gone"], "enabled": False},
        {"policy": "identity_compromise", "about": ["identity"], "actions": ["soc-clear-sessions"]},
        "not a policy",
        {"about": ["email"]},
    ]}}}}

OPTIMIZATION = {
    "Triage Incidents JOB": {"fields": {"TriageScoreThreshold": 20, "TriageWindowHours": 24}},
    "Analyst Assignment JOB": {"fields": {"AssignmentRoles": "Analyst", "AssignmentCases": "starred",
                                          "AssignmentWindow": "24 hours", "AssignmentMaxPerAnalyst": 5,
                                          "AssignmentOnlineOnly": True}},
    "Case Analysis JOB": {"fields": {"CaseWindowHours": 24, "CaseMaxAnalyses": 1, "CaseCases": "unstarred"}},
}

MODES = {"modes": {
    "pov": {"description": "Starring live, containment recorded.",
            "shadow": {"soc-star-case": {"automation": False}, "soc-isolate-endpoint": {"issue_emergency": True}},
            "jobs": {"Auto Triage V3": "on", "SOCFW Analyst Assignment": "on"}},
    "quiet": {"description": "Nothing live.",
              "shadow": {"soc-star-case": {"automation": True}},
              "jobs": {}},
}}

POV_SHADOW = {"soc-star-case": {"automation": False}, "soc-isolate-endpoint": {"issue_emergency": True}}
JOBS_ON_WITH_ANA = {"Auto Triage V3": {"scheduled": True, "owner": ANA},
                    "SOCFW Analyst Assignment": {"scheduled": True, "owner": ANA}}

USERS_IN_CONTEXT = ["not an entry",
                    {"Type": 1, "EntryContext": {"Users": [{"username": "Bo@Example.com"}, "x"],
                                                 "User": {"email": "cy@example.com", "id": ""}}},
                    {"Type": 1, "Contents": ["x", {"id": "dee@example.com"}]}]
USERS_MARKDOWN = [{"Type": 1, "Contents": "| name |\n|---|\n| Ana |"}]
USERS_ERROR = [{"Type": 4, "Contents": "permission denied"}]

EM_TENANT = {"policies": {"endpoint_execution": {"enabled": False, "exposure": ["any"]},
                          "mine": {"source": ["okta"], "actions": ["soc-clear-sessions"]},
                          "bad": "x"},
             "protect": ["host:web01"]}
EM_SETTINGS = {"protect": ["host:a"], "containable_hosts": ["host:b"], "containable_roles": ["server"],
               "role": ["host:b:server"], "escalate_severity": "high"}


def s(command, cfg=None, **kw):
    """One scenario: command arguments plus the tenant around them."""
    args = {"command": command} if command is not None else {}
    args.update({k: v for k, v in kw.items() if k not in TENANT_KEYS})
    spec = {k: v for k, v in kw.items() if k in TENANT_KEYS}
    if cfg is not None:
        spec["cfg"] = cfg
    spec["args"] = args
    return spec


TENANT_KEYS = {"lists", "users", "set_fails", "dataset_down", "core_api", "jobs", "jobs_ignore_writes"}

SCENARIOS = {
    # main
    "main_default_command_is_status": s(None),
    "main_unknown_command": s("nope"),
    "main_argument_for_another_command": s("shadow", vendor="Zscaler"),
    "main_empty_argument_for_another_command_ignored": s("triage", vendor="", arg="[]"),

    # status
    "status_fresh_tenant": s("status"),
    "status_named_actors_and_values": s("status", cfg={
        "shadow": {"soc-star-case": {"Framework": False, "SOAR": "true"}, "soc-odd": "x",
                   "soc-isolate-endpoint": {"analyst": True}},
        "Zscaler": {"category-id": "CAT-1", "using": ""}, "Okta v2": "not an object"}),
    "status_wanted_actions": s("status", action="soc-enrich-domain, soc-star-case"),
    "status_unknown_action": s("status", action="soc-star-case,soc-nope"),
    "status_matches_pov_mode": s("status", cfg={"shadow": POV_SHADOW}, jobs=JOBS_ON_WITH_ANA, users=USERS_IN_CONTEXT),
    "status_every_section_unreadable": s("status", cfg={"triage": "x", "assignment": 1, "case": []},
                                         core_api=False, lists={"SOCFWConfigModes": None,
                                                                "SOCOptimizationConfig_V3": "{bad",
                                                                "SOCFrameworkPhasePolicy_V3": None}),
    "status_jobs_readable_users_not": s("status", users=USERS_MARKDOWN),
    "status_actions_list_missing": s("status", lists={"SOCFrameworkActions_V3": None}),
    "status_actions_list_not_json": s("status", lists={"SOCFrameworkActions_V3": "{bad"}),
    "status_tenant_config_not_object": s("status", cfg="[1, 2]"),
    "status_tenant_config_read_error": s("status", cfg=READ_ERROR),

    # shadow
    "shadow_missing_action": s("shadow", actor="analyst", value="on"),
    "shadow_unknown_action": s("shadow", action="soc-nope", actor="analyst", value="on"),
    "shadow_bad_value": s("shadow", action="soc-star-case", actor="analyst", value="maybe"),
    "shadow_missing_actor": s("shadow", action="soc-star-case", value="on"),
    "shadow_legacy_actor": s("shadow", action="soc-star-case", actor="ai,framework", value="on"),
    "shadow_unknown_actor": s("shadow", action="soc-star-case", actor="ai,robot", value="on"),
    "shadow_read_only_refused": s("shadow", action="soc-enrich-domain", actor="ai", value="on", apply="yes"),
    "shadow_section_not_object": s("shadow", cfg={"shadow": []}, action="soc-star-case", actor="ai", value="off"),
    "shadow_action_not_object": s("shadow", cfg={"shadow": {"soc-star-case": "x"}},
                                  action="soc-star-case", actor="ai", value="off"),
    "shadow_already_set": s("shadow", cfg={"shadow": {"soc-star-case": {"automation": False}}},
                            action="soc-star-case", actor="automation", value="off", apply="yes"),
    "shadow_dry_run_mixed_actors": s("shadow", cfg={"shadow": {"soc-star-case": {"ai": False}}},
                                     action="soc-star-case", actor="AI, analyst, soar", value="off"),
    "shadow_apply_creates_list": s("shadow", action="soc-kill-process", actor="analyst,issue_emergency",
                                   value="off", apply="YES"),
    "shadow_apply_create_without_core_api": s("shadow", action="soc-kill-process", actor="analyst",
                                              value="off", apply="yes", core_api=False),
    "shadow_apply_default_empties_list": s("shadow", cfg={"shadow": {"soc-close-issue": {"ai": True}}, "x": 1},
                                           action="soc-close-issue", actor="ai", value="default", apply="yes"),
    "shadow_apply_write_does_not_land": s("shadow", cfg={}, action="soc-star-case", actor="ai", value="off",
                                          apply="yes", set_fails=True),
    "shadow_apply_dataset_down": s("shadow", cfg={}, action="soc-odd", actor="analyst", value="on",
                                   apply="yes", dataset_down=True),

    # set
    "set_missing_arg": s("set", vendor="Zscaler", value="x"),
    "set_not_a_slot": s("set", vendor="Zscaler", arg="url", value="x"),
    "set_missing_value": s("set", vendor="zscaler", arg="CATEGORY-ID"),
    "set_vendor_not_object": s("set", cfg={"Zscaler": "x"}, vendor="Zscaler", arg="category-id", value="C"),
    "set_dry_run": s("set", vendor="zscaler", arg="category-id", value=" CAT-9 "),
    "set_apply_creates_list": s("set", vendor="ThreatStopv2", arg="list_id", value="77", apply="yes"),
    "set_apply_existing_list": s("set", cfg={"Zscaler": {"using": "zs-1"}}, vendor="Zscaler", arg="category-id",
                                 value="CAT-2", apply="yes"),
    "set_already_set": s("set", cfg={"Zscaler": {"category-id": "CAT-2"}}, vendor="Zscaler", arg="category-id",
                         value="CAT-2", apply="yes"),
    "set_default_removes_required": s("set", cfg={"Cortex Core - IR": {"script_uid": "u1"}},
                                      vendor="Cortex Core - IR", arg="script_uid", value="default", apply="yes"),
    "set_default_when_not_set": s("set", vendor="Okta v2", arg="using", value="Default"),
    "set_default_keeps_other_values": s("set", cfg={"Zscaler": {"category-id": "C", "using": "z"}},
                                        vendor="Zscaler", arg="using", value="default"),

    # job and owner (load_users through owner and job)
    "owner_missing": s("owner", job="Auto Triage V3"),
    "owner_unknown_job": s("owner", job="Nightly", owner=ANA),
    "owner_job_not_installed": s("owner", job="SOC Case Response", owner=ANA),
    "owner_dry_run": s("owner", job="auto triage v3", owner=ANA),
    "owner_apply": s("owner", job="Auto Triage V3", owner=ANA, apply="yes"),
    "owner_apply_not_landing": s("owner", job="Auto Triage V3", owner=ANA, apply="yes", jobs_ignore_writes=True),
    "owner_same_owner": s("owner", job="Auto Triage V3", owner=ANA, jobs={"Auto Triage V3": {"owner": ANA}}),
    "owner_users_in_entry_context": s("owner", job="Auto Triage V3", owner="CY@example.com", users=USERS_IN_CONTEXT),
    "owner_users_id_only": s("owner", job="Auto Triage V3", owner="dee@example.com", users=USERS_IN_CONTEXT),
    "owner_not_a_user": s("owner", job="Auto Triage V3", owner="eve@example.com"),
    "owner_users_markdown_only": s("owner", job="Auto Triage V3", owner=ANA, users=USERS_MARKDOWN),
    "owner_users_error_entry": s("owner", job="Auto Triage V3", owner=ANA, users=USERS_ERROR),
    "owner_users_raise": s("owner", job="Auto Triage V3", owner=ANA, users="raise"),
    "owner_without_core_api": s("owner", job="Auto Triage V3", owner=ANA, core_api=False),
    "job_takes_no_owner": s("job", job="Auto Triage V3", value="on", owner=ANA),
    "job_bad_value": s("job", job="Auto Triage V3", value="maybe"),
    "job_on_placeholder_owner": s("job", job="Auto Triage V3", value="on"),
    "job_on_users_unreadable": s("job", job="Auto Triage V3", value="on", apply="yes",
                                 jobs={"Auto Triage V3": {"owner": "zed@example.com"}}, users=USERS_ERROR),
    "job_on_apply": s("job", job="SOCFW Analyst Assignment", value="ON", apply="yes",
                      jobs={"SOCFW Analyst Assignment": {"owner": ANA}}),
    "job_off_already_off": s("job", job="SOC Case Analysis", value="off", apply="yes"),
    "job_off_dry_run": s("job", job="Auto Triage V3", value="off", jobs=JOBS_ON_WITH_ANA),

    # emergency listing and section settings (_settings_from_args)
    "emergency_list_shipped": s("emergency"),
    "emergency_list_with_tenant_policies": s("emergency", cfg={
        "emergency": EM_TENANT, "shadow": {"soc-isolate-endpoint": {"issue_emergency": False}}}),
    "emergency_list_no_name_only_policy": s("emergency", cfg={"emergency": {"policies": {
        "name_watch": {"about": ["endpoint"]}}}}),
    "emergency_list_policies_not_object": s("emergency", cfg={"emergency": {"policies": [1]}}),
    "emergency_policy_fields_without_label": s("emergency", verdict="malicious"),
    "emergency_policy_list_missing": s("emergency", lists={"SOCFrameworkPhasePolicy_V3": None}),
    "settings_with_policy": s("emergency", policy="endpoint_execution", protect="host:a"),
    "settings_with_policy_field": s("emergency", escalate_severity="high", tactic="TA0011"),
    "settings_all_valid_apply": s("emergency", protect="host:web01, ip:192.0.2.5, cidr:198.51.100.0/24, "
                                  "account:svc, domain:example.com, List:VIPs",
                                  containable_hosts="host:w*, ip:203.0.113.9, cidr:10.0.5.0/24, list:Hosts",
                                  containable_roles="Workstation, server",
                                  role="host:web*:server, HOST:dc*:domain_controller",
                                  escalate_severity="High", apply="yes"),
    "settings_all_default_apply": s("emergency", cfg={"emergency": dict(EM_SETTINGS)}, protect="default",
                                    containable_hosts="DEFAULT", containable_roles="default", role="default",
                                    escalate_severity="default", apply="yes"),
    "settings_default_keeps_policies": s("emergency", cfg={"emergency": dict(EM_SETTINGS, policies={"mine": {}})},
                                         protect="default"),
    "settings_no_change": s("emergency", escalate_severity="default", apply="yes"),
    "settings_roles_any_alone": s("emergency", containable_roles="any"),
    "settings_emergency_not_object": s("emergency", cfg={"emergency": "x"}, protect="host:a"),
    "settings_protect_bad_kind": s("emergency", protect="host:a, server:b"),
    "settings_protect_empty_entry": s("emergency", protect="host: "),
    "settings_protect_bad_ip": s("emergency", protect="ip:999.1.1.1"),
    "settings_hosts_bad_cidr": s("emergency", containable_hosts="cidr:10.0.0.0/33"),
    "settings_hosts_no_accounts": s("emergency", containable_hosts="account:bob"),
    "settings_hosts_no_domains": s("emergency", containable_hosts="domain:example.com"),
    "settings_roles_bad": s("emergency", containable_roles="server,laptop"),
    "settings_roles_any_with_other": s("emergency", containable_roles="any,server"),
    "settings_role_two_parts": s("emergency", role="host:web"),
    "settings_role_not_host": s("emergency", role="vm:x:server"),
    "settings_role_empty_name": s("emergency", role="host::server"),
    "settings_role_any": s("emergency", role="host:x:any"),
    "settings_severity_bad": s("emergency", escalate_severity="urgent"),

    # emergency policies (_edit_from_args)
    "policy_rule_id_on_shipped": s("emergency", policy="endpoint_execution", rule_id="r-1"),
    "policy_name_contains_on_shipped": s("emergency", policy="name_watch", name_contains="locker"),
    "policy_verdict_bad": s("emergency", policy="endpoint_execution", verdict="malicious,evil"),
    "policy_exposure_bad": s("emergency", policy="endpoint_execution", exposure="opened"),
    "policy_confidence_bad": s("emergency", policy="endpoint_execution", confidence="certain"),
    "policy_action_unknown": s("emergency", policy="endpoint_execution", action="soc-isolate-endpoint,soc-nope"),
    "policy_action_not_containment": s("emergency", policy="endpoint_execution", action="soc-kill-process"),
    "policy_enabled_bad": s("emergency", policy="endpoint_execution", enabled="maybe"),
    "policy_shipped_off_dry_run": s("emergency", policy="endpoint_execution", enabled="off"),
    "policy_shipped_on": s("emergency", policy="name_watch", enabled="On"),
    "policy_shipped_edit_apply": s("emergency", cfg={"x": 1}, policy="endpoint_execution",
                                   verdict="Malicious, suspicious", confidence="MEDIUM", exposure="delivered,ANY",
                                   action="soc-isolate-endpoint, soc-block-domain", about="Endpoint",
                                   entity_type="Host", source="CrowdStrike", tactic="TA0002", apply="yes"),
    "policy_reset_with_fields": s("emergency", policy="endpoint_execution", enabled="default", verdict="malicious"),
    "policy_reset_shipped_apply": s("emergency", cfg={"emergency": EM_TENANT}, policy="endpoint_execution",
                                    enabled="default", apply="yes"),
    "policy_reset_own_apply": s("emergency", cfg={"emergency": {"policies": {"mine": EM_TENANT["policies"]["mine"]}}},
                                policy="mine", enabled="default", apply="yes"),
    "policy_reset_unedited_shipped": s("emergency", policy="identity_compromise", enabled="default"),
    "policy_reset_unknown": s("emergency", policy="nothing", enabled="default"),
    "policy_label_only_unknown": s("emergency", policy="nothing"),
    "policy_new_without_subject": s("emergency", policy="new1", action="soc-isolate-endpoint", verdict="any"),
    "policy_new_without_actions": s("emergency", policy="new1", source="Okta"),
    "policy_new_full_apply": s("emergency", policy="okta_takeover", about="Identity", entity_type="user",
                               source="Okta", rule_id="r-9, r-10", tactic="TA0006", verdict="suspicious",
                               exposure="none", confidence="any", action="soc-clear-sessions", enabled="on",
                               apply="yes"),
    "policy_new_name_only_dry_run": s("emergency", policy="ransom2", name_contains="Ransom, Locker",
                                      action="soc-isolate-endpoint"),
    "policy_edit_unchanged": s("emergency", cfg={"emergency": {"policies": {
        "endpoint_execution": {"verdict": ["malicious"]}}}},
                               policy="endpoint_execution", verdict="malicious", apply="yes"),
    "policy_edit_own_adds_field": s("emergency", cfg={"emergency": {"policies": {
        "mine": EM_TENANT["policies"]["mine"]}}},
                                    policy="mine", tactic="TA0001"),
    "policy_emergency_not_object": s("emergency", cfg={"emergency": "x"}, policy="endpoint_execution", enabled="off"),
    "policy_policies_not_object": s("emergency", cfg={"emergency": {"policies": [1]}}, policy="endpoint_execution",
                                    enabled="off"),
    "policy_apply_dataset_down": s("emergency", cfg={}, policy="identity_compromise", enabled="off", apply="yes",
                                   dataset_down=True),

    # assignment (assignment_value)
    "assignment_list": s("assignment", cfg={"assignment": {"groups": "SOC", "roles": ""}}),
    "assignment_section_not_object": s("assignment", cfg={"assignment": []}, cases="all"),
    "assignment_valid_apply": s("assignment", roles="Tier 1, , Tier 2", groups="none", cases="ALL",
                                domains="Security, domain_posture", window="7 Days", max_per_analyst="unlimited",
                                online_only="no", apply="yes"),
    "assignment_valid_more": s("assignment", cfg={"assignment": {"roles": "Tier 1", "cases": "all"}},
                               roles="default", groups="SOC", domains="all", window="all time",
                               max_per_analyst="12", online_only="YES", cases="starred"),
    "assignment_window_singular": s("assignment", window="1 hour", max_per_analyst="0", online_only="1"),
    "assignment_window_all_month": s("assignment", window="all", online_only="false", domains="health"),
    "assignment_window_months": s("assignment", window="3months", max_per_analyst="no limit", groups="none"),
    "assignment_repeat_no_change": s("assignment", cfg={"assignment": {"cases": "all"}}, cases="all", apply="yes"),
    "assignment_roles_only_commas": s("assignment", roles=", ,"),
    "assignment_cases_bad": s("assignment", cases="open"),
    "assignment_domains_bad": s("assignment", domains="security,email"),
    "assignment_domains_empty": s("assignment", domains=","),
    "assignment_window_zero": s("assignment", window="0 days"),
    "assignment_window_words": s("assignment", window="soon"),
    "assignment_max_negative": s("assignment", max_per_analyst="-1"),
    "assignment_online_bad": s("assignment", online_only="maybe"),

    # triage, case, close: dispatch only
    "triage_list": s("triage"),
    "triage_off_apply": s("triage", score_threshold="off", window_hours="12", apply="yes"),
    "triage_bad": s("triage", window_hours="0"),
    "case_list": s("case"),
    "case_set": s("case", window_hours="48", cases="all"),
    "case_bad": s("case", max_analyses="0"),
    "close_list": s("close"),
    "close_set_apply": s("close", report_mailboxes="Abuse@Example.com, abuse@example.com", comment="report box",
                         apply="yes"),
    "close_bad_address": s("close", report_mailboxes="abuse"),

    # mode
    "mode_list_fresh": s("mode"),
    "mode_list_matches_pov": s("mode", cfg={"shadow": POV_SHADOW}, jobs=JOBS_ON_WITH_ANA),
    "mode_list_custom_jobs_unreadable": s("mode", cfg={"shadow": {"soc-star-case": {"ai": False}}}, core_api=False),
    "mode_list_job_not_installed": s("mode", jobs={"Auto Triage V3": None}),
    "mode_owner_without_mode": s("mode", owner=ANA),
    "mode_unknown": s("mode", mode="loud"),
    "mode_modes_list_missing": s("mode", lists={"SOCFWConfigModes": None}),
    "mode_modes_list_empty": s("mode", lists={"SOCFWConfigModes": {"modes": {}}}),
    "mode_names_missing_action": s("mode", mode="pov", lists={"SOCFWConfigModes": {"modes": {
        "pov": {"shadow": {"soc-gone": {"ai": True}, "soc-star-case": {"ai": True}}}}}}),
    "mode_owner_not_email": s("mode", mode="pov", owner="ana"),
    "mode_owner_not_user": s("mode", mode="pov", owner="eve@example.com"),
    "mode_owner_users_unreadable": s("mode", mode="pov", owner=ANA, users=USERS_ERROR),
    "mode_pov_dry_run_no_owner": s("mode", mode="POV"),
    "mode_pov_apply_with_owner": s("mode", mode="pov", owner=ANA, apply="yes"),
    "mode_pov_apply_real_owner_kept": s("mode", cfg={"x": 1}, mode="pov", apply="yes",
                                        jobs={"Auto Triage V3": {"owner": ANA}}),
    "mode_pov_users_unreadable_no_owner": s("mode", mode="pov", users=USERS_ERROR),
    "mode_pov_jobs_unreadable_apply": s("mode", cfg={}, mode="pov", apply="yes", core_api=False),
    "mode_pov_jobs_unreadable_create": s("mode", mode="pov", apply="yes", core_api=False),
    "mode_pov_job_not_installed": s("mode", mode="pov", owner=ANA, jobs={"SOCFW Analyst Assignment": None}),
    "mode_pov_job_write_not_landing": s("mode", mode="pov", owner=ANA, apply="yes", jobs_ignore_writes=True),
    "mode_quiet_from_pov_apply": s("mode", cfg={"shadow": dict(POV_SHADOW, **{"soc-star-case": {"automation": False,
                                                                                                 "ai": True}}),
                                                "Zscaler": {"using": "z"}},
                                   mode="quiet", apply="yes", jobs=JOBS_ON_WITH_ANA),
    "mode_default_apply": s("mode", cfg={"shadow": POV_SHADOW}, mode="default", apply="yes", jobs=JOBS_ON_WITH_ANA),
    "mode_default_nothing_set": s("mode", mode="default", apply="yes"),
    "mode_shadow_section_not_object": s("mode", cfg={"shadow": "x"}, mode="pov"),
    "mode_shadow_action_not_object": s("mode", cfg={"shadow": {"soc-star-case": "x"}}, mode="pov"),
    "mode_jobs_only_change_apply": s("mode", cfg={"shadow": POV_SHADOW}, mode="pov", owner=ANA, apply="yes",
                                     dataset_down=True),
}


class GoldenTenant(Tenant):
    """The test suite's tenant with this file's lists, plus the failures a scenario asks for."""

    def __init__(self, spec):
        """Build the tenant from this file's lists, then apply the scenario's lists, JOBs and failures."""
        super().__init__(core_api=spec.get("core_api", True))
        lists = {"SOCFrameworkActions_V3": ACTIONS, "SOCFrameworkPhasePolicy_V3": POLICY,
                 "SOCOptimizationConfig_V3": OPTIMIZATION, "SOCFWConfigModes": MODES}
        if "cfg" in spec:
            lists[CONFIG] = spec["cfg"]
        lists.update(spec.get("lists", {}))
        self.lists, self.types = {}, {}
        for name, value in lists.items():
            if value is None:
                continue
            self.lists[name] = value if isinstance(value, str) or value is READ_ERROR else json.dumps(value)
            self.types[name] = "json"
        for name, fields in (spec.get("jobs") or {}).items():
            if fields is None:
                self.jobs.pop(name)
            else:
                self.jobs[name] = dict(self.jobs[name], **fields)
        self.users_response = spec.get("users")
        self.set_fails = spec.get("set_fails", False)
        self.dataset_down = spec.get("dataset_down", False)
        self.jobs_ignore_writes = spec.get("jobs_ignore_writes", False)

    def execute(self, command, args):
        """Answer as the suite's tenant does, except where the scenario asks for a failure."""
        name = args.get("listName")
        if command == "getList" and self.lists.get(name) is READ_ERROR:
            self.commands.append((command, args))
            return [{"Type": 4, "Contents": "Forbidden"}]
        if command == "getUsers" and self.users_response is not None:
            self.commands.append((command, args))
            if self.users_response == "raise":
                raise RuntimeError("getUsers is not available")
            return copy.deepcopy(self.users_response)
        if command == "setList" and self.set_fails:
            self.commands.append((command, args))
            return [{"Type": 4, "Contents": "list is locked"}]
        return super().execute(command, args)


class _ScriptEndedError(Exception):
    """return_error ends the script on the platform; the stand-in ends the run here."""


def _event(command, args):
    """The call as recorded; a dataset row's timestamp is the clock, so it is fixed."""
    args = copy.deepcopy(args)
    if command == "socfw-post-to-dataset":
        row = json.loads(args["JSON"])
        row["timestamp"] = "<now>"
        args["JSON"] = row
    return [command, args]


def _run(name):
    spec = SCENARIOS[name]
    tenant = GoldenTenant(spec)
    out = []
    demisto = types.SimpleNamespace(args=lambda: copy.deepcopy(spec["args"]),
                                    executeCommand=tenant.execute, debug=lambda *a: None)

    def return_error(message):
        raise _ScriptEndedError(message)

    for attr, value in (("demisto", demisto), ("CommandResults", Results),
                        ("return_results", out.append), ("return_error", return_error)):
        setattr(builtins, attr, value)
    sys.path.insert(0, str(HERE))
    module = importlib.reload(importlib.import_module("SOCFWConfig"))
    try:
        module.main()
        ended = {"result": {"readable_output": out[0].readable_output,
                            "outputs_prefix": out[0].outputs_prefix, "outputs": out[0].outputs}}
    except _ScriptEndedError as e:
        ended = {"error": str(e)}
    except Exception as e:  # noqa: BLE001 - an uncaught exception is behaviour too; the platform shows it as a script error
        ended = {"crash": f"{type(e).__name__}: {e}"}
    config_after = tenant.lists.get(CONFIG)
    got = {"events": [_event(c, a) for c, a in tenant.commands], **ended,
           "tenant_config_after": None if config_after is READ_ERROR else config_after,
           "tenant_config_type": tenant.types.get(CONFIG),
           "jobs_after": tenant.jobs}
    return json.loads(json.dumps(got, default=repr))


def _golden():
    return json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_dispatch_matches_golden(name):
    """
    Given one SOCFWConfig command with its arguments and a tenant in a known state
    When main runs it
    Then every tenant call, the result or error, and the config list and JOBs afterwards match the golden file
    """
    got = _run(name)
    if UPDATE:
        golden = _golden()
        golden[name] = got
        GOLDEN.write_text(json.dumps(golden, indent=1, ensure_ascii=False, sort_keys=False) + "\n")
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


def test_every_command_ends_both_ways():
    """
    Given the golden file
    When the way each run ended is collected per command
    Then every command has a run that returned and one that was refused, and only the known crash crashes
    """
    crashed = sorted(n for n, run in _golden().items() if "crash" in run)
    # An unlabelled shipped policy puts None into the label list emergency joins into its error text.
    assert crashed == ["emergency_policy_fields_without_label", "policy_label_only_unknown",
                       "policy_reset_unknown"]
    commands = ("status", "shadow", "set", "job", "owner", "emergency", "triage",
                "assignment", "case", "close", "mode")
    ends = {c: set() for c in commands}
    for spec_name, run in _golden().items():
        command = SCENARIOS[spec_name]["args"].get("command") or "status"
        if command in ends:
            ends[command].add("result" if "result" in run else "error")
    assert ends == {c: {"result", "error"} for c in commands}
