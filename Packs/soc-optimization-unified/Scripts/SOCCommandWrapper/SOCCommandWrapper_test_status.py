"""
SOCCommandWrapper_test_status.py

soc-enrich-endpoint reads the endpoint's containment state and role from the
vendor's own output, returns them on the wrapper's record, and refreshes
SOCFramework.Endpoint.containment_status and .role - except for a layout render.
Vendor shapes are the integrations' context outputs (demisto/content, 28 Oct 2026).

Run: pytest Scripts/SOCCommandWrapper/SOCCommandWrapper_test_status.py -v
"""
import copy
import json
import os

import pytest

from SOCCommandWrapper_test import load_script

_LISTS = os.path.join(os.path.dirname(__file__), "..", "..", "Lists")
ACTIONS = json.load(open(os.path.join(_LISTS, "SOCFrameworkActions_V3", "SOCFrameworkActions_V3_data.json")))

SOURCES = {
    "CrowdStrike Falcon": ("ds_crowdstrike_falcon_event", "cs-falcon-search-device",
                           "CrowdStrike.Device(val.ID && val.ID == obj.ID)", "Status", None),
    "Cortex Core - IR": ("ds_panw_xdr_agent", "core-get-endpoints",
                         "Core.Endpoint(val.endpoint_id == obj.endpoint_id)", "is_isolated", "endpoint_type"),
    "SentinelOne V2": ("ds_sentinelone", "sentinelone-list-agents",
                       "SentinelOne.Agents(val.ID == obj.ID)", "NetworkStatus", "MachineType"),
}


def _run(vendor, status_value=None, role_value=None, actor="automation", ec=None):
    key, command, ec_key, status_field, role_field = SOURCES[vendor]
    script, demisto = load_script()
    demisto._args = {"action": "soc-enrich-endpoint", "list_name": "SOCFrameworkActions_V3",
                     "output_key": "UCTest.Executions", "Action_Actor": actor}
    demisto._context = {"SOCFramework": {"RunID": "r", "Artifacts": {"Endpoint": {
        "AgentID": "aid-1", "Hostname": "hobgoblin"}},
        "Product": {"key": key, "category": "Endpoint", "response": vendor}}}
    record = {"ID": "aid-1"}
    if status_value is not None:
        record[status_field] = status_value
    if role_value is not None and role_field:
        record[role_field] = role_value

    def _route(args):
        name = (args or {}).get("listName")
        if name == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps({"soc-enrich-endpoint": copy.deepcopy(ACTIONS["soc-enrich-endpoint"])})}]
        if name == "SOCFWTenantConfig":
            return [{"Contents": "{}"}]
        return [{"Type": 4, "Contents": f" - Item not found (8) on list [{name}] (2609)"}]

    demisto._command_responses = {
        "getList": _route,
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        command: [{"Type": 1, "Contents": [record], "EntryContext": ec if ec is not None else {ec_key: [record]}}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }
    script.main()
    rec = next(r["Contents"] for r in demisto._results if isinstance(r, dict) and isinstance(r.get("Contents"), dict)
               and r["Contents"].get("success") is True)
    ep = (demisto._context.get("SOCFramework") or {}).get("Endpoint") or {}
    return rec, ep


@pytest.mark.parametrize("raw, want", [("normal", "normal"), ("contained", "contained"),
                                       ("containment_pending", "containment_pending"),
                                       ("lift_containment_pending", "contained")])
def test_crowdstrike_status(raw, want):
    rec, ep = _run("CrowdStrike Falcon", raw)
    assert rec["status"] == want and rec["status_raw"] == raw
    assert ep["containment_status"] == want
    assert "role" not in rec          # the device lookup reports no role


@pytest.mark.parametrize("raw, want", [("AGENT_ISOLATED", "contained"), ("AGENT_UNISOLATED", "normal"),
                                       ("AGENT_PENDING_ISOLATION", "containment_pending")])
def test_cortex_core_status_and_role(raw, want):
    rec, ep = _run("Cortex Core - IR", raw, "AGENT_TYPE_SERVER")
    assert rec["status"] == want and ep["containment_status"] == want
    assert rec["role"] == "server" and ep["role"] == "server"


@pytest.mark.parametrize("raw, want", [("connected", "normal"), ("disconnected", "contained"),
                                       ("disconnecting", "containment_pending")])
def test_sentinelone_status_and_role(raw, want):
    rec, ep = _run("SentinelOne V2", raw, "laptop")
    assert rec["status"] == want and rec["role"] == "workstation" and ep["role"] == "workstation"


def test_an_unmapped_value_is_unknown_and_never_written():
    rec, ep = _run("CrowdStrike Falcon", "something_new")
    assert rec["status"] == "unknown" and rec["status_raw"] == "something_new"
    assert "containment_status" not in ep


def test_a_missing_value_is_unknown_and_never_written():
    rec, ep = _run("CrowdStrike Falcon", None)
    assert rec["status"] == "unknown" and "containment_status" not in ep


def test_a_layout_render_reads_but_never_writes():
    rec, ep = _run("CrowdStrike Falcon", "contained", actor="layout")
    assert rec["status"] == "contained"
    assert "containment_status" not in ep


def test_a_branch_without_reads_adds_nothing():
    """Defender reports no isolation state on its lookup."""
    branch = ACTIONS["soc-enrich-endpoint"]["responses"]["Microsoft Defender Advanced Threat Protection"]
    assert "status" not in branch and "role" not in branch
