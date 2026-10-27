"""
SOCCommandWrapper_test_block_domain.py

soc-block-domain against the registry row as it ships in
Lists/SOCFrameworkActions_V3, not a hand-copied fixture, so a change to the
row is tested here. Covers per-vendor target args (ThreatStop ioc_domain,
Zscaler url), customer values from SOCFWTenantConfig, the
not-configured skip, shadow, and the
action_target column on the dataset row.

Run: pytest Scripts/SOCCommandWrapper/SOCCommandWrapper_test_block_domain.py -v
"""

import copy
import json
import os

from SOCCommandWrapper_test import load_script

_LIST = os.path.join(os.path.dirname(__file__), "..", "..", "Lists",
                     "SOCFrameworkActions_V3", "SOCFrameworkActions_V3_data.json")
SHIPPED = json.load(open(_LIST))["soc-block-domain"]


def _row(shadow=False):
    """The shipped row, unedited except for shadow - customer values never go here."""
    row = copy.deepcopy(SHIPPED)
    row["shadow_mode"] = shadow
    row["shadow_mode_by_actor"] = {}
    return {"soc-block-domain": row}


def _tenant(configured=("ThreatStopv2", "Zscaler")):
    cfg = {}
    if "ThreatStopv2" in configured:
        cfg["ThreatStopv2"] = {"list_id": "test-list-guid"}
    if "Zscaler" in configured:
        cfg["Zscaler"] = {"category-id": "CUSTOM_99"}
    return cfg


def _run(action_map, domains, tenant=None, actor="analyst"):
    script, demisto = load_script()
    demisto._args = {"action": "soc-block-domain", "list_name": "SOCFrameworkActions_V3",
                     "output_key": "UCTest.Executions", "Action_Actor": actor}
    demisto._context = {"SOCFramework": {
        "Artifacts": {"Network": {"DNS": {"Query": domains}}}, "RunID": "run-1"}}

    def _route(args):
        name = (args or {}).get("listName")
        if name == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps(action_map)}]
        if name == "SOCFWTenantConfig" and tenant is not None:
            return [{"Contents": json.dumps(tenant)}]
        return [{"Contents": "Item not found"}]

    demisto._command_responses = {
        "getList": _route,
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "threatstopv2-update-domain-list": [{"Type": 1, "Contents": "ok"}],
        "zscaler-category-add-url": [{"Type": 1, "Contents": "ok"}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }
    script.main()
    return demisto


def _calls(demisto, name):
    return [a for c, a in demisto._commands if c == name]


def _rows(demisto):
    return [json.loads(a["JSON"]) for a in _calls(demisto, "socfw-post-to-dataset")]


def test_shipped_row_is_containment_shadowed_fan_out():
    assert SHIPPED["phase"] == "containment"
    assert SHIPPED["shadow_mode"] is True               # one setting for every actor
    assert "shadow_mode_by_actor" not in SHIPPED
    assert SHIPPED["dispatch"] == "all_applicable"
    assert set(SHIPPED["responses"]) == {"ThreatStopv2", "Zscaler"}


def test_configured_blocks_every_domain_in_both_vendors_with_their_own_arg():
    d = _run(_row(), ["evil-a.example", "evil-b.example"], _tenant())
    ts = _calls(d, "threatstopv2-update-domain-list")
    zs = _calls(d, "zscaler-category-add-url")
    assert sorted(a["ioc_domain"] for a in ts) == ["evil-a.example", "evil-b.example"]
    assert sorted(a["url"] for a in zs) == ["evil-a.example", "evil-b.example"]
    assert all(a["list_id"] == "test-list-guid" and a["action"] == "add" for a in ts)
    assert all(a["category-id"] == "CUSTOM_99" for a in zs)
    # empty optional instance is dropped, never sent as using=""
    assert all("using" not in a for a in zs)


def test_customer_values_come_from_tenant_config_not_the_registry_row():
    # the shipped row carries no customer values at all
    assert SHIPPED["responses"]["ThreatStopv2"]["inline_args"]["list_id"] == ""
    assert SHIPPED["responses"]["Zscaler"]["inline_args"]["category-id"] == ""
    d = _run(_row(), ["evil-a.example"],
             {"Zscaler": {"category-id": "CUSTOM_99", "using": "Zscaler_PROD"}})
    zs = _calls(d, "zscaler-category-add-url")
    assert zs and zs[0]["category-id"] == "CUSTOM_99" and zs[0]["using"] == "Zscaler_PROD"


def test_tenant_config_never_overrides_evidence_from_the_issue():
    d = _run(_row(), ["evil-a.example"], {"Zscaler": {"category-id": "CUSTOM_99",
                                                       "url": "attacker-chosen.example"}})
    assert [a["url"] for a in _calls(d, "zscaler-category-add-url")] == ["evil-a.example"]


def test_dataset_rows_name_the_target():
    d = _run(_row(), ["evil-a.example", "evil-b.example"], _tenant())
    rows = [r for r in _rows(d) if r.get("universal_command") == "soc-block-domain"]
    assert len(rows) == 4
    assert sorted((r["vendor"], r["action_target"]) for r in rows) == [
        ("ThreatStopv2", "evil-a.example"), ("ThreatStopv2", "evil-b.example"),
        ("Zscaler", "evil-a.example"), ("Zscaler", "evil-b.example")]


def test_no_tenant_config_list_skips_with_the_value_to_set():
    d = _run(_row(), ["evil-a.example"], None)
    assert not _calls(d, "threatstopv2-update-domain-list")
    assert not _calls(d, "zscaler-category-add-url")
    recs = d.get(d._context, "UCTest.Executions")
    reasons = {r["vendor"]: r["skip_reason"] for r in recs}
    assert len(recs) == 2 and all(r["skipped"] for r in recs)
    assert "list_id" in reasons["ThreatStopv2"] and "SOCFWTenantConfig" in reasons["ThreatStopv2"]
    assert "category-id" in reasons["Zscaler"]


def test_one_vendor_configured_other_still_blocks():
    d = _run(_row(), ["evil-a.example", "evil-b.example"], _tenant(("ThreatStopv2",)))
    assert len(_calls(d, "threatstopv2-update-domain-list")) == 2
    assert not _calls(d, "zscaler-category-add-url")


def test_shipped_shadow_simulates_every_pair_and_calls_nothing():
    d = _run(_row(shadow=True), ["evil-a.example", "evil-b.example"], _tenant())
    assert not _calls(d, "threatstopv2-update-domain-list")
    assert not _calls(d, "zscaler-category-add-url")
    rows = [r for r in _rows(d) if r.get("universal_command") == "soc-block-domain"]
    assert len(rows) == 4 and all(r["action_status"] == "simulated" for r in rows)


def test_no_domain_on_issue_skips_without_calling():
    d = _run(_row(), None, _tenant())
    assert not _calls(d, "threatstopv2-update-domain-list")
    assert not _calls(d, "zscaler-category-add-url")
