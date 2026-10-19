"""
SOCCommandWrapper_test_block_domain.py

soc-block-domain against the registry row as it ships in
Lists/SOCFrameworkActions_V3, not a hand-copied fixture, so a change to the
row is tested here. Covers per-vendor target args (ThreatStop ioc_domain,
Zscaler url), the not-configured skip for tenant IDs, shadow, and the
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


def _row(configured=("ThreatStopv2", "Zscaler"), shadow=False):
    row = copy.deepcopy(SHIPPED)
    row["shadow_mode"] = shadow
    row["shadow_mode_by_actor"] = {}
    if "ThreatStopv2" in configured:
        row["responses"]["ThreatStopv2"]["inline_args"]["list_id"] = "test-list-guid"
    if "Zscaler" in configured:
        row["responses"]["Zscaler"]["inline_args"]["category-id"] = "CUSTOM_99"
    return {"soc-block-domain": row}


def _run(action_map, domains, actor="analyst"):
    script, demisto = load_script()
    demisto._args = {"action": "soc-block-domain", "list_name": "SOCFrameworkActions_V3",
                     "output_key": "UCTest.Executions", "Action_Actor": actor}
    demisto._context = {"SOCFramework": {
        "Artifacts": {"Network": {"DNS": {"Query": domains}}}, "RunID": "run-1"}}

    def _route(args):
        if (args or {}).get("listName") == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps(action_map)}]
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
    assert SHIPPED["shadow_mode"] is True
    assert all(v is True for v in SHIPPED["shadow_mode_by_actor"].values())
    assert SHIPPED["dispatch"] == "all_applicable"
    assert set(SHIPPED["responses"]) == {"ThreatStopv2", "Zscaler"}


def test_configured_blocks_every_domain_in_both_vendors_with_their_own_arg():
    d = _run(_row(), ["evil-a.example", "evil-b.example"])
    ts = _calls(d, "threatstopv2-update-domain-list")
    zs = _calls(d, "zscaler-category-add-url")
    assert sorted(a["ioc_domain"] for a in ts) == ["evil-a.example", "evil-b.example"]
    assert sorted(a["url"] for a in zs) == ["evil-a.example", "evil-b.example"]
    assert all(a["list_id"] == "test-list-guid" and a["action"] == "add" for a in ts)
    assert all(a["category-id"] == "CUSTOM_99" for a in zs)
    # empty optional instance is dropped, never sent as using=""
    assert all("using" not in a for a in zs)


def test_dataset_rows_name_the_target():
    d = _run(_row(), ["evil-a.example", "evil-b.example"])
    rows = [r for r in _rows(d) if r.get("universal_command") == "soc-block-domain"]
    assert len(rows) == 4
    assert sorted((r["vendor"], r["action_target"]) for r in rows) == [
        ("ThreatStopv2", "evil-a.example"), ("ThreatStopv2", "evil-b.example"),
        ("Zscaler", "evil-a.example"), ("Zscaler", "evil-b.example")]


def test_unconfigured_vendors_skip_with_the_value_to_set():
    d = _run(_row(configured=()), ["evil-a.example"])
    assert not _calls(d, "threatstopv2-update-domain-list")
    assert not _calls(d, "zscaler-category-add-url")
    recs = d.get(d._context, "UCTest.Executions")
    reasons = {r["vendor"]: r["skip_reason"] for r in recs}
    assert len(recs) == 2 and all(r["skipped"] for r in recs)
    assert "list_id" in reasons["ThreatStopv2"]
    assert "category-id" in reasons["Zscaler"]


def test_one_vendor_configured_other_still_blocks():
    d = _run(_row(configured=("ThreatStopv2",)), ["evil-a.example", "evil-b.example"])
    assert len(_calls(d, "threatstopv2-update-domain-list")) == 2
    assert not _calls(d, "zscaler-category-add-url")


def test_shipped_shadow_simulates_every_pair_and_calls_nothing():
    d = _run(_row(shadow=True), ["evil-a.example", "evil-b.example"])
    assert not _calls(d, "threatstopv2-update-domain-list")
    assert not _calls(d, "zscaler-category-add-url")
    rows = [r for r in _rows(d) if r.get("universal_command") == "soc-block-domain"]
    assert len(rows) == 4 and all(r["action_status"] == "simulated" for r in rows)


def test_no_domain_on_issue_skips_without_calling():
    d = _run(_row(), None)
    assert not _calls(d, "threatstopv2-update-domain-list")
    assert not _calls(d, "zscaler-category-add-url")
