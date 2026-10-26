"""
SOCCommandWrapper_test_zia_routing.py

Containment on a Zscaler ZIA issue, against the lists as they ship. The ZIA
source entry in SOCProductCategoryMap_V3 names the vendor that acts for it, and
soc-block-network-indicator must carry an implementation for that vendor, or the
wrapper skips the block with "no implementation for source vendor".

Run: pytest Scripts/SOCCommandWrapper/SOCCommandWrapper_test_zia_routing.py -v
"""

import copy
import json
import os

from SOCCommandWrapper_test import load_script

_LISTS = os.path.join(os.path.dirname(__file__), "..", "..", "Lists")
ACTIONS = json.load(open(os.path.join(
    _LISTS, "SOCFrameworkActions_V3", "SOCFrameworkActions_V3_data.json")))
PRODUCT_MAP = json.load(open(os.path.join(
    _LISTS, "SOCProductCategoryMap_V3", "SOCProductCategoryMap_V3_data.json")))
CLASS_MAP = json.load(open(os.path.join(
    _LISTS, "SOCActionClassMap_V3", "SOCActionClassMap_V3_data.json")))

ZIA = PRODUCT_MAP["ds_zscaler_zia"]
ACTION = "soc-block-network-indicator"
IP = "203.0.113.7"


def _run(shadow):
    row = copy.deepcopy(ACTIONS[ACTION])
    row["shadow_mode"] = shadow
    row["shadow_mode_by_actor"] = {}
    script, demisto = load_script()
    demisto._args = {"action": ACTION, "list_name": "SOCFrameworkActions_V3",
                     "output_key": "UCTest.Executions", "Action_Actor": "analyst"}
    demisto._context = {"SOCFramework": {
        "Product": {"key": "ds_zscaler_zia", "category": ZIA["category"],
                    "response": ZIA.get("response"), "responses": ZIA.get("responses")},
        "Artifacts": {"Network": {"Destination": {"IP": IP}}},
        "RunID": "run-1"}}

    def _route(args):
        name = (args or {}).get("listName")
        if name == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps({ACTION: row})}]
        if name == "SOCActionClassMap_V3":
            return [{"Contents": json.dumps(CLASS_MAP)}]
        return [{"Contents": "Item not found"}]

    demisto._command_responses = {
        "getList": _route,
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "zscaler-blacklist-ip": [{"Type": 1, "Contents": "ok"}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }
    script.main()
    return demisto


def _calls(demisto, name):
    return [a for c, a in demisto._commands if c == name]


def _rows(demisto):
    return [json.loads(a["JSON"]) for a in _calls(demisto, "socfw-post-to-dataset")]


def test_zia_source_routes_to_zscaler():
    assert ZIA.get("response") == "Zscaler"
    assert "Zscaler" in ACTIONS[ACTION]["responses"]


def test_zia_ip_block_dispatches_zscaler_blacklist_ip():
    demisto = _run(shadow=False)
    calls = _calls(demisto, "zscaler-blacklist-ip")
    assert len(calls) == 1
    assert calls[0]["ip"] == IP


def test_zia_ip_block_shadow_names_zscaler_without_calling_it():
    demisto = _run(shadow=True)
    assert _calls(demisto, "zscaler-blacklist-ip") == []
    rows = [r for rs in _rows(demisto) for r in (rs if isinstance(rs, list) else [rs])]
    assert any(r.get("vendor") == "Zscaler" and r.get("execution_mode") == "shadow"
               for r in rows)
