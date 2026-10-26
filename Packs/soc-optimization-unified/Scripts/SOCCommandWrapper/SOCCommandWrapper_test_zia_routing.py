"""
SOCCommandWrapper_test_zia_routing.py

Containment on a Zscaler ZIA issue, against the lists as they ship. The ZIA
source entry in SOCProductCategoryMap_V3 names the vendor that acts for it, and
soc-block-network-indicator must carry an implementation for that vendor, or the
wrapper skips the block with "no implementation for source vendor".

Zscaler blocks by adding to a customer-owned custom URL category, the same one
soc-block-domain uses, so the category id comes from SOCFrameworkTenantConfig_V3.

Indicator actions on a ZIA issue route to Unit 42 Intelligence, which the
framework installs, pinned to the instance it creates.

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
DOMAIN = "zia-test.example"


def _run(shadow, tenant=None, action=ACTION):
    row = copy.deepcopy(ACTIONS[action])
    row["shadow_mode"] = shadow
    row["shadow_mode_by_actor"] = {}
    script, demisto = load_script()
    demisto._args = {"action": action, "list_name": "SOCFrameworkActions_V3",
                     "output_key": "UCTest.Executions", "Action_Actor": "analyst"}
    demisto._context = {"SOCFramework": {
        "Product": {"key": "ds_zscaler_zia", "category": ZIA["category"],
                    "response": ZIA.get("response"), "responses": ZIA.get("responses")},
        "Artifacts": {"Network": {"Destination": {"IP": IP, "Hostname": DOMAIN}}},
        "RunID": "run-1"}}

    def _route(args):
        name = (args or {}).get("listName")
        if name == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps({action: row})}]
        if name == "SOCActionClassMap_V3":
            return [{"Contents": json.dumps(CLASS_MAP)}]
        if name == "SOCFrameworkTenantConfig_V3" and tenant is not None:
            return [{"Contents": json.dumps(tenant)}]
        return [{"Contents": "Item not found"}]

    demisto._command_responses = {
        "getList": _route,
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "zscaler-category-add-ip": [{"Type": 1, "Contents": "ok"}],
        "domain": [{"Type": 1, "Contents": "ok"}],
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


TENANT = {"Zscaler": {"category-id": "CUSTOM_99", "using": "zscaler_test"}}


def test_zia_ip_block_adds_ip_to_the_customer_category():
    demisto = _run(shadow=False, tenant=TENANT)
    calls = _calls(demisto, "zscaler-category-add-ip")
    assert len(calls) == 1
    assert calls[0]["ip"] == IP
    assert calls[0]["category-id"] == "CUSTOM_99"
    assert calls[0].get("using") == "zscaler_test"


def test_zia_ip_block_without_category_skips_and_names_it():
    demisto = _run(shadow=False, tenant=None)
    assert _calls(demisto, "zscaler-category-add-ip") == []
    text = json.dumps([str(r) for r in demisto._results])
    assert "category-id" in text and "SOCFWTenantConfig" in text


def test_zia_ip_block_shadow_names_zscaler_without_calling_it():
    demisto = _run(shadow=True, tenant=TENANT)
    assert _calls(demisto, "zscaler-category-add-ip") == []
    rows = [r for rs in _rows(demisto) for r in (rs if isinstance(rs, list) else [rs])]
    assert any(r.get("vendor") == "Zscaler" and r.get("execution_mode") == "shadow"
               for r in rows)


def test_zia_domain_enrichment_uses_the_framework_unit42_instance():
    assert ZIA["responses"]["indicator"] == "Unit 42 Intelligence"
    demisto = _run(shadow=False, action="soc-enrich-domain")
    calls = _calls(demisto, "domain")
    assert len(calls) == 1
    assert calls[0]["domain"] == DOMAIN
    assert calls[0]["using"] == "Unit_42_Intelligence_SOCFW"
