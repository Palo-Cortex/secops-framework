"""
SOCFWClassifyProduct_test.py

The one-task replacement for the Product Classification chain must write what
the chain wrote: the key from the issue's DS tag, the category (product_map
override first, then the entry's category), and type, confidence, response and
responses from the map entry. When the map has no category it runs the
inference script; when the map list is missing it writes nothing; an error
never stops the run.

Run: pytest Scripts/SOCFWClassifyProduct/SOCFWClassifyProduct_test.py -v
"""

import importlib
import json
import os
import sys
import types

HERE = os.path.dirname(__file__)

MAP = {
    "ds_proofpoint_tap": {"category": "Email", "type": "SEG", "confidence": "high",
                          "response": "Proofpoint TAP v2", "responses": {"email": "Proofpoint TAP v2"}},
    "ds_crowdstrike_falcon_event": {"category": "Identity", "type": "EDR", "confidence": "high",
                                    "product_map": {"Falcon": "Endpoint"}},
    "ds_no_category": {"type": "Other"},
}


class Results:
    def __init__(self, readable_output=None, **kw):
        self.readable_output = readable_output


class Tenant:
    def __init__(self, list_contents=None, list_error=False, raise_on=None):
        self.list_contents = json.dumps(MAP) if list_contents is None else list_contents
        self.list_error, self.raise_on = list_error, raise_on
        self.calls, self.context = [], {}

    def execute(self, command, args):
        self.calls.append((command, args))
        if command == self.raise_on:
            raise RuntimeError("boom")
        if command == "getList":
            if self.list_error:
                return [{"Type": 4, "Contents": "Item not found (8) on list [SOCProductCategoryMap_V3]"}]
            return [{"Type": 1, "Contents": self.list_contents}]
        if command == "DeleteContext":
            for k in [k for k in self.context if k.startswith(args["key"])]:
                del self.context[k]
            return [{"Type": 1, "Contents": ""}]
        if command == "SOCFWInferProductCategory":
            self.context["SOCFramework.Product.category"] = "Endpoint"
            self.context["SOCFramework.Product.confidence"] = "inferred"
            return [{"Type": 1, "Contents": ""}]
        raise AssertionError(f"unexpected command {command}")


def run(args, tenant=None):
    tenant = tenant or Tenant()
    out = []
    demisto = types.ModuleType("demistomock")
    demisto.args = lambda: args
    demisto.executeCommand = tenant.execute
    demisto.setContext = lambda k, v: tenant.context.__setitem__(k, v)
    demisto.error = lambda *a: None
    csp = types.ModuleType("CommonServerPython")
    csp.CommandResults = Results
    csp.return_results = out.append
    csp.entryTypes = {"error": 4}
    sys.modules["demistomock"], sys.modules["CommonServerPython"] = demisto, csp
    sys.path.insert(0, HERE)
    module = importlib.import_module("SOCFWClassifyProduct")
    importlib.reload(module)
    module.main()
    return tenant, out[0].readable_output


def product(tenant):
    return {k.split(".", 2)[2]: v for k, v in tenant.context.items()}


def test_a_mapped_source_gets_every_field_from_its_entry():
    tenant, _ = run({"tags": ["DS:Proofpoint TAP", "other"]})
    assert product(tenant) == {"key": "ds_proofpoint_tap", "category": "Email", "type": "SEG",
                               "confidence": "high", "response": "Proofpoint TAP v2",
                               "responses": {"email": "Proofpoint TAP v2"}}
    assert ("SOCFWInferProductCategory", {"lifecycle": "nist_ir"}) not in tenant.calls


def test_the_product_map_overrides_the_entry_category():
    tenant, _ = run({"tags": ["DS:CrowdStrike Falcon Event"], "product": "Falcon"})
    assert product(tenant)["category"] == "Endpoint"


def test_an_unmatched_product_keeps_the_entry_category():
    tenant, _ = run({"tags": ["DS:CrowdStrike Falcon Event"], "product": ["Other"]})
    assert product(tenant)["category"] == "Identity"


def test_tags_arrive_as_a_json_string_or_comma_joined():
    for tags in ('["DS:Proofpoint TAP"]', "DS:Proofpoint TAP,other"):
        tenant, _ = run({"tags": tags})
        assert product(tenant)["key"] == "ds_proofpoint_tap"


def test_an_unmapped_source_runs_inference_with_the_lifecycle():
    tenant, readable = run({"tags": ["DS:Not A Real Source"], "lifecycle": "nist_ir"})
    assert ("SOCFWInferProductCategory", {"lifecycle": "nist_ir"}) in tenant.calls
    assert product(tenant) == {"key": "ds_not_a_real_source", "category": "Endpoint", "confidence": "inferred"}
    assert "inference ran" in readable


def test_an_entry_without_a_category_also_runs_inference():
    tenant, _ = run({"tags": ["DS:No Category"]})
    assert ("SOCFWInferProductCategory", {"lifecycle": "nist_ir"}) in tenant.calls
    assert product(tenant)["type"] == "Other"


def test_no_ds_tag_writes_no_key_and_runs_inference():
    tenant, _ = run({"tags": ["foo"]})
    assert "key" not in product(tenant)
    assert ("SOCFWInferProductCategory", {"lifecycle": "nist_ir"}) in tenant.calls


def test_a_missing_map_writes_nothing_and_says_so():
    tenant, readable = run({"tags": ["DS:Proofpoint TAP"]}, Tenant(list_error=True))
    assert tenant.context == {}
    assert [c for c, _ in tenant.calls] == ["getList"]
    assert "missing" in readable


def test_an_unparseable_map_does_not_stop_the_run():
    tenant, readable = run({"tags": ["DS:Proofpoint TAP"]}, Tenant(list_contents="{not json"))
    assert "failed (continuing)" in readable


def test_a_platform_error_does_not_stop_the_run():
    tenant, readable = run({"tags": ["DS:Proofpoint TAP"]}, Tenant(raise_on="DeleteContext"))
    assert "failed (continuing)" in readable and "boom" in readable


def test_earlier_product_values_are_cleared_first():
    tenant = Tenant()
    tenant.context["SOCFramework.Product.response"] = "stale"
    tenant, _ = run({"tags": ["DS:CrowdStrike Falcon Event"]}, tenant)
    assert "response" not in product(tenant)


def test_the_key_matches_the_old_transform():
    run({"tags": []})
    module = sys.modules["SOCFWClassifyProduct"]
    assert module.product_key(["DS:Abc-Def ghi/x"]) == "ds_abc_def_ghi_x"
    assert module.product_key(["x"]) == ""
