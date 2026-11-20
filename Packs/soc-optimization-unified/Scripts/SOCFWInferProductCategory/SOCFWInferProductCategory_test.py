"""
SOCFWInferProductCategory_test.py

Characterization tests: when an issue's DS: key is missing from
SOCProductCategoryMap_V3, its populated field names are scored against the
categories in the lifecycle's normalization contract. Fields most categories
share are suppressed; the rest are IDF-weighted. A clear winner is written to
SOCFramework.Product.category marked "inferred", with the casing the product
map uses; anything below the floor abstains. Every failure degrades to the
old behaviour (no category) and never breaks classification.

The script uses the platform's injected globals without importing them, so the
harness puts them in builtins before import, as the SOCCommandWrapper tests do.

Run: pytest Scripts/SOCFWInferProductCategory/SOCFWInferProductCategory_test.py -v
"""
import builtins
import importlib
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)


def contract(**cats):
    return {"categories": {c: {"mappings": [{"issue_field": f} for f in fields]}
                           for c, fields in cats.items()}}


CONTRACT = contract(
    endpoint=["hostname", "agentid", "processcmd", "filesha256", "username.[0]", "severity"],
    email=["emailsender", "emailsubject", "emailrecipient", "username", "severity"],
    identity=["username", "useragent", "sourceip", "severity"],
    generic=["severity", "name"],
)
CATEGORY_MAP = {"ds_crowdstrike": {"category": "Endpoint"},
                "ds_okta": {"category": "Identity", "product_map": {"x": "Email"}}}


class Tenant:
    def __init__(self):
        self.lists = {"SOCFrameworkNormalizeMap_NIST_IR": json.dumps(CONTRACT),
                      "SOCProductCategoryMap_V3": json.dumps(CATEGORY_MAP)}
        self.incident = {"CustomFields": {
            "tags": ["DOM:Security", "DS:Acme/Edr"],
            "hostname": "h1", "agentid": "a1", "processcmd": "cmd.exe", "filesha256": "",
            "severity": 3, "username": "u",
        }}
        self.context = {}
        self.results = []
        self.errors = []
        self.calls = []

    def execute(self, cmd, args):
        self.calls.append((cmd, args))
        name = args["listName"]
        value = self.lists.get(name)
        if isinstance(value, Exception):
            raise value
        if value is None:
            return [{"Type": 1, "Contents": "Item not found (8)"}]
        return [{"Type": 1, "Contents": value}]


@pytest.fixture
def t(monkeypatch):
    tn = Tenant()
    demisto = types.SimpleNamespace(
        debug=lambda *a: None,
        error=tn.errors.append,
        args=lambda: {},
        incident=lambda: tn.incident,
        executeCommand=tn.execute,
        setContext=lambda k, v: tn.context.__setitem__(k, v),
    )
    for name, value in {"demisto": demisto, "CommandResults": lambda **k: k,
                        "return_results": tn.results.append}.items():
        monkeypatch.setattr(builtins, name, value, raising=False)
    sys.path.insert(0, HERE)
    sys.modules.pop("SOCFWInferProductCategory", None)
    tn.mod = importlib.import_module("SOCFWInferProductCategory")
    tn.demisto = demisto
    return tn


def run(t, **args):
    t.demisto.args = lambda: args
    t.mod.main()
    return t.context["SOCFramework.Product.Inferred"]


# ── small pieces ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("tag,key", [
    ("DS:CrowdStrike/Falcon", "ds_crowdstrike_falcon"),
    ("DS:Okta/Sso", "ds_okta_sso"),
    ("DS:Proofpoint TAP v2", "ds_proofpoint_tap_v2"),
    ("DS:a.b-c!", "ds_a_b_c!"),          # first and last characters are kept as they are
    ("Acme", "ds_acme"),
])
def test_a_ds_tag_becomes_the_map_key(t, tag, key):
    assert t.mod.ds_key(tag) == key


@pytest.mark.parametrize("value,field", [
    ("username.[0]", "username"), ("username[2]", "username"), (" hostname ", "hostname"), ("a.b", "a.b"),
])
def test_an_indexed_contract_field_is_the_same_field(t, value, field):
    assert t.mod.base_issue_field(value) == field


def test_the_contract_list_is_named_by_the_lifecycle_unless_given(t):
    assert t.mod.resolve_list_name("nist_ir", None) == "SOCFrameworkNormalizeMap_NIST_IR"
    assert t.mod.resolve_list_name("nist_ir", "Mine") == "Mine"


def test_the_corpus_is_one_document_per_category_without_generic(t):
    docs = t.mod.corpus_from_contract(CONTRACT, {"endpoint": "Endpoint"})
    assert sorted(c for _, c in docs) == ["Endpoint", "email", "identity"]
    endpoint = [f for f, c in docs if c == "Endpoint"][0]
    assert endpoint == {"hostname", "agentid", "processcmd", "filesha256", "username", "severity"}


def test_casing_comes_from_the_product_map(t):
    assert t.mod.canonical_casing() == {"endpoint": "Endpoint", "identity": "Identity", "email": "Email"}


def test_no_product_map_means_contract_casing(t):
    t.lists["SOCProductCategoryMap_V3"] = None
    assert t.mod.canonical_casing() == {}


def test_fields_most_categories_share_carry_no_signal(t):
    model = t.mod.fit(t.mod.corpus_from_contract(CONTRACT), 0.5)
    assert {"severity", "username", "tags", "sourcebrand"} <= model["generic"]
    assert "hostname" not in model["generic"]


def test_the_signature_is_the_populated_fields_only(t):
    assert t.mod.issue_signature(t.incident) == {"tags", "hostname", "agentid", "processcmd", "severity",
                                                 "username"}
    assert t.mod.issue_signature({"CustomFields": {"a": None, "b": "null", "c": [], "d": 0}}) == {"d"}


@pytest.mark.parametrize("fields,key", [
    ({"tags": ["DOM:Security", "DS:Okta/Sso"]}, "ds_okta_sso"),
    ({"family_tags": "DS:Acme/Edr"}, "ds_acme_edr"),
    ({"tags": ["DOM:Security"]}, ""),
    ({}, ""),
])
def test_the_ds_key_comes_from_the_tags(t, fields, key):
    assert t.mod.issue_ds_key({"CustomFields": fields}) == key


@pytest.mark.parametrize("scores,best,floor,level", [
    ({}, None, 10, "none"),
    ({"a": 0.0, "b": 0.0}, "a", 10, "none"),
    ({"a": 5.0, "b": 0.0}, "a", 10, "weak"),
    ({"a": 20.0, "b": 6.0}, "a", 10, "high"),
    ({"a": 20.0}, "a", 10, "high"),
    ({"a": 15.0, "b": 9.0}, "a", 10, "medium"),
    ({"a": 12.0, "b": 10.0}, "a", 10, "low"),
])
def test_confidence_needs_both_a_score_over_the_floor_and_a_margin(t, scores, best, floor, level):
    assert t.mod.confidence_of(scores, best, floor) == level


# ── main ─────────────────────────────────────────────────────────────────────

def test_a_clear_winner_is_applied_as_inferred_with_the_map_casing(t):
    record = run(t, floor="1")
    assert record["applied"] is True and record["category"] == "Endpoint"
    assert record["level"] in ("high", "medium", "low") and record["product_key"] == "ds_acme_edr"
    assert {e["field"] for e in record["evidence"]} == {"hostname", "agentid", "processcmd"}
    assert t.context["SOCFramework.Product.category"] == "Endpoint"
    assert t.context["SOCFramework.Product.confidence"] == "inferred"
    out = t.results[-1]["readable_output"]
    assert "category: **Endpoint**" in out and "Add `ds_acme_edr` to SOCProductCategoryMap_V3" in out


def test_below_the_floor_abstains_and_leaves_the_category_empty(t):
    record = run(t, floor="1000")
    assert record["applied"] is False and record["level"] == "weak"
    assert "SOCFramework.Product.category" not in t.context
    assert "below floor 1000.0" in t.results[-1]["readable_output"]


def test_an_issue_with_only_shared_fields_abstains(t):
    t.incident = {"CustomFields": {"severity": 3, "username": "u", "tags": ["DS:Acme/Edr"]}}
    record = run(t, floor="1")
    assert record["applied"] is False and record["level"] == "none"


@pytest.mark.parametrize("change,error", [
    ({"SOCFrameworkNormalizeMap_NIST_IR": None}, "not found on tenant"),
    ({"SOCFrameworkNormalizeMap_NIST_IR": "{bad"}, "is not valid JSON"),
    ({"SOCFrameworkNormalizeMap_NIST_IR": json.dumps(contract(generic=["severity"]))},
     "declares no category mappings"),
    ({"SOCFrameworkNormalizeMap_NIST_IR": RuntimeError("getList down")}, "getList down"),
])
def test_any_failure_degrades_to_no_category_and_says_so(t, change, error):
    t.lists.update(change)
    record = run(t)
    assert record["applied"] is False and error in record["error"]
    assert "SOCFramework.Product.category" not in t.context
    assert t.errors and "degraded" in t.results[-1]["readable_output"]


def test_the_record_names_the_contract_and_the_floor(t):
    record = run(t, lifecycle="vuln_mgmt", list_name="SOCFrameworkNormalizeMap_NIST_IR", floor="7")
    assert record["lifecycle"] == "vuln_mgmt" and record["list_name"] == "SOCFrameworkNormalizeMap_NIST_IR"
    assert record["floor"] == 7.0 and record["fields_scored"] == 6
