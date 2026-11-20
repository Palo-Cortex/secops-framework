"""
SOCFWPhaseActions_test.py

Which action buttons an analyst is offered on an issue, and what clicking one
sends. An action is offered when SOCCommandWrapper would actually run it: the
vendor is the issue's data source's response integration for the action's class
(SOCFramework.Product.responses, from SOCProductCategoryMap_V3), it is not known
to be down, and the contract supplies its arguments. Every button dispatches
SOCCommandWrapper as actor "analyst".

Run: pytest Scripts/SOCFWPhaseActions/SOCFWPhaseActions_test.py -v
"""
import json
import os
import sys
import types

HERE = os.path.dirname(__file__)

demisto = types.ModuleType("demistomock")
demisto.debug = lambda *a, **k: None
sys.modules["demistomock"] = demisto
csp = types.ModuleType("CommonServerPython")
csp.CommandResults = lambda **k: k
csp.return_results = lambda *a, **k: None
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWPhaseActions as pa  # noqa: E402

CORE = "Cortex Core - IR"
CS = "CrowdStrike Falcon"
ACTIONS = {
    "soc-isolate-endpoint": {"phase": "containment", "sequence_rank": 20, "capability": "Isolate host — network",
                             "responses": {CORE: {"inline_args": {"endpoint_id": "${SOCFramework.Artifacts.EndPointID}"}},
                                           CS: {"inline_args": {"ids": "${SOCFramework.Artifacts.EndPointID}"}}}},
    "soc-block-indicators": {"phase": "containment", "sequence_rank": 10, "capability": "Block hash",
                             "responses": {CORE: {"inline_args": {"hash_list": "${SOCFramework.Artifacts.Hash}"}}}},
    "soc-quarantine-email": {"phase": "containment", "sequence_rank": 5, "capability": "Quarantine email",
                             "responses": {"Abnormal Security": {"inline_args": {"id": "${SOCFramework.Artifacts.Email.MessageID}"}}}},
    "soc-deisolate-endpoint": {"phase": "recovery", "sequence_rank": 1, "capability": "Release host",
                               "responses": {CORE: {"inline_args": {"endpoint_id": "${SOCFramework.Artifacts.EndPointID}"}}}},
}
CLASSES = {"soc-isolate-endpoint": "endpoint", "soc-block-indicators": "indicator",
           "soc-quarantine-email": "email", "soc-deisolate-endpoint": "endpoint"}
# What SOCProductCategoryMap_V3 puts on the issue for two real data sources.
XDR_AGENT = {"response": CORE, "responses": {"endpoint": CORE, "indicator": CORE}}
FALCON = {"response": CS, "responses": {"endpoint": CS, "identity": "Active Directory Query v2", "indicator": CORE}}
ABNORMAL = {"response": "Abnormal Security", "responses": {"email": "Abnormal Security", "indicator": CORE}}


def ctx(category="endpoint", product=XDR_AGENT, **artifacts):
    return {"SOCFramework": {"Product": dict(product, category=category), "Artifacts": artifacts}}


def run(context, phase="containment", modules=None):
    results = []
    lists = {"SOCFrameworkActions_V3": ACTIONS, "SOCActionClassMap_V3": CLASSES}
    demisto.args = lambda: {"phase": phase}
    demisto.context = lambda: context
    demisto.getModules = lambda: modules if modules is not None else {}
    demisto.executeCommand = lambda cmd, a: [{"Contents": json.dumps(lists[a["listName"]])}]
    pa.return_results = results.append
    pa.main()
    return results[0]["readable_output"]


def buttons(text):
    return [json.loads(line[3:-3]) for line in text.split("\n") if line.startswith("%%%")]


def offered(text):
    return [b["params"]["action"] for b in buttons(text)]


# ── what is offered, and what a click sends ───────────────────────────────────

def test_offered_actions_follow_the_registry_order_and_dispatch_the_wrapper_as_analyst():
    got = buttons(run(ctx(EndPointID="a1", Hash="abc")))
    assert [b["params"]["action"] for b in got] == ["soc-block-indicators", "soc-isolate-endpoint"]
    assert all(b["action"] == "SOCCommandWrapper" and b["params"]["Action_Actor"] == "analyst" for b in got)


def test_button_labels_carry_the_entity_and_stay_plain_ascii():
    label = buttons(run(ctx(EndPointID="a1")))[0]["message"]
    assert label == "Isolate host - network - a1"
    assert all(32 <= ord(c) < 127 for c in label)


def test_an_email_issue_is_not_offered_endpoint_actions():
    out = run(ctx("email", ABNORMAL, EndPointID="a1", Hash="abc", Email={"MessageID": "<m1>"}))
    assert offered(out) == ["soc-quarantine-email", "soc-block-indicators"]


def test_the_recovery_button_offers_undo_actions():
    out = run(ctx(EndPointID="a1"), phase="recovery")
    assert out.startswith("### Undo containment") and offered(out) == ["soc-deisolate-endpoint"]


def test_nothing_offered_says_so():
    assert "_Nothing to contain on this issue._" in run(ctx())


# ── which vendor: the data source's response integration, as the wrapper routes ──

def test_a_falcon_issue_routes_endpoint_actions_to_crowdstrike_and_indicators_to_core():
    c = ctx(product=FALCON, EndPointID="a1", Hash="abc")
    assert pa.usable(ACTIONS["soc-isolate-endpoint"], "endpoint", c, None) == (CS, "")
    assert pa.usable(ACTIONS["soc-block-indicators"], "indicator", c, None) == (CORE, "")


def test_an_active_integration_is_offered_even_when_its_brand_differs_from_the_label():
    # The installed CrowdStrike brand is 'CrowdstrikeFalcon'; no module carries the
    # label 'CrowdStrike Falcon', so like the wrapper the button dispatches anyway.
    modules = {"m1": {"brand": "CrowdstrikeFalcon", "state": "active"}}
    out = run(ctx(product=FALCON, EndPointID="a1"), modules=modules)
    assert "soc-isolate-endpoint" in offered(out)


def test_a_vendor_that_does_not_own_the_alert_is_never_offered():
    # soc-quarantine-email has only an Abnormal branch; an endpoint source's issue
    # must not borrow it, as the wrapper skips rather than run another vendor.
    assert pa.usable(ACTIONS["soc-quarantine-email"], "email", ctx(EndPointID="a1", Email={"MessageID": "<m>"}), None) \
        == (None, "no implementation for Cortex Core - IR")


def test_the_legacy_single_response_is_used_when_the_class_has_no_entry():
    c = ctx(product={"response": CORE}, EndPointID="a1")
    assert pa.usable(ACTIONS["soc-isolate-endpoint"], "endpoint", c, None) == (CORE, "")


def test_a_builtin_only_action_needs_no_routing():
    entry = {"responses": {"Builtin": {"inline_args": {"id": "${incident.id}"}}}}
    assert pa.routed_vendors(entry, None, {}) == ["Builtin"]


def test_an_all_applicable_action_is_offered_when_any_branch_can_run():
    entry = {"dispatch": "all_applicable", "responses": {
        "ThreatStopv2": {"inline_args": {"d": "${SOCFramework.Artifacts.Domain}", "list_id": ""}},
        "Zscaler": {"inline_args": {"url": "${SOCFramework.Artifacts.Domain}"}}}}
    assert pa.routed_vendors(entry, "network", ctx()) == ["ThreatStopv2", "Zscaler"]
    assert pa.usable(entry, "network", ctx(Domain="bad.example"), None) == ("ThreatStopv2", "")


# ── why something is not offered ──────────────────────────────────────────────

def test_a_brand_whose_instances_are_all_disabled_is_not_offered_and_says_why():
    modules = {"m1": {"brand": CORE, "state": "disabled"}}
    out = run(ctx(EndPointID="a1", Hash="abc"), modules=modules)
    assert offered(out) == []
    assert "Cortex Core - IR has no active instance" in out


def test_missing_arguments_are_named():
    out = run(ctx(Hash="abc"))
    assert offered(out) == ["soc-block-indicators"]
    assert "Cortex Core - IR needs EndPointID" in out


def test_with_no_registry_every_routed_vendor_counts_as_reachable():
    assert pa.reachable(CS, None) is True
    assert pa.reachable(CS, {CS: ["disabled", "active"]}) is True
    assert pa.reachable(CS, {CS: ["disabled"]}) is False
