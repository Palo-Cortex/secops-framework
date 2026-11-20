"""
SOCFWPhaseActions_test.py

Characterization tests: which action buttons an analyst is offered on an issue,
and what clicking one sends. Every button dispatches SOCCommandWrapper as actor
"analyst", so shadow mode and the execution row apply as they do for a playbook.

Run: pytest Scripts/SOCFWPhaseActions/SOCFWPhaseActions_test.py -v
"""
import json
import os
import sys
import types

import pytest

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

ACTIONS = {
    "soc-isolate-endpoint": {"phase": "containment", "sequence_rank": 20, "capability": "Isolate host — network",
                             "responses": {"Cortex Core - IR": {"inline_args": {"endpoint_id": "${SOCFramework.Artifacts.EndPointID}"}}}},
    "soc-block-indicators": {"phase": "containment", "sequence_rank": 10, "capability": "Block hash",
                             "responses": {"Cortex Core - IR": {"inline_args": {"hash_list": "${SOCFramework.Artifacts.Hash}"}}}},
    "soc-quarantine-email": {"phase": "containment", "sequence_rank": 5, "capability": "Quarantine email",
                             "responses": {"Abnormal Security": {"inline_args": {"id": "${SOCFramework.Artifacts.Email.MessageID}"}}}},
    "soc-deisolate-endpoint": {"phase": "recovery", "sequence_rank": 1, "capability": "Release host",
                               "responses": {"Cortex Core - IR": {"inline_args": {"endpoint_id": "${SOCFramework.Artifacts.EndPointID}"}}}},
}
CLASSES = {"soc-isolate-endpoint": "endpoint", "soc-block-indicators": "indicator",
           "soc-quarantine-email": "email", "soc-deisolate-endpoint": "endpoint"}


def ctx(category="endpoint", **artifacts):
    return {"SOCFramework": {"Product": {"category": category}, "Artifacts": artifacts}}


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


def test_offered_actions_follow_the_registry_order_and_dispatch_the_wrapper_as_analyst():
    out = run(ctx(EndPointID="a1", Hash="abc"))
    got = buttons(out)
    assert [b["params"]["action"] for b in got] == ["soc-block-indicators", "soc-isolate-endpoint"]
    assert all(b["action"] == "SOCCommandWrapper" and b["params"]["Action_Actor"] == "analyst" for b in got)


def test_button_labels_carry_the_entity_and_stay_plain_ascii():
    label = buttons(run(ctx(EndPointID="a1")))[0]["message"]
    assert label == "Isolate host - network - a1"
    assert all(32 <= ord(c) < 127 for c in label)


def test_an_email_issue_is_not_offered_endpoint_actions():
    out = run(ctx("email", EndPointID="a1", Hash="abc", Email={"MessageID": "<m1>"}))
    assert [b["params"]["action"] for b in buttons(out)] == ["soc-quarantine-email", "soc-block-indicators"]


def test_an_action_whose_arguments_the_contract_lacks_is_listed_as_not_available():
    out = run(ctx(Hash="abc"))
    assert [b["params"]["action"] for b in buttons(out)] == ["soc-block-indicators"]
    assert "**Not available**" in out and "Isolate host" in out


def test_with_no_registry_every_vendor_counts_as_reachable():
    assert pa.usable(ACTIONS["soc-isolate-endpoint"], ctx(EndPointID="a1"), None) == ("Cortex Core - IR", "")


def test_an_inactive_brand_is_not_offered():
    modules = {"m1": {"brand": "Cortex Core - IR", "state": "disabled"}}
    assert buttons(run(ctx(EndPointID="a1", Hash="abc"), modules=modules)) == []


def test_the_recovery_button_offers_undo_actions():
    out = run(ctx(EndPointID="a1"), phase="recovery")
    assert out.startswith("### Undo containment")
    assert [b["params"]["action"] for b in buttons(out)] == ["soc-deisolate-endpoint"]


def test_nothing_offered_says_so():
    assert "_Nothing to contain on this issue._" in run(ctx())


@pytest.mark.xfail(strict=True, reason=(
    "Known defect: a response is offered only when its vendor label equals an active "
    "module's brand. Labels in SOCFrameworkActions_V3 often differ from the installed "
    "brand (the list says 'CrowdStrike Falcon', the integration id is "
    "'CrowdstrikeFalcon'), so the button never offers it. SOCCommandWrapper tolerates "
    "the difference; this script does not."))
def test_an_active_integration_is_offered_even_when_its_brand_differs_from_the_label():
    entry = {"phase": "containment", "responses": {"CrowdStrike Falcon": {
        "inline_args": {"ids": "${SOCFramework.Artifacts.EndPointID}"}}}}
    brands = {"CrowdstrikeFalcon"}
    assert pa.usable(entry, ctx(EndPointID="a1"), brands)[0] is not None
