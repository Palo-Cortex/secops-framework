"""
SOCCommandWrapper_test_main.py

Characterisation tests for main(): argument checks, loading the action list,
the time map and tenant config, shadow resolution, the routing ladder, the
all_applicable plan, the skips, and the dispatch summary. Every list read, War
Room entry, context write, result and error is recorded in order and compared
with a golden file captured from the code before it was restructured.
_dispatch_vendor is stubbed: it has its own golden test, and here only the
calls into it matter.

Regenerate the golden file only for an intended behaviour change, never to make
a refactor pass:

    SOCFW_UPDATE_GOLDEN=1 pytest SOCCommandWrapper_test_main.py
"""

import copy
import json
import os
from pathlib import Path

import pytest

from SOCCommandWrapper_test import load_script

GOLDEN = Path(__file__).parent / "test_data" / "main_golden.json"
UPDATE = os.environ.get("SOCFW_UPDATE_GOLDEN") == "1"
LIST = "SOCFrameworkActions_V3"

ISOLATE = {
    "phase": "containment",
    "shadow_mode": True,
    "responses": {
        "CrowdStrike Falcon": {"command": "cs-falcon-contain-host", "inline_args": {"ids": "${x}"}},
        "Cortex Core - IR": {"command": "core-isolate-endpoint", "inline_args": {"endpoint_id": "${y}"}},
    },
}
STAR = {"phase": "triage", "shadow_mode": False, "responses": {"Builtin": {"command": "setParentIncidentFields"}}}
BLOCK = {
    "phase": "containment",
    "shadow_mode_by_actor": {"analyst": False, "ai": True},
    "target_arg": "domain",
    "dispatch": "all_applicable",
    "responses": {
        "FW": {"command": "fw-block-domain", "inline_args": {"domain": "${d}"}},
        "Proxy": {"command": "proxy-block", "target_arg": "url", "inline_args": {"url": "${d}"}},
        "Note": "not a branch",
    },
}
EMPTY_FAN = {"phase": "containment", "dispatch": "all_applicable", "responses": {"Note": "text only"}}
ODD = dict(ISOLATE, dispatch="sideways")
ACTIONS = {
    "soc-isolate-endpoint": ISOLATE,
    "soc-star-case": STAR,
    "soc-block-domain": BLOCK,
    "soc-empty-fan": EMPTY_FAN,
    "soc-odd-dispatch": ODD,
}
CLASS_MAP = {"soc-isolate-endpoint": "endpoint", "soc-odd-dispatch": "endpoint", "soc-block-domain": "network"}
TIME_MAP = {"soc-isolate-endpoint": {"time_minutes": 15, "action_category": "containment"}}
TENANT = {
    "value": {"soc-isolate-endpoint": {"time_minutes": "40"}},
    "shadow": {"soc-isolate-endpoint": {"analyst": False}},
}


def _ctx(responses=None, legacy=None):
    product = {}
    if responses is not None:
        product["responses"] = responses
    if legacy is not None:
        product["response"] = legacy
    return {"SOCFramework": {"RunID": "run-1", "Product": product}}


ROUTED_CTX = _ctx(responses={"endpoint": "CrowdStrike Falcon"})
BASE_ARGS = {"action": "soc-isolate-endpoint", "list_name": LIST, "output_key": "UCTest.Executions",
             "tags": "cer, containment", "Action_Actor": "playbook", "using": "inst-1"}

SCENARIOS = {
    "missing_action": dict(args={"list_name": LIST}),
    "missing_list_name": dict(args={"action": "soc-isolate-endpoint"}),
    "action_list_unreadable": dict(lists={LIST: None}),
    "action_list_not_json": dict(lists={LIST: "{not json"}),
    "action_not_in_list": dict(args=dict(BASE_ARGS, action="soc-nope")),
    "target_on_action_without_target": dict(args=dict(BASE_ARGS, target="host-1")),
    "routed_by_action_class": dict(),
    "routed_class_responses_as_text": dict(ctx=_ctx(responses=json.dumps({"endpoint": "Cortex Core - IR"}))),
    "routed_class_vendor_without_branch_falls_to_legacy": dict(
        ctx=_ctx(responses={"endpoint": "SentinelOne"}, legacy="Cortex Core - IR")),
    "class_map_missing_uses_legacy": dict(ctx=_ctx(legacy="CrowdStrike Falcon"),
                                          lists={"SOCActionClassMap_V3": "Item not found"}),
    "class_map_not_json_uses_legacy": dict(ctx=_ctx(legacy="CrowdStrike Falcon"),
                                           lists={"SOCActionClassMap_V3": "{bad"}),
    "builtin_only_action": dict(args=dict(BASE_ARGS, action="soc-star-case")),
    "no_vendor_skips_with_record": dict(ctx=_ctx(legacy="SentinelOne")),
    "no_vendor_skips_without_output_key": dict(ctx=_ctx(), args=dict(BASE_ARGS, output_key="")),
    "unknown_dispatch_is_routed": dict(args=dict(BASE_ARGS, action="soc-odd-dispatch")),
    "tenant_value_and_shadow_override": dict(lists={"SOCFWTenantConfig": json.dumps(TENANT)},
                                             args=dict(BASE_ARGS, Action_Actor="analyst")),
    "time_map_missing": dict(lists={"SOCActionTimeMap_V3": None}),
    "schema_list_used": dict(lists={"SOCFrameworkSchema_NIST": json.dumps([{"field": "f", "source": "s"}])},
                             args=dict(BASE_ARGS, LifeCycle="NIST")),
    "routed_one_outcome_no_summary": dict(outcomes=[["success"]]),
    "routed_many_outcomes_summary": dict(outcomes=[["success", "simulated", "duplicate"]]),
    "fan_out_no_branches_skips": dict(args=dict(BASE_ARGS, action="soc-empty-fan")),
    "fan_out_mixed_summary": dict(args=dict(BASE_ARGS, action="soc-block-domain", target="a.example,b.example"),
                                  outcomes=[["success", "failed"], ["skipped_not_configured"]]),
    "fan_out_every_dispatch_failed": dict(args=dict(BASE_ARGS, action="soc-block-domain", Action_Actor="ai"),
                                          outcomes=[["failed"], ["failed"]]),
    "tags_as_json_list": dict(args=dict(BASE_ARGS, tags='["a", " ", "b"]')),
}


class _Stop(Exception):
    """return_error ends the script on the platform; the stand-in ends the run here."""


def _encode(value):
    """JSON for anything recorded, keys kept in insertion order."""
    if hasattr(value, "__dict__"):
        return {"__class__": type(value).__name__, **vars(value)}
    return repr(value)


def _lists(spec):
    lists = {
        LIST: json.dumps(ACTIONS),
        "SOCActionClassMap_V3": json.dumps(CLASS_MAP),
        "SOCActionTimeMap_V3": json.dumps(TIME_MAP),
        "SOCFWTenantConfig": None,
    }
    lists.update(spec.get("lists", {}))
    return lists


def _run(name):
    spec = SCENARIOS[name]
    script, demisto = load_script()
    events = []
    lists = _lists(spec)

    def get_list(args):
        name_ = args["listName"]
        events.append(["getList", name_])
        raw = lists.get(name_)
        return [{"Contents": raw}] if raw is not None else []

    demisto._command_responses["getList"] = get_list
    demisto._args = copy.deepcopy(spec.get("args", BASE_ARGS))
    demisto._context = copy.deepcopy(spec.get("ctx", ROUTED_CTX))

    def hook(fn_name, returns=None):
        def record(*args, **kwargs):
            events.append([fn_name, copy.deepcopy(list(args)), kwargs])
            return returns(*args) if callable(returns) else returns
        setattr(script, fn_name, record)

    for fn_name in ("warroom_log", "append_context", "return_results"):
        hook(fn_name)
    hook("utc_now", lambda: "2026-11-21T10:00:00Z")
    hook("get_issue_data", lambda: {"id": "100"})

    def return_error(message):
        events.append(["return_error", [message], {}])
        raise _Stop(message)
    script.return_error = return_error

    outcomes = iter(spec.get("outcomes", [["simulated"]] * 4))

    def dispatch_vendor(shared, vendor, vendor_data, target_arg, single_vendor):
        """Stand-in for _dispatch_vendor: records the call, returns this scenario's outcomes."""
        view = {k: shared[k] for k in sorted(shared) if k not in ("ctx", "action_map")}
        events.append(["_dispatch_vendor", [view, vendor, vendor_data, target_arg, single_vendor], {}])
        return [{"vendor": vendor, "target": "t", "outcome": o, "reason": None if o != "failed" else "boom"}
                for o in next(outcomes)]
    script._dispatch_vendor = dispatch_vendor

    try:
        script.main()
        ended = "returned"
    except _Stop:
        ended = "return_error"
    return json.loads(json.dumps({"events": events, "ended": ended}, default=_encode))


def _golden():
    return json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_main_matches_golden(name):
    """
    Given one call to the universal command (bad input, a routing case, a fan-out, a skip)
    When main runs it
    Then every list read, War Room entry, context write, dispatch, result and error matches the golden file, in order
    """
    got = _run(name)
    if UPDATE:
        golden = _golden()
        golden[name] = got
        GOLDEN.write_text(json.dumps(golden, indent=1, ensure_ascii=False) + "\n")
        return
    assert name in _golden(), f"no golden for {name}; generate it from main with SOCFW_UPDATE_GOLDEN=1"
    assert json.dumps(got, ensure_ascii=False) == json.dumps(_golden()[name], ensure_ascii=False)


def test_every_way_main_ends_is_covered():
    """
    Given the golden file
    When the way each run ended and the vendors it chose are collected
    Then errors, skips, each routing step and the fan-out all appear
    """
    runs = _golden().values()
    assert {r["ended"] for r in runs} == {"returned", "return_error"}
    vendors = {e[1][1] for r in runs for e in r["events"] if e[0] == "_dispatch_vendor"}
    assert {"CrowdStrike Falcon", "Cortex Core - IR", "Builtin", "FW", "Proxy"} <= vendors
