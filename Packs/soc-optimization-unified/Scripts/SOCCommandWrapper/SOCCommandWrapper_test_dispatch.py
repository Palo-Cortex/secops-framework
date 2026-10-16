"""
SOCCommandWrapper_test_dispatch.py

Unit tests for targets[] expansion and the per-action dispatch mode
(routed | all_applicable). Follows the exact harness pattern from
SOCCommandWrapper_test.py — demistomock in builtins, no tenant required.

Run: pytest Scripts/SOCCommandWrapper/SOCCommandWrapper_test_dispatch.py -v
"""

import json

import pytest

from SOCCommandWrapper_test import load_script


BLOCK_DOMAIN_TWO_VENDORS = {
    "soc-block-domain": {
        "shadow_mode": False,
        "dispatch": "all_applicable",
        "target_arg": "domain",
        "responses": {
            "ThreatStop": {
                "command": "threatstop-block",
                "inline_args": {"domain": "${SOCFramework.Artifacts.Network.Domain}"},
            },
            "Zscaler": {
                "command": "zscaler-block",
                "inline_args": {"domain": "${SOCFramework.Artifacts.Network.Domain}"},
            },
        },
    }
}


def _args(action="soc-block-domain"):
    return {
        "action": action,
        "list_name": "SOCFrameworkActions_V3",
        "output_key": "UCTest.Executions",
        "tags": "cer",
    }


def _ctx(domains):
    return {"SOCFramework": {"Artifacts": {"Network": {"Domain": domains}},
                             "RunID": "run-1"}}


def _action_list_response(action_map):
    """Route getList by listName: the action list gets the fixture, every
    other list (SOCActionTimeMap_V3, SOCActionClassMap_V3, schema lists)
    gets 'Item not found' — matching a tenant where only the action list
    is populated."""
    def _route(args):
        if (args or {}).get("listName") == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps(action_map)}]
        return [{"Contents": "Item not found"}]
    return _route


def _commands_named(demisto, name):
    return [c for c in demisto._commands if c[0] == name]


def test_all_applicable_dispatches_every_vendor_per_target():
    script, demisto = load_script()
    demisto._args = _args()
    demisto._context = _ctx(["evil-a.example", "evil-b.example"])
    demisto._command_responses = {
        "getList": _action_list_response(BLOCK_DOMAIN_TWO_VENDORS),
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "threatstop-block": [{"Type": 1, "Contents": "ok"}],
        "zscaler-block": [{"Type": 1, "Contents": "ok"}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }

    script.main()

    # 2 vendors x 2 targets = 4 vendor calls, each with a scalar domain
    ts_calls = _commands_named(demisto, "threatstop-block")
    zs_calls = _commands_named(demisto, "zscaler-block")
    assert len(ts_calls) == 2 and len(zs_calls) == 2
    sent = sorted(a["domain"] for _, a in ts_calls + zs_calls)
    assert sent == ["evil-a.example", "evil-a.example",
                    "evil-b.example", "evil-b.example"]
    for _, call_args in ts_calls + zs_calls:
        assert isinstance(call_args["domain"], str)

    # one execution record per (vendor, target), each carrying its target
    recs = demisto.get(demisto._context, "UCTest.Executions")
    assert len(recs) == 4
    assert sorted(r["target"] for r in recs) == sorted(sent)
    assert all(r["success"] for r in recs)


def test_targets_deduped_and_empties_dropped():
    script, demisto = load_script()
    demisto._args = _args()
    demisto._context = _ctx(["evil.example", "evil.example", "", None, "other.example"])
    demisto._command_responses = {
        "getList": _action_list_response(BLOCK_DOMAIN_TWO_VENDORS),
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "threatstop-block": [{"Type": 1, "Contents": "ok"}],
        "zscaler-block": [{"Type": 1, "Contents": "ok"}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }

    script.main()

    assert len(_commands_named(demisto, "threatstop-block")) == 2
    assert len(_commands_named(demisto, "zscaler-block")) == 2


def test_all_applicable_one_vendor_fails_other_still_dispatches():
    script, demisto = load_script()
    demisto._args = _args()
    demisto._context = _ctx("single.example")  # scalar context value
    demisto._command_responses = {
        "getList": _action_list_response(BLOCK_DOMAIN_TWO_VENDORS),
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "threatstop-block": [{"Type": 4, "Contents": "boom from vendor"}],
        "zscaler-block": [{"Type": 1, "Contents": "ok"}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }

    # One hard failure out of two must NOT raise — fan-out survives.
    script.main()

    assert len(_commands_named(demisto, "zscaler-block")) == 1
    recs = demisto.get(demisto._context, "UCTest.Executions")
    assert len(recs) == 2
    outcomes = sorted((r["vendor"], bool(r.get("success"))) for r in recs)
    assert outcomes == [("ThreatStop", False), ("Zscaler", True)]


def test_all_applicable_every_vendor_failing_raises():
    script, demisto = load_script()
    demisto._args = _args()
    demisto._context = _ctx("single.example")
    demisto._command_responses = {
        "getList": _action_list_response(BLOCK_DOMAIN_TWO_VENDORS),
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "threatstop-block": [{"Type": 4, "Contents": "boom ts"}],
        "zscaler-block": [{"Type": 4, "Contents": "boom zs"}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }

    with pytest.raises(RuntimeError, match="every dispatch failed"):
        script.main()


def test_all_applicable_shadow_simulates_each_pair():
    action_map = json.loads(json.dumps(BLOCK_DOMAIN_TWO_VENDORS))
    action_map["soc-block-domain"]["shadow_mode"] = True
    script, demisto = load_script()
    demisto._args = _args()
    demisto._context = _ctx(["evil-a.example", "evil-b.example"])
    demisto._command_responses = {
        "getList": _action_list_response(action_map),
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }

    script.main()

    # no vendor command ever fires in shadow
    assert not _commands_named(demisto, "threatstop-block")
    assert not _commands_named(demisto, "zscaler-block")
    # but each (vendor, target) pair is simulated and recorded
    recs = demisto.get(demisto._context, "UCTest.Executions")
    assert len(recs) == 4
    assert all(r["shadow_mode"] for r in recs)
    # one dataset row per pair
    posts = _commands_named(demisto, "socfw-post-to-dataset")
    assert len(posts) == 4


def test_routed_with_list_target_fans_out_on_single_vendor():
    action_map = {
        "soc-block-domain": {
            "shadow_mode": False,
            "target_arg": "domain",
            "responses": {
                "ThreatStop": {
                    "command": "threatstop-block",
                    "inline_args": {"domain": "${SOCFramework.Artifacts.Network.Domain}"},
                },
            },
        }
    }
    script, demisto = load_script()
    demisto._args = _args()
    ctx = _ctx(["a.example", "b.example", "c.example"])
    ctx["SOCFramework"]["Product"] = {"response": "ThreatStop"}
    demisto._context = ctx
    demisto._command_responses = {
        "getList": _action_list_response(action_map),
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "threatstop-block": [{"Type": 1, "Contents": "ok"}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }

    script.main()

    calls = _commands_named(demisto, "threatstop-block")
    assert [a["domain"] for _, a in calls] == ["a.example", "b.example", "c.example"]
    recs = demisto.get(demisto._context, "UCTest.Executions")
    assert len(recs) == 3


def test_routed_scalar_without_new_fields_is_unchanged_legacy():
    action_map = {
        "soc-block-domain": {
            "shadow_mode": False,
            "responses": {
                "ThreatStop": {
                    "command": "threatstop-block",
                    "inline_args": {"domain": "${SOCFramework.Artifacts.Network.Domain}"},
                },
            },
        }
    }
    script, demisto = load_script()
    demisto._args = _args()
    ctx = _ctx("one.example")
    ctx["SOCFramework"]["Product"] = {"response": "ThreatStop"}
    demisto._context = ctx
    demisto._command_responses = {
        "getList": _action_list_response(action_map),
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "threatstop-block": [{"Type": 1, "Contents": "ok"}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }

    script.main()

    calls = _commands_named(demisto, "threatstop-block")
    assert len(calls) == 1
    recs = demisto.get(demisto._context, "UCTest.Executions")
    assert len(recs) == 1
    # legacy records carry no target key and no dispatch summary is emitted
    assert "target" not in recs[0]
    assert not any("dispatch summary" in str(r) for r in demisto._results)


def test_unknown_dispatch_value_treated_as_routed():
    action_map = {
        "soc-block-domain": {
            "shadow_mode": False,
            "dispatch": "everything-everywhere",
            "responses": {
                "ThreatStop": {
                    "command": "threatstop-block",
                    "inline_args": {"domain": "${SOCFramework.Artifacts.Network.Domain}"},
                },
            },
        }
    }
    script, demisto = load_script()
    demisto._args = _args()
    ctx = _ctx("one.example")
    ctx["SOCFramework"]["Product"] = {"response": "ThreatStop"}
    demisto._context = ctx
    demisto._command_responses = {
        "getList": _action_list_response(action_map),
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "threatstop-block": [{"Type": 1, "Contents": "ok"}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }

    script.main()

    assert len(_commands_named(demisto, "threatstop-block")) == 1


def test_target_list_resolving_empty_skips_cleanly():
    script, demisto = load_script()
    demisto._args = _args()
    demisto._context = _ctx(["", None])
    demisto._command_responses = {
        "getList": _action_list_response(BLOCK_DOMAIN_TWO_VENDORS),
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }

    script.main()

    assert not _commands_named(demisto, "threatstop-block")
    assert not _commands_named(demisto, "zscaler-block")
    recs = demisto.get(demisto._context, "UCTest.Executions")
    assert recs and all(r.get("skipped") for r in recs)
