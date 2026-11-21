"""
SOCCommandWrapper_test_dispatch_vendor.py

Characterisation tests for _dispatch_vendor: argument resolution, the three
skips, target fan-out, the once-per-target ledger, and what it hands to
_dispatch_one. Every War Room entry, context write, ledger read and write, and
dispatch is recorded in order and compared with a golden file captured from the
code before it was restructured. _dispatch_one and _record_duplicate are stubbed:
_dispatch_one has its own golden test, and here only the calls into them matter.

Regenerate the golden file only for an intended behaviour change, never to make
a refactor pass:

    SOCFW_UPDATE_GOLDEN=1 pytest SOCCommandWrapper_test_dispatch_vendor.py
"""

import copy
import json
import os
from pathlib import Path

import pytest

from SOCCommandWrapper_test import load_script

GOLDEN = Path(__file__).parent / "test_data" / "dispatch_vendor_golden.json"
UPDATE = os.environ.get("SOCFW_UPDATE_GOLDEN") == "1"
ACTION = "soc-block-ip"

BLOCK = {
    "command": "fw-block-ip",
    "inline_args": {
        "ip": "${SOCFramework.Artifacts.Network.IP}",
        "object_name": "socfw-block-${SOCFramework.Artifacts.Network.IP}",
        "list_id": "",
        "mode": "strict",
    },
    "required_args": ["list_id"],
    "value_map": {"mode": {"strict": "STRICT_MODE"}},
}
IPS = ["192.0.2.10", "192.0.2.10", "", "198.51.100.7"]
CONFIGURED = {"FW": {"list_id": "LIST-1", "ip": "203.0.113.99"}}
UNDO_MAP = {"soc-unblock-ip": {"reversed_by": ACTION}, ACTION: {"phase": "containment"}}


def _ctx(ips=IPS, host="host-1.example"):
    network = {"IP": ips} if ips is not None else {}
    return {"SOCFramework": {"Artifacts": {"Network": network},
                             "Primary": {"Endpoint": {"Hostname": host}}}}


def _encode(value):
    """JSON for anything recorded, keys kept in insertion order."""
    if hasattr(value, "__dict__"):
        return {"__class__": type(value).__name__, **vars(value)}
    return repr(value)


SCENARIOS = {
    "fan_out_live_once_with_undo": dict(),
    "fan_out_shadow_per_vendor": dict(shadow=True, dispatch="all_applicable"),
    "prior_live_is_a_duplicate": dict(ledger=[{"a": ACTION, "t": "192.0.2.10", "m": "live"}]),
    "prior_shadow_runs_live": dict(ledger=[{"a": ACTION, "t": "192.0.2.10", "m": "shadow"}]),
    "prior_shadow_is_a_duplicate_in_shadow": dict(
        shadow=True, ledger=[{"a": ACTION, "t": "192.0.2.10", "m": "shadow"}]),
    "prior_reversed_runs_again": dict(ledger=[{"a": ACTION, "t": "192.0.2.10", "m": "live", "reversed": True}]),
    "failed_dispatch_writes_no_ledger": dict(outcome="failed"),
    "not_configured_single_vendor": dict(tenant_config={}),
    "not_configured_one_of_many": dict(tenant_config={}, single_vendor=False),
    "no_artifact_single_vendor": dict(ctx=_ctx(ips=None)),
    "no_artifact_one_of_many": dict(ctx=_ctx(ips=None), single_vendor=False),
    "no_usable_targets": dict(vendor_data={"command": "fw-block-ip", "inline_args": {
        "ip": ["", None], "host": "${SOCFramework.Primary.Endpoint.Hostname}"}}),
    "static_target_list": dict(vendor_data={"command": "fw-block-ip", "inline_args": {
        "ip": ["192.0.2.1", "192.0.2.2", "192.0.2.1"], "host": "${SOCFramework.Primary.Endpoint.Hostname}"}}),
    "target_override": dict(override=["192.0.2.50", "192.0.2.51"]),
    "no_target_arg_not_once": dict(target_arg=None, phase="enrichment", vendor_data={
        "command": "host-lookup", "inline_args": {"host": "${SOCFramework.Primary.Endpoint.Hostname}"}}),
    "single_target_terminal": dict(ctx=_ctx(ips=["192.0.2.10"])),
    "value_the_map_does_not_name_passes_through": dict(vendor_data=dict(BLOCK, inline_args=dict(
        BLOCK["inline_args"], mode="lenient"))),
    "static_scalar_target": dict(vendor_data={"command": "fw-block-ip", "inline_args": {
        "ip": "192.0.2.9", "host": "${SOCFramework.Primary.Endpoint.Hostname}"}}),
    # No output key: the skips record nothing in context, everything else is the same.
    "no_artifact_no_output_key": dict(ctx=_ctx(ips=None), output_key=""),
    "not_configured_no_output_key": dict(tenant_config={}, output_key=""),
    "no_usable_targets_no_output_key": dict(output_key="", vendor_data={"command": "fw-block-ip", "inline_args": {
        "ip": ["", None], "host": "${SOCFramework.Primary.Endpoint.Hostname}"}}),
}


def _shared(spec, ctx):
    shared = {
        "action": ACTION,
        "args": {"Action_Actor": "playbook"},
        "ctx": ctx,
        "tags": ["cer"],
        "output_key": spec.get("output_key", "UCTest.Executions"),
        "shadow_mode": spec.get("shadow", False),
        "run_id": "run-1",
        "timestamp": "2026-11-21T10:00:00Z",
        "issue": {"id": "100", "parentXDRIncident": "INCIDENT-7"},
        "tenant_config": spec.get("tenant_config", CONFIGURED),
        "action_entry": {"phase": spec.get("phase", "containment"), "dispatch": spec.get("dispatch", "routed")},
        "action_map": UNDO_MAP,
    }
    if spec.get("override"):
        shared["target_override"] = spec["override"]
    return shared


def _run(name):
    spec = SCENARIOS[name]
    script, demisto = load_script()
    events = []

    def hook(fn_name, returns=None):
        def record(*args, **kwargs):
            events.append([fn_name, copy.deepcopy(list(args)), kwargs])
            return returns(*args) if callable(returns) else returns
        setattr(script, fn_name, record)

    for fn_name in ("warroom_log", "append_context", "return_results", "write_ledger"):
        hook(fn_name)
    hook("read_ledger", lambda issue, ctx: copy.deepcopy(spec.get("ledger", [])))
    shadow = spec.get("shadow", False)
    default = "simulated" if shadow else "success"

    def dispatch_one(*call):
        """Stand-in for _dispatch_one (shared, vendor, vendor_data, command, inline_args, target, terminal)."""
        _shared_, vendor, _vendor_data, command, inline_args, target, terminal = call
        events.append(["_dispatch_one", [vendor, command, copy.deepcopy(inline_args), target, terminal], {}])
        return {"vendor": vendor, "target": target, "outcome": spec.get("outcome", default)}
    script._dispatch_one = dispatch_one

    def record_duplicate(*call):
        """Stand-in for _record_duplicate (shared, vendor, command, inline_args, key, prior, terminal)."""
        _shared_, vendor, command, inline_args, key, prior, terminal = call
        events.append(["_record_duplicate", [vendor, command, copy.deepcopy(inline_args), key, prior, terminal], {}])
        return {"vendor": vendor, "target": key, "outcome": "duplicate"}
    script._record_duplicate = record_duplicate

    ctx = spec.get("ctx", _ctx())
    shared = _shared(spec, ctx)
    vendor_data = copy.deepcopy(spec.get("vendor_data", BLOCK))
    results = script._dispatch_vendor(shared, "FW", vendor_data, spec.get("target_arg", "ip"),
                                      spec.get("single_vendor", True))
    after = {"target_key": shared.get("target_key"), "ledger": shared.get("ledger")}
    return json.loads(json.dumps({"events": events, "results": results, "shared_after": after}, default=_encode))


def _golden():
    return json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_dispatch_vendor_matches_golden(name):
    """
    Given one vendor-branch situation (fan-out, skip, override, ledger state)
    When _dispatch_vendor runs it
    Then every War Room entry, context write, ledger read and write and dispatch matches the golden file, in order
    """
    got = _run(name)
    if UPDATE:
        golden = _golden()
        golden[name] = got
        GOLDEN.write_text(json.dumps(golden, indent=1, ensure_ascii=False) + "\n")
        return
    assert name in _golden(), f"no golden for {name}; generate it from main with SOCFW_UPDATE_GOLDEN=1"
    assert json.dumps(got, ensure_ascii=False) == json.dumps(_golden()[name], ensure_ascii=False)


def test_every_outcome_is_covered():
    """
    Given the golden file
    When the outcomes _dispatch_vendor returned are collected
    Then each kind of skip, a duplicate, a dispatch and a failure all appear
    """
    outcomes = {r["outcome"] for run in _golden().values() for r in run["results"]}
    assert {"skipped_no_artifact", "skipped_not_configured", "duplicate", "success", "simulated", "failed"} <= outcomes
