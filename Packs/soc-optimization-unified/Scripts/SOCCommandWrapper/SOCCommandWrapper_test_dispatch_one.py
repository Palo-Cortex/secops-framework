"""
SOCCommandWrapper_test_dispatch_one.py

Characterisation tests for _dispatch_one: every outcome it can reach, with
everything it writes recorded in order - War Room entries, context writes,
dataset rows, results, warnings and errors - and compared with a golden file
captured from the code before it was restructured. A refactor of _dispatch_one
must reproduce the golden file exactly, key order included, because the War
Room shows records in the order their keys were written.

Regenerate the golden file only for an intended behaviour change, never to make
a refactor pass:

    SOCFW_UPDATE_GOLDEN=1 pytest SOCCommandWrapper_test_dispatch_one.py
"""

import json
import os
from pathlib import Path

import pytest

from SOCCommandWrapper_test import load_script

GOLDEN = Path(__file__).parent / "test_data" / "dispatch_one_golden.json"
UPDATE = os.environ.get("SOCFW_UPDATE_GOLDEN") == "1"

VENDOR_DATA = {
    "command": "vendor-isolate",
    "output_map": {"UC.Isolate.Status": "Vendor.Device.Status"},
    "status": {"path": "Vendor.Device.Status", "values": {"contained": "contained", "normal": "normal"}},
}

SUCCESS = [{"Type": 1, "ContentsFormat": "json", "Contents": {"ok": True},
            "EntryContext": {"Vendor.Device": {"Status": "contained"}}}]
VENDOR_ERROR = [{"Type": 4, "ContentsFormat": "text", "Contents": "vendor said no (500)"}]
ERROR_23 = [{"Type": 4, "ContentsFormat": "text", "Contents": "Command failed (23)"}]


def _encode(value):
    """JSON for anything the wrapper passes out, keys kept in insertion order."""
    if hasattr(value, "__dict__"):
        return {"__class__": type(value).__name__, **vars(value)}
    return repr(value)


class Recorder:
    """Stands in for every way _dispatch_one reaches the platform, and keeps the calls in order."""

    def __init__(self, script, demisto):
        """Record calls made by the loaded script against the mocked platform."""
        self.events = []
        self.script = script
        self.demisto = demisto

    def hook(self, name):
        """Replace the script's function of this name with one that records its calls."""
        def record(*args, **kwargs):
            self.events.append([name, list(args), kwargs])
        setattr(self.script, name, record)

    def install(self, *, enrich_fails=False):
        """Stub every platform call _dispatch_one makes; enrich_fails makes dataset enrichment raise."""
        for name in ("warroom_log", "append_context", "post_dataset_payload",
                     "return_results", "return_warning", "return_error", "apply_output_map"):
            self.hook(name)
        self.script.resolve_schema_payload = lambda entries, ctx: {"schema": "base"}

        def enrich(base, ctx, issue, wrapper_values, args):
            if enrich_fails:
                raise ValueError("schema list unreadable")
            return {"base": base, "wrapper": wrapper_values}
        self.script.enrich_payload = enrich

        def set_context(key, value):
            self.events.append(["setContext", [key, value], {}])
        self.demisto.setContext = set_context

    def dump(self):
        """The recorded calls as plain JSON, in order."""
        return json.loads(json.dumps(self.events, default=_encode))


def _shared(*, shadow_mode, using="", target_key=None, phase="containment", output_key="UCTest.Executions"):
    shared = {
        "action": "soc-isolate-endpoint",
        "args": {"Action_Actor": "playbook"},
        "ctx": {"SOCFramework": {"RunID": "run-1"}},
        "tags": ["cer"],
        "raw_tags": "cer",
        "output_key": output_key,
        "using": using,
        "shadow_mode": shadow_mode,
        "run_id": "run-1",
        "timestamp": "2026-11-21T10:00:00Z",
        "schema_entries": [],
        "issue": {"id": "100"},
        "action_time_minutes": 15,
        "action_time_category": "containment",
        "action_entry": {"phase": phase},
    }
    if target_key:
        shared["target_key"] = target_key
    return shared


# name -> what the call sees: shared values, the vendor's result or an exception, terminal, target
SCENARIOS = {
    "shadow_served_with_target": dict(shared={"shadow_mode": True}, target="host-1"),
    "shadow_no_instance_target_key": dict(shared={"shadow_mode": True, "target_key": "host-key"},
                                          served=False),
    "shadow_terminal_no_instance": dict(shared={"shadow_mode": True}, served=False, terminal=True),
    "success_with_target": dict(shared={"shadow_mode": False}, result=SUCCESS, target="host-1"),
    "success_layout_actor_using": dict(shared={"shadow_mode": False, "using": "Vendor_inst_2"},
                                       result=SUCCESS, actor="layout"),
    "success_target_key": dict(shared={"shadow_mode": False, "target_key": "host-key"}, result=SUCCESS),
    "failed_terminal": dict(shared={"shadow_mode": False}, result=VENDOR_ERROR, terminal=True, target="host-1"),
    "failed_non_terminal_target_key": dict(shared={"shadow_mode": False, "target_key": "host-key"},
                                           result=VENDOR_ERROR),
    "failed_read_only_terminal": dict(shared={"shadow_mode": False, "phase": "enrichment"},
                                      result=VENDOR_ERROR, terminal=True),
    "failed_read_only_non_terminal": dict(shared={"shadow_mode": False, "phase": "enrichment"},
                                          result=VENDOR_ERROR),
    "unavailable_error_23": dict(shared={"shadow_mode": False}, result=ERROR_23, target="host-1"),
    "unavailable_brand_inactive": dict(shared={"shadow_mode": False, "target_key": "host-key"},
                                       brand=False, terminal=True),
    "exception_non_terminal_target": dict(shared={"shadow_mode": False}, raises=True, target="host-1"),
    "exception_target_key_enrich_fails": dict(shared={"shadow_mode": False, "target_key": "host-key"},
                                              raises=True, enrich_fails=True),
    "exception_terminal_reraises": dict(shared={"shadow_mode": False}, raises=True, terminal=True),
    # No output key: nothing is appended to context, everything else is the same.
    "shadow_no_output_key": dict(shared={"shadow_mode": True, "output_key": ""}),
    "success_no_output_key": dict(shared={"shadow_mode": False, "output_key": ""}, result=SUCCESS),
    "failed_no_output_key": dict(shared={"shadow_mode": False, "output_key": ""}, result=VENDOR_ERROR),
    "exception_no_output_key": dict(shared={"shadow_mode": False, "output_key": ""}, raises=True),
}


def _run(name):
    spec = SCENARIOS[name]
    script, demisto = load_script()
    recorder = Recorder(script, demisto)
    recorder.install(enrich_fails=spec.get("enrich_fails", False))
    # The platform loads `formats` into every script; the shared harness doesn't.
    script.formats = {"text": "text", "json": "json", "markdown": "markdown"}
    script.command_served = lambda command: spec.get("served", True)
    script.brand_available = lambda vendor: spec.get("brand", True)
    demisto.context = lambda: {"Vendor": {"Device": {"Status": "contained"}}}

    def execute(command, args):
        recorder.events.append(["executeCommand", [command, args], {}])
        if spec.get("raises"):
            raise RuntimeError("connection reset")
        return spec["result"]
    demisto.executeCommand = execute

    shared = _shared(**spec["shared"])
    if spec.get("actor"):
        shared["args"] = {"Action_Actor": spec["actor"]}
    inline_args = {"device_id": "${SOCFramework.Primary.Endpoint.id}", "empty": "", "kept": "x"}

    outcome, raised = None, None
    try:
        outcome = script._dispatch_one(shared, "Vendor", VENDOR_DATA, "vendor-isolate",
                                       inline_args, spec.get("target"), spec.get("terminal", False))
    except Exception as err:  # the terminal exception path re-raises
        raised = f"{type(err).__name__}: {err}"
    return {"events": recorder.dump(), "outcome": outcome, "raised": raised}


def _golden():
    return json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_dispatch_one_matches_golden(name):
    """
    Given one dispatch situation (shadow, success, vendor error, unavailable integration or exception)
    When _dispatch_one runs it
    Then every War Room entry, context write, dataset row and result matches the golden file, key order included
    """
    got = _run(name)
    if UPDATE:
        golden = _golden()
        golden[name] = got
        GOLDEN.write_text(json.dumps(golden, indent=1, ensure_ascii=False) + "\n")
        return
    assert name in _golden(), f"no golden for {name}; generate it from main with SOCFW_UPDATE_GOLDEN=1"
    want = _golden()[name]
    # Compare as text too, so a change in key order fails: the War Room shows keys in that order.
    assert json.dumps(got, ensure_ascii=False) == json.dumps(want, ensure_ascii=False)


def test_every_outcome_is_covered():
    """
    Given the golden file
    When its recorded outcomes are collected
    Then every outcome _dispatch_one can return appears at least once
    """
    outcomes = {run["outcome"]["outcome"] for run in _golden().values() if run["outcome"]}
    assert {"simulated", "no_instance", "success", "failed", "integration_unavailable"} <= outcomes
