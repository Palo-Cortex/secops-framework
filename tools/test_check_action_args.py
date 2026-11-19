"""Tests for check_action_args.py.

Run: python3 -m pytest tools/test_check_action_args.py -q
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import check_action_args as caa  # noqa: E402

ISOLATE = {"source": "Vendor", "deprecated": False,
           "args": {"machine_id": {"required": True, "list": True},
                    "comment": {"required": True},
                    "mode": {"allowed": ["Full", "Selective"], "default": "Full"}}}


def specs(defs, unverified=None):
    return {"source": "demisto/content test", "commands": defs, "unverified": unverified or {}}


def resp(command, **args):
    return {"command": command, "inline_args": args}


def test_a_response_that_fits_passes():
    assert caa.problems_against(ISOLATE, {"machine_id": "${X}", "comment": "c"}) == []


def test_an_argument_the_command_does_not_take_fails():
    assert "'machine_ids' is not an argument of this command" in \
        caa.problems_against(ISOLATE, {"machine_ids": "${X}", "comment": "c", "machine_id": "${X}"})


def test_a_missing_required_argument_fails():
    assert caa.problems_against(ISOLATE, {"machine_id": "${X}"}) == ["required argument 'comment' is not sent"]


def test_a_required_argument_with_a_default_may_be_left_out():
    spec = {"args": {"fromPart": {"required": True, "default": "envelope_from"}}}
    assert caa.problems_against(spec, {}) == []


def test_platform_arguments_are_always_allowed():
    assert caa.problems_against(ISOLATE, {"machine_id": "x", "comment": "c", "using": "inst"}) == []


def test_a_literal_outside_the_allowed_values_fails():
    probs = caa.problems_against(ISOLATE, {"machine_id": "x", "comment": "c", "mode": "Partial"})
    assert probs == ["'mode' is 'Partial'; the command takes one of ['Full', 'Selective']"]


def test_a_context_reference_is_not_held_to_the_allowed_values():
    assert caa.problems_against(ISOLATE, {"machine_id": "x", "comment": "c", "mode": "${SOCFramework.Mode}"}) == []


def test_a_command_nothing_defines_fails():
    status, details = caa.check_response("Vendor", resp("vendor-missing"), specs({}))
    assert status == "fail" and "not defined" in details[0]


def test_an_unverified_command_is_reported_with_its_reason():
    status, details = caa.check_response("Vendor", resp("vendor-missing"),
                                         specs({}, {"vendor-missing": "not in content"}))
    assert (status, details) == ("unverified", ["not in content"])


def test_the_definition_named_by_the_brand_is_the_one_checked():
    other = {"source": "Other", "deprecated": False, "args": {"id": {"required": True}}}
    status, _ = caa.check_response("Vendor", resp("isolate", id="x"), specs({"isolate": [ISOLATE, other]}))
    assert status == "fail"


def test_with_no_brand_match_any_current_definition_will_do():
    other = {"source": "Other", "deprecated": False, "args": {"id": {"required": True}}}
    status, _ = caa.check_response("Label", resp("isolate", id="x"), specs({"isolate": [ISOLATE, other]}))
    assert status == "ok"


def test_fitting_only_a_deprecated_integration_is_a_warning():
    old = {"source": "Old", "deprecated": True, "args": {"id": {}}}
    status, details = caa.check_response("Old", resp("lookup", id="x"), specs({"lookup": [old]}))
    assert status == "deprecated" and "deprecated" in details[0]


def test_platform_brands_are_not_checked():
    actions = {"soc-close": {"responses": {"Builtin": resp("closeInvestigation", nonsense="x")}}}
    assert caa.check(actions, specs({}))["fail"] == []


def test_the_shipped_actions_pass_against_the_committed_specs():
    actions = json.loads(caa.ACTIONS.read_text())
    report = caa.check(actions, json.loads(caa.SPECS.read_text()))
    assert report["fail"] == [], report["fail"]


def test_a_target_arg_that_points_at_no_argument_fails():
    r = dict(resp("isolate", machine_id="x", comment="c"), target_arg="address")
    status, details = caa.check_response("Vendor", r, specs({"isolate": [ISOLATE]}))
    assert status == "fail" and "target_arg 'address'" in details[0]


def test_a_required_arg_the_response_does_not_send_fails():
    r = dict(resp("isolate", machine_id="x", comment="c"), required_args=["list_id"])
    status, details = caa.check_response("Vendor", r, specs({"isolate": [ISOLATE]}))
    assert status == "fail" and "'list_id'" in details[0]
