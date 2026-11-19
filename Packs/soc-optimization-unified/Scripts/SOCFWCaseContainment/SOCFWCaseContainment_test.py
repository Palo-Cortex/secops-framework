"""SOCFWCaseContainment: a case reads contained only when every step really ran.

The planner and the executor are faked; what is tested is how their answers
become a case's containment_state and its case_containment row.
"""
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))

sys.modules.setdefault("demistomock", types.ModuleType("demistomock"))
csp = types.ModuleType("CommonServerPython")
csp.CommandResults = lambda **k: k
csp.return_results = lambda *a, **k: None
csp.return_error = lambda *a, **k: None
csp.entryTypes = {"error": 4}
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWCaseContainment as cc  # noqa: E402

cc.entryTypes = {"error": 4}


def step(status):
    return {"status": status}


@pytest.mark.parametrize("statuses,state", [
    (["executed", "executed"], "contained"),
    (["executed", "duplicate"], "contained"),
    (["shadow", "shadow"], "simulated"),
    (["executed", "shadow"], "partially_contained"),
    (["executed", "failed"], "partially_contained"),
    (["executed", "skipped"], "partially_contained"),
    (["executed", "awaiting_approval"], "partially_contained"),
    (["shadow", "integration_unavailable"], "partially_contained"),
    (["failed"], "uncontained"),
    (["contract_gap", "environment_denied"], "uncontained"),
    ([], "nothing_to_contain"),
])
def test_containment_state(statuses, state):
    assert cc.containment_state([step(s) for s in statuses]) == state


def test_a_failure_with_no_decisions_is_an_error_not_nothing_to_contain():
    assert cc.containment_state([], "executor raised") == "error"


def test_a_failure_never_reads_contained():
    assert cc.containment_state([step("executed")], "planner raised") == "partially_contained"


class Tenant:
    """A planner and an executor whose answers are set per test."""

    def __init__(self, plan=None, plan_error=None, decisions=None, exec_error=None):
        self.plan, self.plan_error = plan, plan_error
        self.decisions, self.exec_error = decisions, exec_error
        self.rows, self.out = [], []

    def execute(self, command, args):
        if command == "SOCFWBuildPhasePlan":
            if args["phase"] != "containment":
                return [{"Type": 1, "Contents": "ok", "EntryContext": {}}]
            if self.plan_error:
                return [{"Type": 4, "Contents": self.plan_error}]
            if not self.plan:
                return [{"Type": 1, "Contents": "ok", "EntryContext": {}}]
            return [{"Type": 1, "EntryContext": {"SOCFramework.Phase.Proposed(val.step)": self.plan}}]
        if command == "SOCFWPhaseExecutor":
            if self.exec_error:
                return [{"Type": 4, "Contents": self.exec_error}]
            return [{"Type": 1, "EntryContext": {"SOCFramework.Phase.Plan(val.step)": self.decisions}}]
        if command == "socfw-post-to-dataset":
            self.rows.append(json.loads(args["JSON"]))
        return [{"Type": 1, "Contents": "ok"}]

    def run(self):
        cc.demisto = types.SimpleNamespace(
            args=lambda: {"cases": json.dumps([{"ID": "42", "Payload": {}}])},
            executeCommand=self.execute, debug=lambda *a: None)
        cc.return_results = self.out.append
        cc.main()
        return self.rows[-1]


def test_an_all_shadow_run_is_simulated_and_counts_nothing_executed():
    row = Tenant(plan=[{"action": "soc-isolate-endpoint"}],
                 decisions=[step("shadow")]).run()
    assert row["containment_state"] == "simulated"
    assert (row["steps_dispatched"], row["steps_executed"], row["steps_simulated"]) == (1, 0, 1)


def test_a_failed_step_is_counted_as_failed():
    row = Tenant(plan=[{"a": 1}, {"a": 2}], decisions=[step("executed"), step("failed")]).run()
    assert row["containment_state"] == "partially_contained"
    assert (row["steps_dispatched"], row["steps_executed"], row["steps_failed"]) == (2, 1, 1)


def test_an_executor_error_reads_error():
    row = Tenant(plan=[{"a": 1}], exec_error="SOCFWPhaseExecutor failed: boom").run()
    assert row["containment_state"] == "error"
    assert "boom" in row["error_message"]


def test_a_planner_error_reads_error():
    row = Tenant(plan_error="SOCFWBuildPhasePlan failed: boom").run()
    assert row["containment_state"] == "error"


def test_an_empty_plan_is_nothing_to_contain():
    row = Tenant(plan=[]).run()
    assert row["containment_state"] == "nothing_to_contain"
    assert row["error_message"] == ""
