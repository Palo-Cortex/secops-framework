"""SOCFWAssessmentDecisions runs the five post-assessment scripts the AI entry
playbook used to run as separate tasks: same order, same arguments, every entry
posted again, and a failure in one step does not stop the next.

Run: pytest Scripts/SOCFWAssessmentDecisions/SOCFWAssessmentDecisions_test.py -v
"""
import sys
import types

sys.modules.setdefault("demistomock", types.ModuleType("demistomock"))
if "CommonServerPython" not in sys.modules or not hasattr(sys.modules["CommonServerPython"], "formats"):
    csp = types.ModuleType("CommonServerPython")
    csp.entryTypes = {"note": 1, "error": 4}
    csp.formats = {"text": "text", "markdown": "markdown"}
    csp.return_results = lambda *a, **k: None
    sys.modules["CommonServerPython"] = csp

import SOCFWAssessmentDecisions as m  # noqa: E402

ORDER = ["SOCFWPromoteAssessment", "SOCFWRenderAssessment", "SOCFWEmergencyResponse",
         "SOCFWElevateCase", "SOCFWCloseDecision"]


def note(text, ctx=None):
    e = {"Type": 1, "ContentsFormat": "markdown", "Contents": text, "HumanReadable": text}
    if ctx:
        e["EntryContext"] = ctx
    return e


def test_runs_the_five_scripts_in_the_old_task_order_with_the_old_arguments():
    calls = []
    m.run_steps(lambda s, a: calls.append((s, a)) or [note(s)])
    assert [s for s, _ in calls] == ORDER
    args = dict(calls)
    assert args["SOCFWPromoteAssessment"] == {"phase": "Assessment", "promote": "true",
                                              "source_key": "Assessment.AI", "target_namespace": "Assessment"}
    assert args["SOCFWRenderAssessment"] == {"source_key": "Assessment.AI"}
    assert args["SOCFWEmergencyResponse"] == {"source_key": "Assessment.AI"}
    assert args["SOCFWElevateCase"] == {"actor": "automation", "source_key": "Assessment.AI"}
    assert args["SOCFWCloseDecision"] == {}


def test_every_entry_but_promotes_is_posted_in_order_without_its_context():
    entries, failed = m.run_steps(lambda s, a: [note(s + " one", {"X": 1}), note(s + " two")])
    assert [e["Contents"] for e in entries] == [f"{s} {n}" for s in ORDER[1:] for n in ("one", "two")]
    assert not any("EntryContext" in e for e in entries)
    assert failed == []


def test_an_error_entry_is_posted_and_the_rest_still_run():
    def execute(script, args):
        if script == "SOCFWEmergencyResponse":
            return [{"Type": 4, "ContentsFormat": "text", "Contents": "list unreadable"}]
        return [note(script)]
    entries, failed = m.run_steps(execute)
    assert failed == ["SOCFWEmergencyResponse"]
    assert [e["Contents"] for e in entries][-2:] == ["SOCFWElevateCase", "SOCFWCloseDecision"]
    assert any(e["Type"] == 4 and e["Contents"] == "list unreadable" for e in entries)


def test_an_exception_becomes_an_error_entry_and_the_rest_still_run():
    def execute(script, args):
        if script == "SOCFWPromoteAssessment":
            raise RuntimeError("boom")
        return [note(script)]
    entries, failed = m.run_steps(execute)
    assert failed == ["SOCFWPromoteAssessment"]
    assert entries[0]["Type"] == 4 and "boom" in entries[0]["Contents"]
    assert [e["Contents"] for e in entries[1:]] == ORDER[1:]


def test_promote_stays_quiet_unless_it_fails():
    def execute(script, args):
        if script == "SOCFWPromoteAssessment":
            return [note("promoted"), {"Type": 4, "ContentsFormat": "text", "Contents": "bad json"}]
        return [note(script)]
    entries, failed = m.run_steps(execute)
    assert "promoted" not in [e["Contents"] for e in entries]
    assert entries[0]["Contents"] == "bad json" and failed == ["SOCFWPromoteAssessment"]


def test_a_step_with_no_entries_is_fine():
    entries, failed = m.run_steps(lambda s, a: None)
    assert entries == [] and failed == []
