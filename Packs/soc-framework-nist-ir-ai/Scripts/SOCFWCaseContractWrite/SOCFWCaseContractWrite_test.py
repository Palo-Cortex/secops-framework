"""
SOCFWCaseContractWrite_test.py

Characterization tests: how a case contract goes up to the parent case. Every
leaf becomes one setParentIncidentContext call under the root, as a string the
case can read back (${SOCFramework.Analysis.AI.verdict}). Case response and the
verdict report both depend on that shape.

Run: pytest Scripts/SOCFWCaseContractWrite/SOCFWCaseContractWrite_test.py -v
"""
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)


class Stop(Exception):
    """return_error ends the script on the tenant; here it raises."""


demisto = types.ModuleType("demistomock")
sys.modules["demistomock"] = demisto
csp = types.ModuleType("CommonServerPython")
csp.entryTypes = {"error": 4, "note": 1}
csp.CommandResults = lambda **k: k


def _return_error(msg):
    raise Stop(msg)


csp.return_error = _return_error
csp.return_results = lambda *a, **k: None
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWCaseContractWrite as ccw  # noqa: E402


@pytest.mark.parametrize("value,text", [
    (True, "true"), (False, "false"), (3, "3"), (0.5, "0.5"), (None, ""),
    ("benign", "benign"), (["a", "b"], '["a","b"]'), ({"k": 1}, '{"k":1}'),
])
def test_every_leaf_is_written_as_the_string_the_case_reads_back(value, text):
    assert ccw.render(value) == text


def run(args, answer=lambda key: [{"Type": 1, "Contents": "ok"}]):
    calls, results = [], []

    def execute(cmd, a):
        calls.append((cmd, a))
        out = answer(a["key"])
        if isinstance(out, Exception):
            raise out
        return out

    demisto.args = lambda: args
    demisto.executeCommand = execute
    ccw.return_results = results.append
    ccw.main()
    return calls, results[0]


def test_one_call_per_top_level_leaf_under_the_default_root():
    calls, result = run({"contract": json.dumps({"verdict": "malicious", "scope": [{"id": "h1"}]})})
    assert calls == [
        ("setParentIncidentContext", {"key": "SOCFramework.Analysis.AI.verdict", "value": "malicious"}),
        ("setParentIncidentContext", {"key": "SOCFramework.Analysis.AI.scope", "value": '[{"id":"h1"}]'}),
    ]
    assert result["outputs"] == {"written": 2, "failed": 0, "root": "SOCFramework.Analysis.AI"}


def test_a_root_given_with_dots_at_the_ends_is_trimmed():
    calls, _ = run({"root": ".SOCFramework.Containment.", "contract": {"status": "done"}})
    assert calls[0][1]["key"] == "SOCFramework.Containment.status"


def test_an_error_entry_or_exception_counts_as_failed_and_the_rest_still_go_up():
    answers = {"SOCFramework.Analysis.AI.a": [{"Type": 4, "Contents": "boom"}],
               "SOCFramework.Analysis.AI.b": RuntimeError("down")}
    calls, result = run({"contract": {"a": 1, "b": 2, "c": 3}},
                        answer=lambda key: answers.get(key, [{"Type": 1, "Contents": "ok"}]))
    assert len(calls) == 3
    assert result["outputs"] == {"written": 1, "failed": 2, "root": "SOCFramework.Analysis.AI"}
    assert "a (boom)" in result["readable_output"] and "b (down)" in result["readable_output"]


@pytest.mark.parametrize("contract,why", [("{not json", "not JSON"), ("{}", "empty"), (None, "empty")])
def test_an_unreadable_or_empty_contract_stops_with_an_error(contract, why):
    with pytest.raises(Stop, match=why):
        run({"contract": contract})
