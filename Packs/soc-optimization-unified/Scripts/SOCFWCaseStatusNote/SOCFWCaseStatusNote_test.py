"""
SOCFWCaseStatusNote_test.py

Characterization tests: one "collecting evidence" note per case, written only
where case analysis is enabled in SOCOptimizationConfig_V3 and only when the
issue is already in a case. The case's status key is read first; if it is
set, nothing is written. Every failure is silent: the note is a courtesy, never
a reason to break the issue's playbook.

Run: pytest Scripts/SOCFWCaseStatusNote/SOCFWCaseStatusNote_test.py -v
"""
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)

demisto = types.ModuleType("demistomock")
sys.modules["demistomock"] = demisto
csp = types.ModuleType("CommonServerPython")
csp.CommandResults = lambda **k: k
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWCaseStatusNote as sn  # noqa: E402


def _get(obj, path):
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


CASE = "INCIDENT-52099"


class Tenant:
    def __init__(self):
        self.config = {"Case Analysis JOB": {"enabled": True}}
        self.status = None
        self.context = {"parentIncidentContext": {"incident": {"parentXDRIncident": CASE}}}
        self.calls = []
        self.results = []
        self.fail = set()

    def execute(self, cmd, args):
        self.calls.append((cmd, args))
        if cmd in self.fail:
            raise RuntimeError(f"{cmd} down")
        if cmd == "getList":
            c = self.config
            return [{"Type": 1, "Contents": c if isinstance(c, str) else json.dumps(c)}]
        uri = args["uri"]
        if uri in self.fail:
            raise RuntimeError(f"{uri} down")
        if uri.endswith("/context"):
            return [{"Type": 1, "Contents": {"response": self.status}}]
        return [{"Type": 1, "Contents": "ok"}]

    def writes(self):
        return [json.loads(a["body"]) for c, a in self.calls
                if c == "core-api-post" and a["uri"] == "/xsoar/public/v1/entry/execute/sync"]


@pytest.fixture
def t(monkeypatch):
    tn = Tenant()
    monkeypatch.setattr(demisto, "executeCommand", tn.execute, raising=False)
    monkeypatch.setattr(demisto, "get", _get, raising=False)
    monkeypatch.setattr(demisto, "debug", lambda *a: None, raising=False)
    monkeypatch.setattr(demisto, "context", lambda: tn.context, raising=False)
    monkeypatch.setattr(sn, "return_results", tn.results.append, raising=False)
    return tn


def test_the_first_issue_in_a_case_writes_the_status_and_the_note(t):
    sn.main()
    read = [a for c, a in t.calls if c == "core-api-post" and a["uri"].endswith("/context")]
    assert read[0]["uri"] == f"/xsoar/public/v1/investigation/{CASE}/context"
    assert json.loads(read[0]["body"]) == {"query": "${SOCFramework.Case.Status}"}
    w = t.writes()
    assert w[0] == {"investigationId": CASE, "data": "!Set key=SOCFramework.Case.Status value=collecting"}
    assert w[1]["investigationId"] == CASE and w[1]["data"].startswith("!Print value=`")
    assert "collecting evidence" in w[1]["data"]
    assert t.results[-1]["readable_output"] == f"Case status written to {CASE}."


def test_a_case_already_marked_gets_nothing_more(t):
    t.status = "collecting"
    sn.main()
    assert t.writes() == [] and t.results[-1]["readable_output"] == ""


def test_an_issue_not_yet_in_a_case_writes_nothing(t):
    t.context = {}
    sn.main()
    assert not [c for c, a in t.calls if c == "core-api-post"]
    assert t.results[-1]["readable_output"] == ""


@pytest.mark.parametrize("config", [
    {"Case Analysis JOB": {"enabled": False}},
    {"Case Analysis JOB": {}},
    {},
    "Item not found (8)",
    "",
])
def test_nothing_is_said_where_case_analysis_is_not_enabled(t, config):
    t.config = config
    sn.main()
    assert not [c for c, a in t.calls if c == "core-api-post"]
    assert t.results[-1]["readable_output"] == ""


def test_an_unreadable_config_stays_silent(t):
    t.fail.add("getList")
    sn.main()
    assert not [c for c, a in t.calls if c == "core-api-post"]


def test_a_failed_status_read_still_writes_the_note(t):
    t.fail.add(f"/xsoar/public/v1/investigation/{CASE}/context")
    sn.main()
    assert len(t.writes()) == 2


def test_a_failed_write_is_silent(t):
    t.fail.add("/xsoar/public/v1/entry/execute/sync")
    sn.main()
    assert t.results[-1]["readable_output"] == ""


@pytest.mark.xfail(strict=True, reason=(
    "Known defect: enabled is read with bool(), so the string \"false\" reads as "
    "enabled. A config written as text (by hand, or by a tool that writes strings) "
    "makes the note promise a verdict on a tenant with case analysis off."))
def test_enabled_written_as_the_text_false_is_off(t):
    t.config = {"Case Analysis JOB": {"enabled": "false"}}
    sn.main()
    assert not [c for c, a in t.calls if c == "core-api-post"]
