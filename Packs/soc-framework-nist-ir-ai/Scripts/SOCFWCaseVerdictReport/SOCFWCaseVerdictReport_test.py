"""
SOCFWCaseVerdictReport_test.py

Characterization tests: what the case verdict report does with one AI answer.
It writes the case contract (seeded from the phase contract, barrier last),
posts the War Room entry to the case, marks the title, stars the case when a
person must own it, and posts the execution row. A run with no answer writes
the entry and the row, and leaves the contract alone.

Run: pytest Scripts/SOCFWCaseVerdictReport/SOCFWCaseVerdictReport_test.py -v
"""
import datetime as _dt
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)


class DemistoException(Exception):
    pass


demisto = types.ModuleType("demistomock")
sys.modules["demistomock"] = demisto
csp = types.ModuleType("CommonServerPython")
csp.entryTypes = {"error": 4, "note": 1}
csp.DemistoException = DemistoException
csp.CommandResults = lambda **k: k
csp.datetime = _dt.datetime
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWCaseVerdictReport as vr  # noqa: E402


def _get(obj, path):
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


PHASE_CONTRACT = {"writes_by_phase": {"analysis": [
    {"target": "Analysis.verdict", "init": ""},
    {"target": "Analysis.confidence", "init": ""},
    {"target": "Analysis.case_score", "init": 0},
    {"target": "Analysis.case_host_count", "init": 0},
    {"target": "Analysis.containment_plan", "init": []},
]}}


class Tenant:
    """What the script reaches through executeCommand, recorded."""

    def __init__(self):
        self.calls = []        # (command, uri or None, body or args)
        self.entries = []      # investigation entries the reads return
        self.title = "Phishing along with 3 other issues"
        self.contract_reply = "34 leaves written"
        self.fail = set()      # uris that answer with an error entry
        self.row_reply = "Posted 1 event(s) to the HTTP Collector."
        self.search = {"data": [{"id": "9001"}]}
        self.context = {}
        self.results = []

    def execute(self, cmd, args):
        if cmd == "getList":
            self.calls.append((cmd, None, args))
            return [{"Type": 1, "Contents": json.dumps(PHASE_CONTRACT)}]
        if cmd == "socfw-post-to-dataset":
            self.calls.append((cmd, None, json.loads(args["JSON"])))
            return [{"Type": 1, "Contents": self.row_reply}]
        uri, body = args["uri"], json.loads(args["body"])
        self.calls.append((cmd, uri, body))
        if uri in self.fail:
            return [{"Type": 4, "Contents": "boom"}]
        if uri.startswith("/xsoar/public/v1/investigation/"):
            return [{"Type": 1, "Contents": {"response": {"entries": self.entries}}}]
        if uri == "/xsoar/public/v1/incidents/search":
            return [{"Type": 1, "Contents": json.dumps(self.search)}]
        if uri == "/public_api/v1/incidents/get_incidents/":
            return [{"Type": 1, "Contents": json.dumps(
                {"reply": {"incidents": [{"description": self.title}]}})}]
        if uri == "/xsoar/public/v1/entry/execute/sync" and "SOCFWCaseContractWrite" in body["data"]:
            return [{"Type": 1, "Contents": self.contract_reply}]
        return [{"Type": 1, "Contents": "ok"}]

    def sent(self, uri, contains=""):
        return [b for c, u, b in self.calls
                if u == uri and contains in json.dumps(b)]


@pytest.fixture
def t(monkeypatch):
    tn = Tenant()
    monkeypatch.setattr(demisto, "executeCommand", tn.execute, raising=False)
    monkeypatch.setattr(demisto, "get", _get, raising=False)
    monkeypatch.setattr(demisto, "debug", lambda *a: None, raising=False)
    monkeypatch.setattr(demisto, "context", lambda: tn.context, raising=False)
    monkeypatch.setattr(demisto, "investigation", lambda: {"id": "job-1"}, raising=False)
    monkeypatch.setattr(demisto, "setContext", lambda k, v: tn.context.__setitem__(k, v), raising=False)
    monkeypatch.setattr(vr, "return_results", tn.results.append, raising=False)
    return tn


EXEC = "/xsoar/public/v1/entry/execute/sync"
ANSWER = {"verdict": "malicious", "confidence": "high", "story": ["WHAT FIRED: a macro"],
          "needs_analyst": "false", "containment_plan": [{"step": 1, "action": "isolate", "target": "h1"}]}
PAYLOAD = json.dumps({"shapes": [{"contract_from": "7001"}], "hosts": ["h1", "h2"],
                      "predicted_score": 80, "user_count": 1})


# -- small pieces -------------------------------------------------------------

@pytest.mark.parametrize("ai,expected", [
    ({"needs_analyst": "True"}, True),
    ({"needs_analyst": True}, True),
    ({"recovery_plan": [{"requires_human": "true"}]}, True),
    ({"containment_plan": [{"requires_human": False}], "needs_analyst": "false"}, False),
    ({}, False),
])
def test_a_person_is_needed_when_the_verdict_or_any_plan_step_says_so(ai, expected):
    assert vr.needs_person(ai) is expected


@pytest.mark.parametrize("value,expected", [
    ('{"verdict": "benign"}', {"verdict": "benign"}),
    ([{"verdict": "old"}, {"verdict": "new"}], {"verdict": "new"}),
    ("not json", {}),
    ([], {}),
    (None, {}),
])
def test_a_context_value_becomes_this_iterations_dict(value, expected):
    assert vr.as_obj(value) == expected


def test_only_a_model_call_failure_is_reported_as_one():
    raw = "Error from Scripts: x\nAI Gateway failed to generate content:\n  400   Bad Request"
    assert vr.ai_error_text(raw) == "AI Gateway failed to generate content: 400 Bad Request"
    assert vr.ai_error_text("Error from Scripts: KeyError") == ""


# -- superseding earlier verdicts ---------------------------------------------

def test_earlier_verdicts_are_read_from_the_bare_case_id_and_tagged_once(t):
    t.entries = [
        {"id": "e1", "tags": [vr.VERDICT_TAG]},
        {"id": "e2", "tags": [vr.VERDICT_TAG, vr.SUPERSEDED_TAG]},
        {"id": "e3", "tags": ["other"]},
    ]
    assert vr.supersede_prior("42") == 1
    assert t.sent("/xsoar/public/v1/investigation/42")
    tagged = t.sent("/xsoar/public/v1/entry/tags")
    assert [b["id"] for b in tagged] == ["e1"]
    assert tagged[0]["tags"] == [vr.VERDICT_TAG, vr.SUPERSEDED_TAG]


def test_the_superseded_tag_is_written_to_the_case_investigation(t):
    t.entries = [{"id": "e1", "tags": [vr.VERDICT_TAG]}]
    vr.supersede_prior("42")
    assert t.sent("/xsoar/public/v1/entry/tags")[0]["investigationId"] == "INCIDENT-42"


def test_the_read_asks_for_every_entry(t):
    """page is ignored and pageSize caps the read silently, so no paging arguments."""
    vr.supersede_prior("42")
    assert t.sent("/xsoar/public/v1/investigation/42") == [{}]


def test_a_prefixed_case_id_is_read_bare_and_tagged_prefixed(t):
    t.entries = [{"id": "e1", "tags": [vr.VERDICT_TAG]}]
    assert vr.supersede_prior("INCIDENT-42") == 1
    assert t.sent("/xsoar/public/v1/investigation/42")
    assert t.sent("/xsoar/public/v1/entry/tags")[0]["investigationId"] == "INCIDENT-42"


def test_only_tags_that_landed_are_counted(t, monkeypatch):
    t.entries = [{"id": "e1", "tags": [vr.VERDICT_TAG]}, {"id": "e2", "tags": [vr.VERDICT_TAG]}]
    real = t.execute

    def first_tag_fails(cmd, args):
        if args.get("uri") == "/xsoar/public/v1/entry/tags" and json.loads(args["body"])["id"] == "e1":
            t.calls.append((cmd, args["uri"], json.loads(args["body"])))
            return [{"Type": 4, "Contents": "denied"}]
        return real(cmd, args)
    monkeypatch.setattr(demisto, "executeCommand", first_tag_fails, raising=False)
    assert vr.supersede_prior("42") == 1
    assert [b["id"] for b in t.sent("/xsoar/public/v1/entry/tags")] == ["e1", "e2"]


def test_a_failed_read_supersedes_nothing_and_never_raises(t):
    t.fail.add("/xsoar/public/v1/investigation/42")
    assert vr.supersede_prior("42") == 0


# -- the case contract --------------------------------------------------------

def test_the_contract_is_seeded_from_the_phase_contract_and_the_barrier_is_last(t):
    case = {"IssueCount": 4, "ContractCoverage": {"covered_issues": 3, "total_issues": 4}}
    ok, note = vr.write_case_contract("42", ANSWER, case, json.loads(PAYLOAD))
    assert ok, note
    assert note == "5/5 targets populated, 10 leaves written, barrier set"
    writes = t.sent(EXEC, "SOCFWCaseContractWrite")
    assert len(writes) == 1 and writes[0]["investigationId"] == "7001"
    blob = writes[0]["data"].split("contract=`", 1)[1].rstrip("`")
    contract = json.loads(blob)
    assert contract["verdict"] == "malicious"
    assert contract["case_score"] == 80 and contract["case_host_count"] == 2
    assert contract["containment_plan"] == ANSWER["containment_plan"]
    assert contract["analysed_by"] == "ai" and contract["analysed_covered_issues"] == 3
    assert list(contract)[-1] == vr.BARRIER_LEAF


def test_the_case_subtree_is_cleared_before_the_write(t):
    vr.write_case_contract("42", ANSWER, {"IssueCount": 1}, json.loads(PAYLOAD))
    order = [b["data"] for c, u, b in t.calls if u == EXEC]
    assert order[0] == f"!DeleteContext key={vr.CONTRACT_ROOT}"
    assert t.sent(EXEC, "DeleteContext")[0]["investigationId"] == "INCIDENT-42"
    assert "SOCFWCaseContractWrite" in order[1]


def test_a_failed_clear_stops_the_write_rather_than_append(t):
    t.fail.add(EXEC)
    ok, note = vr.write_case_contract("42", ANSWER, {"IssueCount": 1}, json.loads(PAYLOAD))
    assert not ok and note.startswith("clear failed, write skipped")
    assert not t.sent(EXEC, "SOCFWCaseContractWrite")


def test_without_the_phase_contract_nothing_is_written(t, monkeypatch):
    monkeypatch.setattr(vr, "load_analysis_contract", lambda: [])
    assert vr.write_case_contract("42", ANSWER, {}, {}) == (False, "phase contract unavailable")
    assert not t.sent(EXEC)


@pytest.mark.parametrize("reply,ok", [
    ("34 leaves written", True),
    ("2 leaves written, 1 failed: x", False),
    ("", False),
])
def test_a_contract_write_counts_only_when_the_writer_says_so(t, reply, ok):
    t.contract_reply = reply
    assert vr.write_contract("7001", {"a": 1})[0] is ok


def test_a_backtick_cannot_end_the_contract_argument_early(t):
    vr.write_contract("7001", {"story": "ran `whoami`"})
    data = t.sent(EXEC, "SOCFWCaseContractWrite")[0]["data"]
    assert data.count("`") == 2 and "'whoami'" in data


# -- member issue, War Room, title, star --------------------------------------

def test_the_member_issue_comes_from_the_payload_before_any_search(t):
    assert vr.member_issue("42", {"shapes": [{"sample_alert_id": "7002"}]}) == "7002"
    assert not t.sent("/xsoar/public/v1/incidents/search")


@pytest.mark.parametrize("search", [{"data": [{"id": "9001"}]}, {"response": {"data": [{"id": "9001"}]}}])
def test_without_shapes_the_member_issue_is_searched_for(t, search):
    t.search = search
    assert vr.member_issue("42", {}) == "9001"


def test_the_entry_goes_to_the_case_war_room_as_markdown(t):
    assert vr.post_to_case("42", "## verdict") == (True, "")
    sent = t.sent("/xsoar/public/v1/entry")[0]
    assert sent == {"investigationId": "INCIDENT-42", "data": "## verdict", "markdown": True}


def test_a_failed_entry_write_is_reported_not_raised(t):
    t.fail.add("/xsoar/public/v1/entry")
    ok, err = vr.post_to_case("42", "x")
    assert not ok and "boom" in err


def test_the_title_is_marked_once(t):
    assert vr.mark_case_title("42", "7001") == (True, "marked")
    data = t.sent(EXEC, "setParentIncidentFields")[0]["data"]
    assert data == f'!setParentIncidentFields description="{vr.AI_MARK} Phishing along with 3 other issues"'
    t.title = f"{vr.AI_MARK} already"
    assert vr.mark_case_title("42", "7001") == (True, "already marked")


def test_a_double_quote_in_the_title_cannot_end_the_argument(t):
    t.title = 'Login from "admin"'
    vr.mark_case_title("42", "7001")
    assert "Login from 'admin'" in t.sent(EXEC, "setParentIncidentFields")[0]["data"]


def test_the_star_goes_through_the_universal_command_as_the_ai(t):
    assert vr.star_case("7001") == (True, "star requested")
    assert t.sent(EXEC, "soc-star-case")[0]["data"] == \
        "!SOCCommandWrapper action=soc-star-case Phase=analysis Action_Actor=ai"


# -- reading the answer -------------------------------------------------------

def test_the_answer_is_read_from_this_cases_ai_task_entry(t):
    t.entries = [
        {"parentContent": '!SOCFWCaseAnalysis case_id="41"', "contents": 'p\nAnswer:\n{"verdict":"benign"}'},
        {"parentContent": '!SOCFWCaseAnalysis case_id="42"', "contents": 'prompt\nAnswer:\nok {"verdict":"malicious"} done'},
    ]
    assert vr.ai_from_task_entry("42") == {"verdict": "malicious"}
    assert vr.ai_from_task_entry("43") == {}


@pytest.mark.parametrize("reply,ok", [
    ("Posted 1 event(s) to the HTTP Collector.", True),
    ("", False),
])
def test_the_row_counts_as_posted_only_on_the_writers_word(t, reply, ok):
    t.row_reply = reply
    assert vr.post_execution_row({"case_id": "42"})[0] is ok


# -- main ---------------------------------------------------------------------

def run_main(t, monkeypatch, **args):
    base = {"case_id": "42", "issue_count": 4, "payload": PAYLOAD}
    base.update(args)
    monkeypatch.setattr(demisto, "args", lambda: base, raising=False)
    vr.main()
    rows = [b for c, u, b in t.calls if c == "socfw-post-to-dataset"]
    return rows[-1], t.results[-1]["readable_output"]


def test_a_verdict_writes_the_contract_the_entry_the_title_and_the_row(t, monkeypatch):
    row, out = run_main(t, monkeypatch, ai_output=json.dumps(ANSWER))
    assert row["verdict"] == "malicious" and row["reasoning_status"] == "promoted"
    assert row["case_contract_written"] and row["case_warroom_written"] and row["case_title_marked"]
    assert not row["case_star_requested"]
    assert "**CASE 42** — MALICIOUS" in out and "ledger row:" in out


def test_a_verdict_that_needs_a_person_stars_the_case(t, monkeypatch):
    row, _ = run_main(t, monkeypatch, ai_output=json.dumps(dict(ANSWER, needs_analyst="true")))
    assert row["case_star_requested"] and t.sent(EXEC, "soc-star-case")


def test_no_answer_leaves_the_contract_alone_but_still_reports(t, monkeypatch):
    row, out = run_main(t, monkeypatch)
    assert row["reasoning_status"] == "no_output" and row["verdict"] == "inconclusive"
    assert not t.sent(EXEC, "SOCFWCaseContractWrite") and not t.sent(EXEC, "DeleteContext")
    assert row["case_warroom_written"]
    assert "NO VERDICT" in out and "case contract untouched" in out


def test_a_failed_model_call_is_named_as_the_cause(t, monkeypatch):
    row, out = run_main(t, monkeypatch, ai_error="AI Gateway failed to generate content: 400 Bad Request")
    assert row["reasoning_status"] == "call_failed"
    assert row["ai_error"].startswith("AI Gateway failed")
    assert "The model call failed" in out


def test_a_dropped_row_is_said_out_loud(t, monkeypatch):
    t.row_reply = ""
    _, out = run_main(t, monkeypatch, ai_output=json.dumps(ANSWER))
    assert "LEDGER ROW NOT WRITTEN" in out


def test_the_story_is_cut_to_the_line_budget(t, monkeypatch):
    long = dict(ANSWER, story=[f"step {i}" for i in range(20)])
    _, out = run_main(t, monkeypatch, ai_output=json.dumps(long))
    assert f"  {vr.MAX_STORY_LINES}. step {vr.MAX_STORY_LINES - 1}" in out
    assert f"{20 - vr.MAX_STORY_LINES} further step(s) omitted" in out
