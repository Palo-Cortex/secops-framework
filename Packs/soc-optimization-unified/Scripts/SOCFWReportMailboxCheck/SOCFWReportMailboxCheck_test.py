"""
SOCFWReportMailboxCheck_test.py

Mail delivered to a listed report mailbox is skipped; everything else is
assessed: an empty or missing list, a recipient that is not listed, a click to a
listed mailbox, several recipients where one is a person, and any failure.

Run: pytest Scripts/SOCFWReportMailboxCheck/SOCFWReportMailboxCheck_test.py -v
"""

import importlib
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)
LISTED = {"report_mailboxes": ["abuse@example.com", "phish@example.com"]}


class Results:
    def __init__(self, readable_output=None, **kw):
        self.readable_output = readable_output


class Issue:
    """One issue: its context, the tenant list, and everything the script wrote."""

    def __init__(self, tenant_config=LISTED, recipient="abuse@example.com", click_time=None,
                 click_ip=None, case="INCIDENT-4242", to=None, list_error=False):
        email = {"recipient": recipient, "click_time": click_time, "click_ip": click_ip}
        self.ctx = {"SOCFramework": {"lifecycle": "NIST_IR",
                                     "Email": {k: v for k, v in email.items() if v is not None}}}
        if to is not None:
            self.ctx["SOCFramework"]["Artifacts"] = {"Email": {"To": to}}
        self.tenant_config, self.case, self.list_error = tenant_config, case, list_error
        self.rows, self.context_writes, self.commands = [], {}, []

    def execute(self, command, args):
        self.commands.append(command)
        if command == "getList":
            if self.list_error:
                raise RuntimeError("getList blew up")
            if self.tenant_config is None:
                return [{"Type": 4, "Contents": " - Item not found (8) on list [SOCFWTenantConfig] (2609)"}]
            body = (self.tenant_config if isinstance(self.tenant_config, str)
                    else json.dumps(self.tenant_config))
            return [{"Type": 1, "Contents": body}]
        if command == "socfw-post-to-dataset":
            self.rows.append(json.loads(args["JSON"]))
            return [{"Type": 1, "Contents": "ok"}]
        raise AssertionError(f"unexpected command {command}")


def run(issue):
    out = []

    def get(obj, path):
        for part in path.split("."):
            obj = obj.get(part) if isinstance(obj, dict) else None
        return obj

    demisto = types.ModuleType("demistomock")
    demisto.executeCommand = issue.execute
    demisto.context = lambda: issue.ctx
    demisto.incident = lambda: {"id": "777", "parentXDRIncident": issue.case}
    demisto.setContext = lambda k, v: issue.context_writes.__setitem__(k, v)
    demisto.debug = lambda *a, **k: None
    demisto.get = get
    csp = types.ModuleType("CommonServerPython")
    csp.CommandResults = Results
    csp.return_results = out.append
    sys.modules["demistomock"], sys.modules["CommonServerPython"] = demisto, csp
    sys.path.insert(0, HERE)
    module = importlib.import_module("SOCFWReportMailboxCheck")
    importlib.reload(module)
    module.main()
    return out[0]


SKIP = "SOCFramework.ReportMailbox.skip"


# ── happy path ───────────────────────────────────────────────────────────────

def test_mail_to_a_listed_mailbox_is_left_alone_and_recorded():
    i = Issue()
    r = run(i)
    assert i.context_writes == {SKIP: "true"}
    assert "not assessed" in r.readable_output
    assert i.rows == [{"event_type": "report_mailbox_decision", "status": "left_alone",
                       "incident_id": "777", "case_id": "4242", "parent_xdr_incident": "4242",
                       "recipient": "abuse@example.com", "lifecycle": "NIST_IR",
                       "decided_at": i.rows[0]["decided_at"]}]
    # No phase: the value dashboards select rows by phase and must not pick this up.
    assert "phase" not in i.rows[0]


def test_match_ignores_case_and_display_names():
    i = Issue(recipient='"Abuse Desk" <ABUSE@Example.com>')
    run(i)
    assert i.context_writes == {SKIP: "true"}


def test_recipient_falls_back_to_the_mirrored_key():
    i = Issue(recipient=None, to="phish@example.com")
    run(i)
    assert i.context_writes == {SKIP: "true"}


def test_an_issue_with_no_case_yet_is_still_left_alone():
    i = Issue(case=None)
    run(i)
    assert i.context_writes == {SKIP: "true"} and "case_id" not in i.rows[0]


# ── a click is never skipped ─────────────────────────────────────────────────

@pytest.mark.parametrize("click", [{"click_time": "2026-11-18T12:00:00Z"}, {"click_ip": "203.0.113.9"}])
def test_a_click_to_a_listed_mailbox_is_assessed(click):
    i = Issue(**click)
    r = run(i)
    assert i.context_writes == {}
    assert [row["status"] for row in i.rows] == ["assessed_click"]
    assert "assessed as usual" in r.readable_output


# ── an empty list changes nothing ────────────────────────────────────────────

@pytest.mark.parametrize("config", [None, {}, {"report_mailboxes": []}, {"triage": {"window_hours": 6}},
                                    {"report_mailboxes": "abuse@example.com"}, "not json"])
def test_no_listed_mailbox_writes_nothing_at_all(config):
    i = Issue(tenant_config=config)
    r = run(i)
    assert i.context_writes == {} and i.rows == [] and r.readable_output == ""
    assert i.commands == ["getList"]


# ── everything else is assessed ──────────────────────────────────────────────

@pytest.mark.parametrize("recipient", ["ana@example.com", "abuse@example.org", "notabuse@example.com",
                                       "abuse@example.com.evil.test", "", None])
def test_a_recipient_that_is_not_listed_is_assessed_with_no_row(recipient):
    i = Issue(recipient=recipient)
    r = run(i)
    assert i.context_writes == {} and i.rows == [] and r.readable_output == ""


def test_several_recipients_are_skipped_only_when_all_are_listed():
    mixed = Issue(recipient="abuse@example.com, ana@example.com")
    run(mixed)
    assert mixed.context_writes == {} and mixed.rows == []
    both = Issue(recipient=["abuse@example.com", "phish@example.com"])
    run(both)
    assert both.context_writes == {SKIP: "true"}
    assert both.rows[0]["recipient"] == "abuse@example.com, phish@example.com"


def test_a_failure_reading_the_list_means_the_issue_is_assessed():
    i = Issue(list_error=True)
    r = run(i)
    assert i.context_writes == {} and i.rows == [] and r.readable_output == ""
