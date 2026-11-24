"""Which settings the selector obeys, and that starred cases are left to analysts.

Runs main() against a fake tenant: one page of cases from get_incidents and an
optional SOCFWTenantConfig list. Everything else the selector does (settling,
watermark, siblings) is held neutral so only the settings under test decide.
"""
import importlib
import json
import os
import sys
import types
from datetime import datetime, timedelta

HERE = os.path.dirname(__file__)
NOW_MS = int(datetime.utcnow().timestamp() * 1000)
OLD_MS = NOW_MS - 3 * 60 * 60 * 1000  # quiet and old enough to be past settling


def case(case_id, starred=False, alert_count=3):
    return {"incident_id": case_id, "alert_count": alert_count, "status": "new",
            "incident_domain": "DOMAIN_SECURITY", "starred": starred,
            "creation_time": OLD_MS, "modification_time": OLD_MS, "hosts": [], "users": []}


def case_reply(record):
    """What the case context read returns: the record, an error entry for a ("error", text) tuple, or a raise."""
    if isinstance(record, Exception):
        raise record
    if isinstance(record, tuple):
        return [{"Type": 4, "Contents": record[1]}]
    return [{"Type": 1, "Contents": {"response": record}}]


def run(page, tenant=None, records=None, **args):
    """Run main() on one page of cases; records maps a case id to its Analysis contract, or an exception to raise."""
    context, calls = {}, []
    records = records or {}

    def execute(command, cmd_args):
        calls.append((command, cmd_args))
        if command == "getList":
            if tenant is None:
                return [{"Type": 4, "Contents": "Item not found (8)"}]
            return [{"Type": 1, "Contents": json.dumps(tenant)}]
        if command == "core-api-post" and "/investigation/INCIDENT-" in cmd_args["uri"]:
            return case_reply(records.get(cmd_args["uri"].split("INCIDENT-")[1].split("/")[0]))
        if command == "core-api-post":
            return [{"Type": 1, "Contents": {"response": {"reply": {"incidents": page}}}}]
        return []

    def get(obj, path):
        for part in path.split("."):
            obj = obj.get(part) if isinstance(obj, dict) else None
        return obj

    demisto = types.ModuleType("demistomock")
    demisto.args = lambda: {"domain": "DOMAIN_SECURITY", "settle_minutes": "5", **args}
    demisto.executeCommand = execute
    demisto.get = get
    demisto.debug = lambda *a: None
    demisto.setContext = lambda k, v: context.__setitem__(k, v)
    csp = types.ModuleType("CommonServerPython")
    # The script takes these from CommonServerPython's star import, as on the tenant.
    csp.datetime, csp.timedelta, csp.json = datetime, timedelta, json
    csp.demisto = demisto
    csp.tableToMarkdown = lambda *a, **k: ""
    csp.entryTypes = {"error": 4, "note": 1}
    csp.CommandResults = lambda **k: k
    csp.return_results = lambda *a, **k: None

    def return_error(msg):
        raise RuntimeError(msg)

    csp.return_error = return_error
    # execute_command hands back the entry contents, not the entry.
    csp.execute_command = lambda c, a: execute(c, a)[0]["Contents"]
    sys.modules["demistomock"] = demisto
    sys.modules["CommonServerPython"] = csp
    sys.path.insert(0, HERE)
    module = importlib.import_module("SOCFWCaseSelect")
    module = importlib.reload(module)
    module.main()
    context["calls"] = calls
    return context


def picked(ctx):
    return [c["case_id"] for c in ctx["SOCFramework.Case.Candidates"]]


def test_starred_cases_are_analysed_by_default() -> None:
    """A starred case keeps getting a verdict as it grows; the analyst works beside it, not instead of it."""
    ctx = run([case(1), case(2, starred=True)])
    assert picked(ctx) == ["1", "2"]
    assert ctx["SOCFramework.Case.SelectStats"]["skipped_starred"] == 0
    assert ctx["SOCFramework.Case.SelectStats"]["cases"] == "all"


def test_unstarred_leaves_starred_cases_to_analysts() -> None:
    """A tenant that wants the AI off analyst-owned cases says unstarred."""
    ctx = run([case(1), case(2, starred=True)], cases="unstarred")
    assert picked(ctx) == ["1"]
    assert ctx["SOCFramework.Case.SelectStats"]["skipped_starred"] == 1
    assert ctx["SOCFramework.Case.SelectStats"]["cases"] == "unstarred"


def test_tenant_setting_wins_over_the_job_argument() -> None:
    """What SOCFWConfig command=case set on the tenant beats the JOB's own argument."""
    ctx = run([case(1), case(2, starred=True)], tenant={"case": {"cases": "unstarred"}}, cases="all")
    assert picked(ctx) == ["1"]
    assert ctx["SOCFramework.Case.SelectStats"]["settings_from_tenant"] == "cases"


def test_unknown_value_reads_as_the_default() -> None:
    """Only an explicit unstarred narrows the selection."""
    ctx = run([case(1), case(2, starred=True)], cases="every")
    assert picked(ctx) == ["1", "2"]


def test_tenant_window_reaches_the_job_queries():
    ctx = run([case(1)], tenant={"case": {"window_hours": 72}}, window_hours="6")
    assert ctx["SOCFramework.Case.Config.CaseWindowHours"] == "72"
    assert ctx["SOCFramework.Case.SelectStats"]["window_hours"] == 72


def test_job_window_is_used_when_the_tenant_sets_none():
    ctx = run([case(1)], tenant={"triage": {"window_hours": 12}}, window_hours="6")
    assert ctx["SOCFramework.Case.Config.CaseWindowHours"] == "6"
    assert ctx["SOCFramework.Case.SelectStats"]["settings_from_tenant"] is None


def test_tenant_max_analyses_one_means_one_pass():
    watermark = json.dumps([{"case_id": "1", "analyses": 1, "attempts": 1, "alert_count": 1,
                             "covered_issues": 3, "total_issues": 3}])
    ctx = run([case(1, alert_count=5)], tenant={"case": {"max_analyses": 1}},
              max_analyses="2", watermark_rows=watermark)
    assert picked(ctx) == []
    assert ctx["SOCFramework.Case.SelectStats"]["skipped_max_analyses"] == 1


def test_missing_tenant_list_falls_back_to_the_job():
    ctx = run([case(1), case(2, starred=True)], tenant=None, cases="all")
    assert picked(ctx) == ["1", "2"]


def contract(issues, covered=None, total=None, analysed_at="2026-11-22T23:01:55Z"):
    """The case's own Analysis contract as SOCFWCaseVerdictReport writes it."""
    return {"verdict": "malicious", "analysed_issue_count": issues,
            "analysed_covered_issues": issues if covered is None else covered,
            "analysed_total_issues": issues if total is None else total,
            "analysed_at": analysed_at}


def test_a_case_analysed_before_its_dataset_row_is_queryable_is_not_analysed_again():
    """
    Given a case analysed at 8 issues whose verdict row has not reached the watermark yet
    When the next run selects cases
    Then the case's own contract says it is unchanged, so it is skipped
    """
    ctx = run([case(52237, alert_count=8)], records={"52237": contract(8)})
    assert picked(ctx) == []
    stats = ctx["SOCFramework.Case.SelectStats"]
    assert stats["skipped_unchanged"] == 1
    assert stats["skipped_unchanged_on_case"] == 1


def test_the_case_record_wins_over_an_older_watermark():
    """
    Given a watermark from the analysis at 47 issues and a case contract from the one at 48
    When the case still holds 48 issues
    Then it is skipped as unchanged
    """
    watermark = json.dumps([{"case_id": "52247", "analyses": 1, "attempts": 1,
                             "analysed_issue_count": 47, "analysed_covered_issues": 47,
                             "analysed_total_issues": 47}])
    ctx = run([case(52247, alert_count=48)], records={"52247": contract(48)}, watermark_rows=watermark)
    assert picked(ctx) == []


def test_a_case_that_grew_since_its_contract_is_analysed():
    """
    Given a case contract written at 47 issues
    When the case now holds 48
    Then it is selected
    """
    ctx = run([case(52247, alert_count=48)], records={"52247": contract(47)})
    assert picked(ctx) == ["52247"]
    assert ctx["SOCFramework.Case.SelectStats"]["skipped_unchanged_on_case"] == 0


def test_incomplete_coverage_on_the_case_record_is_analysed_again():
    """
    Given a case contract written while 2 of 8 issues had no contract yet
    When the case still holds 8 issues
    Then it is selected so the late contracts are read
    """
    ctx = run([case(52237, alert_count=8)], records={"52237": contract(8, covered=6, total=8)})
    assert picked(ctx) == ["52237"]


def test_a_contract_without_its_barrier_says_nothing():
    """
    Given a case contract with no analysed_at (cleared, or mid-write)
    When the case is selected
    Then the contract is ignored and the case is analysed
    """
    ctx = run([case(52237, alert_count=8)], records={"52237": contract(8, analysed_at=None)})
    assert picked(ctx) == ["52237"]


def test_an_unreadable_case_record_falls_back_to_the_watermark():
    """
    Given a case whose context read fails, and no watermark row
    When the case is selected
    Then it is analysed, as before this check existed
    """
    ctx = run([case(52237, alert_count=8)], records={"52237": RuntimeError("timeout")})
    assert picked(ctx) == ["52237"]


def test_a_case_the_watermark_already_skips_is_not_read():
    """
    Given a case the watermark shows unchanged
    When selection runs
    Then its context is never read, so the check costs nothing on an ordinary run
    """
    watermark = json.dumps([{"case_id": "1", "analyses": 1, "attempts": 1, "analysed_issue_count": 3,
                             "analysed_covered_issues": 3, "analysed_total_issues": 3}])
    ctx = run([case(1)], records={"1": contract(3)}, watermark_rows=watermark)
    assert picked(ctx) == []
    assert ctx["SOCFramework.Case.SelectStats"]["skipped_unchanged_on_case"] == 0
    assert not [c for c in ctx["calls"] if "/investigation/" in str(c[1].get("uri"))]


def test_each_case_read_is_counted_by_what_it_found():
    """
    Given three cases to select: one with a contract, one without, one whose read fails
    When selection runs
    Then the stats count the reads, the empty ones and the failed ones
    """
    ctx = run([case(1, alert_count=4), case(2), case(3)],
              records={"1": contract(4), "2": None, "3": ("error", "Failed to execute core-api-post: 404")})
    stats = ctx["SOCFramework.Case.SelectStats"]
    assert (stats["case_reads"], stats["case_reads_empty"], stats["case_reads_failed"]) == (3, 1, 1)


def test_the_first_failed_read_is_named_with_its_case_and_reply():
    """
    Given a case whose read returns an error entry
    When selection runs
    Then the note names the case and what came back, so a run row says why the check did nothing
    """
    ctx = run([case(3)], records={"3": ("error", "Failed to execute core-api-post: 404")})
    note = ctx["SOCFramework.Case.SelectStats"]["case_read_note"]
    assert "case 3" in note and "404" in note


def test_an_empty_read_is_named_with_the_shape_of_the_reply():
    """
    Given a case whose read returns no contract
    When selection runs
    Then the note names the case and the shape of what came back
    """
    ctx = run([case(2)], records={"2": "SOCFramework.Analysis.AI"})
    note = ctx["SOCFramework.Case.SelectStats"]["case_read_note"]
    assert "case 2" in note and "SOCFramework.Analysis.AI" in note


def test_a_raised_read_is_counted_as_failed():
    """
    Given a case whose read raises
    When selection runs
    Then it counts as failed and the note carries the exception
    """
    ctx = run([case(3)], records={"3": RuntimeError("timeout")})
    stats = ctx["SOCFramework.Case.SelectStats"]
    assert stats["case_reads_failed"] == 1 and "timeout" in stats["case_read_note"]


def test_a_run_whose_reads_all_worked_has_no_note():
    """
    Given a case whose read returns its contract
    When selection runs
    Then there is nothing to report
    """
    ctx = run([case(1, alert_count=4)], records={"1": contract(4)})
    stats = ctx["SOCFramework.Case.SelectStats"]
    assert stats["case_reads"] == 1 and stats["case_read_note"] is None


def test_the_case_read_never_sends_a_raw_dollar_brace():
    """
    Given a case to read
    When selection reads its contract
    Then the body carries no ${ for the platform to resolve against the JOB's own context,
    and still decodes to the context query
    """
    ctx = run([case(52251, alert_count=46)], records={"52251": contract(46)})
    body = [a["body"] for c, a in ctx["calls"] if "/investigation/" in str(a.get("uri"))][0]
    assert "${" not in body
    assert json.loads(body) == {"query": "${SOCFramework.Analysis.AI}"}


def test_the_reply_seen_inside_the_job_reads_as_empty():
    """
    Given the reply a JOB got on deathstar for a blank query, {"response": ""}
    When selection reads it
    Then it counts as empty and the case is selected
    """
    ctx = run([case(52254, alert_count=8)], records={"52254": ""})
    stats = ctx["SOCFramework.Case.SelectStats"]
    assert picked(ctx) == ["52254"]
    assert stats["case_reads_empty"] == 1 and "{'response': ''}" in stats["case_read_note"]
