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
            record = records.get(cmd_args["uri"].split("INCIDENT-")[1].split("/")[0])
            if isinstance(record, Exception):
                raise record
            return [{"Type": 1, "Contents": {"response": record}}]
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


def test_starred_cases_are_left_to_analysts_by_default():
    ctx = run([case(1), case(2, starred=True)])
    assert picked(ctx) == ["1"]
    assert ctx["SOCFramework.Case.SelectStats"]["skipped_starred"] == 1
    assert ctx["SOCFramework.Case.SelectStats"]["cases"] == "unstarred"


def test_all_takes_starred_cases_too():
    ctx = run([case(1), case(2, starred=True)], cases="all")
    assert picked(ctx) == ["1", "2"]


def test_tenant_setting_wins_over_the_job_argument():
    ctx = run([case(1), case(2, starred=True)], tenant={"case": {"cases": "all"}}, cases="unstarred")
    assert picked(ctx) == ["1", "2"]
    assert ctx["SOCFramework.Case.SelectStats"]["settings_from_tenant"] == "cases"


def test_unknown_value_reads_as_unstarred():
    ctx = run([case(1), case(2, starred=True)], cases="every")
    assert picked(ctx) == ["1"]


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
