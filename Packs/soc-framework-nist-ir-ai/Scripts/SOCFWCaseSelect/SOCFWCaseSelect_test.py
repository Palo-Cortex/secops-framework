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


def run(page, tenant=None, **args):
    context, calls = {}, []

    def execute(command, cmd_args):
        calls.append((command, cmd_args))
        if command == "getList":
            if tenant is None:
                return [{"Type": 4, "Contents": "Item not found (8)"}]
            return [{"Type": 1, "Contents": json.dumps(tenant)}]
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
