"""
SOCFWHealthCheck_test.py

The Configuration section grades what SOCFWConfig status reports: a JOB that is
on with an owner who is not a user is a FAIL, Auto Triage with the score gate off
is a WARN, missing required values are a WARN, and a SOCFWConfig that fails is a
FAIL that does not stop the rest of the check. The check is read-only: no run
writes a list.

Run: pytest Scripts/SOCFWHealthCheck/SOCFWHealthCheck_test.py -v
"""

import importlib
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)


class Results:
    def __init__(self, readable_output=None, outputs_prefix=None, outputs=None, **kw):
        self.readable_output, self.outputs_prefix, self.outputs = readable_output, outputs_prefix, outputs


def status(**over):
    base = {
        "tenant_config_exists": True,
        "rows": [
            {"action": "soc-star-case", "actor": "automation", "state": "live", "read_only": False},
            {"action": "soc-close-issue", "actor": "ai", "state": "live", "read_only": False},
            {"action": "soc-isolate-endpoint", "actor": "issue_emergency", "state": "shadow", "read_only": False},
            {"action": "soc-isolate-endpoint", "actor": "analyst", "state": "live", "read_only": False},
        ],
        "values": [{"vendor": "Zscaler", "arg": "using", "required": False, "set": False}],
        "jobs": [{"job": "Auto Triage V3", "installed": True, "scheduled": True,
                  "owner": "dc@example.com", "owner_is_user": True}],
        "mode": "pov",
        "triage": {"score_threshold": {"effective": 40, "from": "shipped"},
                   "window_hours": {"effective": 6, "from": "shipped"}},
        "emergency": {"enabled": True, "policies": 4, "tenant_policies": 0},
    }
    base.update(over)
    return base


class Fake:
    def __init__(self, config=None, config_error=None):
        self.config, self.config_error = config, config_error
        self.calls, self.writes = [], []

    def raw(self, command, args):
        self.calls.append((command, args))
        if command == "SOCFWConfig":
            if self.config_error:
                return [{"Type": 4, "Contents": self.config_error}]
            return [{"Type": 1, "Contents": "", "EntryContext": {"SOCFWConfig.Status": self.config}}]
        if command == "getList":
            raise AssertionError("the health check must not read or create lists")
        raise AssertionError(f"unexpected demisto.executeCommand {command}")

    def execute(self, command, args, fail_on_error=False):
        self.calls.append((command, args))
        if "lists/save" in str(args.get("uri")):
            self.writes.append(args)
        return False, "no Core REST API in this test"


def load(fake, args=None):
    out = []
    demisto = types.ModuleType("demistomock")
    demisto.args = lambda: args or {}
    demisto.executeCommand = fake.raw
    for name in ("debug", "info", "error"):
        setattr(demisto, name, lambda *a, **k: None)
    csp = types.ModuleType("CommonServerPython")
    csp.CommandResults = Results
    csp.return_results = out.append
    csp.return_error = lambda m: (_ for _ in ()).throw(SystemExit(m))
    csp.execute_command = fake.execute
    csp.entryTypes = {"error": 4, "note": 1}
    csp.argToBoolean = lambda v: str(v).lower() == "true"
    csp.argToList = lambda v: [x.strip() for x in str(v).split(",") if x.strip()] if v else []
    csp.register_module_line = lambda *a, **k: None
    sys.modules["demistomock"], sys.modules["CommonServerPython"] = demisto, csp
    builtins = __import__("builtins")
    for k in ("demisto", "CommandResults", "return_results", "return_error", "execute_command",
              "entryTypes", "argToBoolean", "argToList", "register_module_line"):
        setattr(builtins, k, demisto if k == "demisto" else getattr(csp, k))
    builtins.__line__ = lambda: 0
    sys.path.insert(0, HERE)
    module = importlib.import_module("SOCFWHealthCheck")
    importlib.reload(module)
    return module, out


def config_checks(**over):
    module, _ = load(Fake(config=status(**over)))
    return {c["check"]: c for c in module.check_configuration()}


def test_a_healthy_pov_tenant_is_all_ok():
    checks = config_checks()
    assert all(c["status"] == "OK" for c in checks.values()), checks
    assert "matches pov" in checks["Mode"]["detail"]
    assert "soc-star-case (automation)" in checks["Mode"]["detail"]
    assert "analyst" not in checks["Mode"]["detail"]          # analyst actions are not automation
    assert "soc-isolate-endpoint" not in checks["Mode"]["detail"]


def test_a_job_on_with_an_owner_who_is_not_a_user_fails():
    c = config_checks(jobs=[{"job": "Auto Triage V3", "installed": True, "scheduled": True,
                             "owner": "set-owner-with-SOCFWConfig", "owner_is_user": False}])
    job = c["JOB: Auto Triage V3"]
    assert job["status"] == "FAIL" and "command=owner" in job["detail"]


def test_a_job_off_with_the_placeholder_owner_is_fine():
    c = config_checks(jobs=[{"job": "Auto Triage V3", "installed": True, "scheduled": False,
                             "owner": "set-owner-with-SOCFWConfig", "owner_is_user": False}])
    assert c["JOB: Auto Triage V3"]["status"] == "OK"
    assert "before turning it on" in c["JOB: Auto Triage V3"]["detail"]


def test_an_owner_that_cannot_be_checked_warns():
    c = config_checks(jobs=[{"job": "Auto Triage V3", "installed": True, "scheduled": True,
                             "owner": "dc@example.com", "owner_is_user": None}])
    assert c["JOB: Auto Triage V3"]["status"] == "WARN"


def test_a_missing_job_and_unreadable_jobs_warn():
    assert config_checks(jobs=[{"job": "Auto Triage V3", "installed": False}])[
        "JOB: Auto Triage V3"]["status"] == "WARN"
    assert config_checks(jobs=[])["Framework JOBs"]["status"] == "WARN"


def test_score_gate_off_warns():
    c = config_checks(triage={"score_threshold": {"effective": "off", "from": "tenant"},
                              "window_hours": {"effective": 6, "from": "shipped"}})
    assert c["Auto Triage settings"]["status"] == "WARN"


def test_tenant_triage_values_are_shown_with_their_source():
    c = config_checks(triage={"score_threshold": {"effective": 100, "from": "tenant"},
                              "window_hours": {"effective": 12, "from": "tenant"}})
    assert c["Auto Triage settings"]["detail"] == "score below 100 (tenant), older than 12h (tenant)"


def test_missing_required_value_warns_and_says_how_to_set_it():
    c = config_checks(values=[{"vendor": "CrowdStrike Falcon", "arg": "using", "required": True, "set": False}])
    assert c["Customer values"]["status"] == "WARN"
    assert "CrowdStrike Falcon using" in c["Customer values"]["detail"]


def test_custom_mode_and_no_tenant_config_are_reported():
    c = config_checks(mode="custom", tenant_config_exists=False, rows=[])
    assert c["Mode"]["detail"] == "matches custom; nothing automated runs for real"
    assert "shipped settings" in c["Tenant config (SOCFWTenantConfig)"]["detail"]


def test_unreadable_sections_warn():
    s = status()
    for key in ("mode", "triage", "emergency"):
        s.pop(key)
    module, _ = load(Fake(config=s))
    c = {x["check"]: x for x in module.check_configuration()}
    assert c["Mode"]["status"] == c["Auto Triage settings"]["status"] == c["Emergency response"]["status"] == "WARN"


def test_socfwconfig_failure_is_one_fail_and_the_run_goes_on():
    fake = Fake(config_error="SOCFWConfig: SOCFWTenantConfig is not valid JSON")
    module, out = load(fake)
    module.main()
    r = out[0].outputs
    first = r["checks"][0]
    assert first["status"] == "FAIL" and "not valid JSON" in first["detail"]
    assert r["overall_status"] == "FAIL" and len(r["checks"]) > 1


def test_a_run_writes_nothing():
    fake = Fake(config=status())
    module, out = load(fake)
    module.main()
    assert fake.writes == []
    assert not any(c[0] == "getList" for c in fake.calls)
    assert out[0].outputs_prefix == "SOCFWHealthCheck"
    assert "SOCFW_UniversalCommand" not in out[0].readable_output


def test_yml_declares_what_the_script_reads_and_writes():
    import re
    import yaml
    spec = yaml.safe_load(open(os.path.join(HERE, "SOCFWHealthCheck.yml")))
    src = open(os.path.join(HERE, "SOCFWHealthCheck.py")).read()
    read = set(re.findall(r'args\.get\("([a-z_]+)"', src))
    assert {a["name"] for a in spec["args"]} == read
    declared = {o["contextPath"] for o in spec["outputs"]}
    module, out = load(Fake(config=status()))
    module.main()
    assert {f"SOCFWHealthCheck.{k}" for k in out[0].outputs} == declared


ASSIGN_ON = [{"job": "Auto Triage V3", "installed": True, "scheduled": True, "owner": "dc@example.com",
              "owner_is_user": True},
             {"job": "SOCFW Analyst Assignment", "installed": True, "scheduled": True, "owner": "dc@example.com",
              "owner_is_user": True}]


class RosterFake(Fake):
    def __init__(self, rows=None, error=None, **kw):
        super().__init__(**kw)
        self.rows, self.error = rows, error

    def execute(self, command, args, fail_on_error=False):
        self.calls.append((command, args))
        if "lookups/get_data" in str(args.get("uri")):
            if self.error:
                return False, self.error
            return True, [{"response": {"reply": {"data": self.rows}}}]
        return False, "no Core REST API in this test"


def roster_check(rows=None, error=None, jobs=ASSIGN_ON):
    module, _ = load(RosterFake(rows=rows, error=error, config=status(jobs=jobs)))
    return {c["check"]: c for c in module.check_configuration()}.get("Analyst assignment roster")


def test_roster_only_from_the_role_fallback_warns_with_the_fix():
    c = roster_check(rows=[{"email": "dc@example.com", "source": "xsiam_role"}])
    assert c["status"] == "WARN" and "SOCFWOnDutySync analysts=" in c["detail"]


def test_roster_with_the_customer_analysts_is_ok():
    c = roster_check(rows=[{"email": "a@x.com", "source": "manual"}, {"email": "b@x.com", "source": "xsiam_role"}])
    assert c["status"] == "OK" and "1 manual" in c["detail"]


def test_no_roster_yet_or_nobody_on_duty_warns():
    assert roster_check(error="Dataset socfw_on_duty not found")["status"] == "WARN"
    assert roster_check(rows=[])["status"] == "WARN"


def test_no_roster_check_while_the_assignment_job_is_off():
    jobs = [dict(ASSIGN_ON[1], scheduled=False)]
    assert roster_check(rows=[], jobs=jobs) is None


def named(instances, api_ok=True):
    module, _ = load(Fake(config=status()))
    return {c["check"].replace("Instance: ", ""): c for c in module.check_named_instances(instances, api_ok)}


WRITER = "socfw_ir_execution_writer"


def inst(name, brand="SOCFWDatasetWriter", enabled="true"):
    return {"name": name, "brand": brand, "enabled": enabled}


def test_named_instances_all_present_are_ok():
    module, _ = load(Fake(config=status()))
    all_ok = [inst(n, b) for n, (b, _) in module.REQUIRED_INSTANCES.items()]
    assert all(c["status"] == "OK" for c in named(all_ok).values())


def test_same_brand_under_another_name_fails_and_names_the_rename():
    c = named([inst("SOCFWDatasetWriter_instance_1")])[WRITER]
    assert c["status"] == "FAIL"
    assert "SOCFWDatasetWriter_instance_1" in c["detail"] and f"rename one to {WRITER}" in c["detail"]


def test_missing_brand_says_what_to_create():
    c = named([])[WRITER]
    assert c["status"] == "FAIL" and f"named exactly {WRITER}" in c["detail"]


def test_disabled_named_instance_fails():
    assert named([inst(WRITER, enabled="false")])[WRITER]["status"] == "FAIL"


def test_unreadable_instances_warn():
    assert all(c["status"] == "WARN" for c in named([], api_ok=False).values())


def test_brand_check_leaves_named_brands_alone():
    module, _ = load(Fake(config=status()))
    cfg = [{"name": WRITER, "brand": "SOCFWDatasetWriter"}, {"name": "Whois_instance_SOCFW", "brand": "Whois"}]
    checks = module.check_integration_instances_from_config(cfg, [inst("w", "Whois")], True)
    assert [c["check"] for c in checks] == ["Integration: Whois"]


def test_every_instance_called_by_name_is_required_and_shipped():
    """Every using= name in the pack's scripts and action list is in REQUIRED_INSTANCES,
    and xsoar_config.json ships each with the same brand."""
    import glob
    import json
    import re
    pack = os.path.abspath(os.path.join(HERE, "..", ".."))
    called = set()
    for path in glob.glob(os.path.join(pack, "Scripts", "*", "*.py")):
        if "_test" in os.path.basename(path):
            continue
        src = open(path).read()
        called |= set(re.findall(r'"using":\s*"([^"]+)"', src))
        called |= set(re.findall(r'^(?:DATASET_INSTANCE|DATASET_WRITER_INSTANCE|DEFAULT_INSTANCE)\s*=\s*["\']([^"\']+)',
                                 src, re.M))
    actions = open(os.path.join(pack, "Lists", "SOCFrameworkActions_V3", "SOCFrameworkActions_V3_data.json")).read()
    called |= {u for u in re.findall(r'"using":\s*"([^"]*)"', actions) if u}
    module, _ = load(Fake(config=status()))
    assert called == set(module.REQUIRED_INSTANCES), called ^ set(module.REQUIRED_INSTANCES)
    shipped = {i["name"]: i["brand"] for i in json.load(open(os.path.join(pack, "xsoar_config.json")))["integration_instances"]}
    for name, (brand, _) in module.REQUIRED_INSTANCES.items():
        assert shipped.get(name) == brand, name
