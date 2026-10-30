"""
SOCAutoTriageScoreFilter_test.py

Where the score threshold and age window come from (the JOB's argument or the
tenant's SOCFWTenantConfig 'triage' override), and that a whole run honours
them: a tenant threshold beats the JOB's, 'off' drops the score gate but never
the starred, status or age guards, and an unusable value closes nothing.

Run: pytest Scripts/SOCAutoTriageScoreFilter/SOCAutoTriageScoreFilter_test.py -v
"""

import importlib
import json
import os
import sys
import time
import types

import pytest

HERE = os.path.dirname(__file__)
HOUR_MS = 3600 * 1000


class Results:
    def __init__(self, readable_output=None, outputs_prefix=None, outputs=None, **kw):
        self.readable_output, self.outputs_prefix, self.outputs = readable_output, outputs_prefix, outputs


class Fake:
    """getList for SOCFWTenantConfig, one get_incidents page, closes and dataset rows."""

    def __init__(self, tenant_config=None, cases=()):
        self.tenant_config = tenant_config
        self.cases = list(cases)
        self.closed, self.rows = [], []

    def raw(self, command, args):
        if command == "getList":
            if self.tenant_config is None:
                return [{"Type": 4, "Contents": " - Item not found (8) on list [SOCFWTenantConfig] (2609)"}]
            body = self.tenant_config if isinstance(self.tenant_config, str) else json.dumps(self.tenant_config)
            return [{"Type": 1, "Contents": body}]
        raise AssertionError(f"unexpected demisto.executeCommand {command}")

    def execute(self, command, args):
        if command == "core-api-post":
            body = json.loads(args["body"])["request_data"]
            if args["uri"].endswith("get_incidents"):
                page = self.cases[body["search_from"]:body["search_to"]]
                return [{"response": {"reply": {"incidents": page}}}]
            self.closed.append(body["incident_id"])
            return [{"response": {"reply": True}}]
        if command == "socfw-post-to-dataset":
            self.rows += json.loads(args["JSON"])
            return [{"Contents": "ok"}]
        raise AssertionError(f"unexpected execute_command {command}")


def load(fake, args):
    out, errors = [], []

    def get(obj, path):
        for part in path.split("."):
            obj = obj.get(part) if isinstance(obj, dict) else None
        return obj

    demisto = types.ModuleType("demistomock")
    demisto.args = lambda: args
    demisto.executeCommand = fake.raw
    demisto.debug = lambda *a, **k: None
    demisto.get = get
    csp = types.ModuleType("CommonServerPython")
    csp.CommandResults = Results
    csp.return_results = out.append

    def return_error(msg):
        errors.append(msg)
        raise SystemExit(msg)

    csp.return_error = return_error
    csp.execute_command = lambda c, a: fake.execute(c, a)[0]
    sys.modules["demistomock"], sys.modules["CommonServerPython"] = demisto, csp
    sys.path.insert(0, HERE)
    module = importlib.import_module("SOCAutoTriageScoreFilter")
    importlib.reload(module)
    return module, out, errors


def case(cid, score, age_hours=24, starred=False, status="new"):
    return {"incident_id": cid, "aggregated_score": score, "starred": starred, "status": status,
            "manual_score": None, "incident_domain": "DOMAIN_SECURITY",
            "creation_time": int(time.time() * 1000) - int(age_hours * HOUR_MS)}


def run(fake, **args):
    module, out, errors = load(fake, args)
    try:
        module.main()
    except SystemExit:
        pass
    return (out[0] if out else None), errors


# ── where the settings come from ────────────────────────────────────────────

def resolve(args, overrides):
    module, _, _ = load(Fake(), {})
    return module.resolve_settings(args, overrides)


def test_job_arguments_are_used_when_the_tenant_sets_nothing():
    assert resolve({"score_threshold": "40", "window_hours": "6"}, {}) == (
        40.0, 6.0, {"score_threshold": "argument", "window_hours": "argument"})


def test_defaults_when_nothing_is_passed():
    threshold, window, _ = resolve({}, {})
    assert (threshold, window) == (40.0, 6.0)


def test_tenant_values_win_over_the_job_arguments():
    threshold, window, sources = resolve({"score_threshold": "40", "window_hours": "6"},
                                         {"score_threshold": 100, "window_hours": 12})
    assert (threshold, window) == (100.0, 12.0)
    assert sources == {"score_threshold": "SOCFWTenantConfig", "window_hours": "SOCFWTenantConfig"}


def test_one_tenant_value_leaves_the_other_to_the_job():
    threshold, window, sources = resolve({"score_threshold": "40", "window_hours": "6"}, {"window_hours": 2})
    assert (threshold, window) == (40.0, 2.0)
    assert sources["score_threshold"] == "argument"


def test_off_means_no_score_gate():
    threshold, _, _ = resolve({"score_threshold": "40"}, {"score_threshold": "off"})
    assert threshold is None


@pytest.mark.parametrize("args, overrides", [
    ({}, {"score_threshold": "high"}),
    ({}, {"window_hours": 0}),
    ({"window_hours": "-1"}, {}),
    ({"score_threshold": "abc"}, {}),
])
def test_unusable_values_are_refused(args, overrides):
    with pytest.raises(ValueError):
        resolve(args, overrides)


@pytest.mark.parametrize("config", [None, "not json", {"triage": "100"}, {"Zscaler": {"using": "z"}}])
def test_missing_or_unusable_tenant_list_means_no_overrides(config):
    module, _, _ = load(Fake(tenant_config=config), {})
    assert module.tenant_triage() == {}


def test_tenant_list_triage_section_is_read():
    module, _, _ = load(Fake(tenant_config={"triage": {"score_threshold": 100}}), {})
    assert module.tenant_triage() == {"score_threshold": 100}


# ── a whole run ──────────────────────────────────────────────────────────────

CASES = [case("1", 20), case("2", 80), case("3", 100), case("4", 10, starred=True),
         case("5", 10, status="under_investigation"), case("6", 10, age_hours=2), case("7", None)]


def test_job_threshold_closes_only_low_scores():
    f = Fake(cases=CASES)
    r, errors = run(f, score_threshold="40", window_hours="6")
    assert not errors and f.closed == ["1"]
    assert r.outputs["settings_from"]["score_threshold"] == "argument"


def test_tenant_threshold_100_beats_the_job_40():
    f = Fake(tenant_config={"triage": {"score_threshold": 100}}, cases=CASES)
    r, _ = run(f, score_threshold="40", window_hours="6")
    assert f.closed == ["1", "2", "3"]
    assert r.outputs["score_threshold"] == 100.0
    assert "threshold: 100.0 (SOCFWTenantConfig)" in r.readable_output


def test_off_closes_any_score_but_keeps_starred_status_and_age_guards():
    f = Fake(tenant_config={"triage": {"score_threshold": "off"}}, cases=CASES)
    r, _ = run(f, score_threshold="40", window_hours="6")
    assert f.closed == ["1", "2", "3", "7"]       # 7 has no score: closable only with the score off
    assert r.outputs["score_threshold"] == "off"
    reasons = {s["incident_id"]: s["reason"] for s in r.outputs["skipped_incidents"]}
    assert reasons["4"].startswith("starred guard") and reasons["5"].startswith("status guard")
    assert "6" not in f.closed


def test_tenant_window_lets_younger_cases_close():
    f = Fake(tenant_config={"triage": {"window_hours": 1}}, cases=CASES)
    r, _ = run(f, score_threshold="40", window_hours="6")
    assert sorted(f.closed) == ["1", "6"]
    assert "window: 1.0h (SOCFWTenantConfig)" in r.readable_output


def test_dry_run_with_tenant_values_closes_nothing():
    f = Fake(tenant_config={"triage": {"score_threshold": 100}}, cases=CASES)
    r, _ = run(f, score_threshold="40", window_hours="6", dry_run="true")
    assert f.closed == [] and r.outputs["would_close_count"] == 3
    assert all(row["execution_mode"] == "shadow" for row in f.rows)


def test_unusable_tenant_value_closes_nothing():
    f = Fake(tenant_config={"triage": {"score_threshold": "lots"}}, cases=CASES)
    r, errors = run(f, score_threshold="40", window_hours="6")
    assert r is None and f.closed == []
    assert "SOCFWTenantConfig" in errors[0]
