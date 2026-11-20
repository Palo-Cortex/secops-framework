"""
SOCFWBuildCasePayload_test.py

Characterization tests: how the four case aggregates are split per case and
collapsed into the payload the case analysis prompt reads. Cases with no
contracted issues are skipped, cases still filling are deferred until the age
escape, repetition below the campaign size is skipped, shapes are capped with
the cap recorded, entities are regrouped by host, and the raw aggregate rows
are cleared from context once collapsed.

Run: pytest Scripts/SOCFWBuildCasePayload/SOCFWBuildCasePayload_test.py -v
"""
import datetime as dt
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
csp.tableToMarkdown = lambda title, rows: f"## {title}\n" + json.dumps(rows)
csp.datetime = dt.datetime
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWBuildCasePayload as bcp  # noqa: E402


def _get(obj, path):
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


def now_ms(minutes_ago=0):
    return int((dt.datetime.utcnow() - dt.timedelta(minutes=minutes_ago)).timestamp() * 1000)


def xql(name, rows, cost=None, quota=None):
    node = {"query_name": name, "results": rows}
    if cost is not None:
        node["query_cost_charged"] = cost
    if quota is not None:
        node["remaining_quota"] = quota
    return node


def shape(cid, name, n, first=None, last=None, **extra):
    row = {"incident_id": cid, "alert_name": name, "n": n}
    if first is not None:
        row["first_seen"] = first
    if last is not None:
        row["last_seen"] = last
    row.update(extra)
    return row


def coverage(cid, n, covered, domain="DOMAIN_SECURITY"):
    return {"incident_id": cid, "n": n, "covered_issues": covered, "issue_domain": domain}


class Tenant:
    def __init__(self):
        self.context = {}
        self.calls = []
        self.results = []

    def execute(self, cmd, args):
        self.calls.append((cmd, args))
        return [{"Type": 1, "Contents": "ok"}]


@pytest.fixture
def t(monkeypatch):
    tn = Tenant()
    monkeypatch.setattr(demisto, "executeCommand", tn.execute, raising=False)
    monkeypatch.setattr(demisto, "get", _get, raising=False)
    monkeypatch.setattr(demisto, "debug", lambda *a: None, raising=False)
    monkeypatch.setattr(demisto, "context", lambda: tn.context, raising=False)
    monkeypatch.setattr(demisto, "setContext", lambda k, v: tn.context.__setitem__(k, v), raising=False)
    monkeypatch.setattr(bcp, "return_results", tn.results.append, raising=False)
    return tn


def run(t, monkeypatch, candidates, shapes=(), entities=(), cov=(), **args):
    t.context["PaloAltoNetworksXQL"] = {"GenericQuery": [
        xql("socfw_case_shapes", list(shapes)),
        xql("socfw_case_entities", list(entities)),
        xql("socfw_case_coverage", list(cov)),
    ]}
    a = {"candidates": candidates}
    a.update(args)
    monkeypatch.setattr(demisto, "args", lambda: a, raising=False)
    bcp.main()
    return t.context


def cand(cid, created=None, **extra):
    c = {"case_id": cid, "alert_count": extra.pop("alert_count", 4),
         "creation_time": now_ms(5) if created is None else created}
    c.update(extra)
    return c


# ── collect_results ──────────────────────────────────────────────────────────

def test_results_are_found_wherever_the_xql_integration_nests_them():
    ctx = {
        "A": {"deep": [{"x": {"QueryName": "socfw_case_shapes", "Results": [{"n": 1}]}}]},
        "B": [xql("socfw_case_entities", [{"n": 2}, {"n": 3}])],
        "C": xql("something_else", [{"n": 9}]),
    }
    found, roots, cost = bcp.collect_results(ctx)
    assert found == {"shapes": [{"n": 1}], "entities": [{"n": 2}, {"n": 3}], "coverage": []}
    assert roots == {"A", "B"}
    assert cost["queries"] == 2 and cost["rows_returned"] == 3


def test_query_cost_is_summed_from_each_reply():
    ctx = {"X": [xql("socfw_case_shapes", [{"n": 1}], cost={"a": 0.25, "b": "0.5"}, quota="7.5"),
                 xql("socfw_case_coverage", [{"n": 1}], cost=1.125, quota=7.5)]}
    _, _, cost = bcp.collect_results(ctx)
    assert cost == {"queries": 2, "cost_charged": 1.875, "rows_returned": 2, "remaining_quota": 7.5}


def test_remaining_quota_is_the_lowest_reported():
    ctx = {"X": [xql("socfw_case_shapes", [{"n": 1}], quota=10),
                 xql("socfw_case_coverage", [{"n": 1}], quota=7.5)]}
    _, _, cost = bcp.collect_results(ctx)
    assert cost["remaining_quota"] == 7.5


def test_a_query_that_returned_no_rows_is_still_counted_and_charged():
    ctx = {"X": [xql("socfw_case_entities", [], cost=0.5, quota=9)]}
    _, _, cost = bcp.collect_results(ctx)
    assert cost["queries"] == 1 and cost["cost_charged"] == 0.5 and cost["remaining_quota"] == 9.0


def test_no_context_finds_nothing():
    found, roots, cost = bcp.collect_results(None)
    assert found == {"shapes": [], "entities": [], "coverage": []} and roots == set()
    assert cost["remaining_quota"] is None


# ── by_case / drop_raw_results ───────────────────────────────────────────────

def test_rows_are_split_by_case_without_their_case_id():
    out = bcp.by_case([{"incident_id": 7, "n": 1}, {"incident_id": "7", "n": 2},
                       {"n": 3}, "junk", {"incident_id": 8, "n": 4}])
    assert out == {"7": [{"n": 1}, {"n": 2}], "8": [{"n": 4}]}


def test_raw_rows_are_cleared_but_framework_context_is_kept(t):
    assert bcp.drop_raw_results({"PaloAltoNetworksXQL", "SOCFramework", "Other"}) == \
        ["Other", "PaloAltoNetworksXQL"]
    assert [a["key"] for c, a in t.calls if c == "DeleteContext"] == ["Other", "PaloAltoNetworksXQL"]


def test_a_failed_clear_is_not_fatal(t, monkeypatch):
    def boom(cmd, args):
        raise RuntimeError("no")
    monkeypatch.setattr(demisto, "executeCommand", boom, raising=False)
    assert bcp.drop_raw_results({"X"}) == []


# ── selection inside main ────────────────────────────────────────────────────

def test_a_case_with_no_contracted_issues_is_skipped(t, monkeypatch):
    ctx = run(t, monkeypatch, [cand("1", incident_domain="Security")],
              shapes=[shape("1", "a", 2), shape("1", "b", 2)],
              cov=[coverage("1", 4, 0)])
    assert ctx["SOCFramework.Case.Payloads"] == []
    assert ctx["SOCFramework.Case.Uncontracted"] == [
        {"case_id": "1", "issues": 4, "issue_domain": "DOMAIN_SECURITY", "incident_domain": "Security"}]
    assert "Skipped — no contracted issues" in t.results[-1]["readable_output"]


def test_a_case_with_no_coverage_row_is_uncontracted_and_counts_its_alerts(t, monkeypatch):
    ctx = run(t, monkeypatch, [cand("1", alert_count=9)])
    assert ctx["SOCFramework.Case.Uncontracted"][0]["issues"] == 9


def test_a_young_case_below_full_coverage_is_deferred(t, monkeypatch):
    ctx = run(t, monkeypatch, [cand("1", created=now_ms(10))],
              shapes=[shape("1", "a", 2), shape("1", "b", 2)], cov=[coverage("1", 4, 3)])
    assert ctx["SOCFramework.Case.Payloads"] == []
    rows = ctx["SOCFramework.Case.ExecutionRows"]
    assert rows[0]["cases_deferred_coverage"] == 1
    assert "Deferred — below the 100.0% coverage floor" in t.results[-1]["readable_output"]


def test_an_old_case_below_full_coverage_is_analysed_as_it_stands(t, monkeypatch):
    ctx = run(t, monkeypatch, [cand("1", created=now_ms(121))],
              shapes=[shape("1", "a", 2), shape("1", "b", 2)], cov=[coverage("1", 4, 3)])
    p = ctx["SOCFramework.Case.Payloads"][0]
    assert p["ContractCoverage"] == {"covered_issues": 3, "total_issues": 4, "pct": 75.0}


def test_the_coverage_floor_and_wait_are_arguments(t, monkeypatch):
    ctx = run(t, monkeypatch, [cand("1", created=now_ms(10))],
              shapes=[shape("1", "a", 2), shape("1", "b", 2)], cov=[coverage("1", 4, 3)],
              min_coverage_pct="70")
    assert len(ctx["SOCFramework.Case.Payloads"]) == 1


def test_a_case_with_no_creation_time_below_full_coverage_is_deferred_every_run(t, monkeypatch):
    """Current behaviour, pinned: with creation_time missing its age reads 0, so
    the max_wait escape never fires and the case waits until coverage reaches the
    floor. Recorded so a change here is deliberate."""
    ctx = run(t, monkeypatch, [cand("1", created=0)],
              shapes=[shape("1", "a", 2), shape("1", "b", 2)], cov=[coverage("1", 4, 3)])
    assert ctx["SOCFramework.Case.Payloads"] == []
    assert ctx["SOCFramework.Case.ExecutionRows"][0]["cases_deferred_coverage"] == 1


def test_repetition_below_the_campaign_size_is_skipped(t, monkeypatch):
    ctx = run(t, monkeypatch, [cand("1")],
              shapes=[shape("1", "Port scan", 19)], cov=[coverage("1", 19, 19)])
    assert ctx["SOCFramework.Case.Payloads"] == []
    assert ctx["SOCFramework.Case.SingleShape"] == [
        {"case_id": "1", "issues": 19, "shapes": 1, "top_shape": "Port scan"}]


def test_a_single_shape_campaign_is_analysed(t, monkeypatch):
    ctx = run(t, monkeypatch, [cand("1", alert_count=20)],
              shapes=[shape("1", "Phish delivered", 20)], cov=[coverage("1", 20, 20)])
    assert [p["ID"] for p in ctx["SOCFramework.Case.Payloads"]] == ["1"]


def test_the_top_shape_falls_back_to_the_issues_dataset_name(t, monkeypatch):
    ctx = run(t, monkeypatch, [cand("1")],
              shapes=[{"incident_id": "1", "xdm.issue.name": "X", "n": 1}],
              cov=[coverage("1", 1, 1)])
    assert ctx["SOCFramework.Case.SingleShape"][0]["top_shape"] == "X"


@pytest.mark.parametrize("raw", [
    json.dumps([{"case_id": "1", "alert_count": 4}]),
    {"case_id": "1", "alert_count": 4},
])
def test_candidates_arrive_as_json_text_or_a_single_object(t, monkeypatch, raw):
    ctx = run(t, monkeypatch, raw, shapes=[shape("1", "a", 2), shape("1", "b", 2)],
              cov=[coverage("1", 4, 4)])
    assert [p["ID"] for p in ctx["SOCFramework.Case.Payloads"]] == ["1"]


def test_unreadable_candidates_mean_no_cases(t, monkeypatch):
    ctx = run(t, monkeypatch, "not json")
    assert ctx["SOCFramework.Case.Payloads"] == []
    assert "No candidate cases had aggregate results" in t.results[-1]["readable_output"]


# ── the payload ──────────────────────────────────────────────────────────────

def analysed(t, monkeypatch, **kw):
    ctx = run(t, monkeypatch, [cand("1", **kw.pop("cand", {}))], **kw)
    p = ctx["SOCFramework.Case.Payloads"][0]
    return p, json.loads(p["Payload"]), ctx


def test_shapes_are_kept_largest_first_and_the_cap_is_recorded(t, monkeypatch):
    shapes = [shape("1", f"s{i}", i) for i in range(1, 6)]
    p, body, _ = analysed(t, monkeypatch, shapes=shapes, cov=[coverage("1", 15, 15)], max_shapes="2")
    assert [s["alert_name"] for s in body["shapes"]] == ["s5", "s4"]
    assert p["ShapeCoverage"] == {"kept": 2, "total": 5, "issue_coverage_pct": 60.0}


def test_the_window_spans_first_and_last_seen(t, monkeypatch):
    p, _, _ = analysed(t, monkeypatch,
                       shapes=[shape("1", "a", 1, first=300, last=400), shape("1", "b", 1, first=100, last=900),
                               shape("1", "c", 1)],
                       cov=[coverage("1", 3, 3)])
    assert p["Window"] == {"first_seen": 100, "last_seen": 900}


def test_issue_names_become_a_sample_and_a_count(t, monkeypatch):
    _, body, _ = analysed(t, monkeypatch,
                          shapes=[shape("1", "a", 3, issue_names=["n1", "n2", "n1"]), shape("1", "b", 1)],
                          cov=[coverage("1", 4, 4)])
    s = body["shapes"][0]
    assert "issue_names" not in s
    assert s["issue_name_sample"] == "n1" and s["distinct_issue_names"] == 2


def test_categories_come_from_the_source_tag_or_alert_source(t, monkeypatch):
    p, _, _ = analysed(t, monkeypatch,
                       shapes=[shape("1", "a", 1, source_tag="Email"), shape("1", "b", 1, alert_source="XDR"),
                               shape("1", "c", 1, source_tag="Email")],
                       cov=[coverage("1", 3, 3)])
    assert p["Categories"] == ["Email", "XDR"]


def test_entities_are_regrouped_by_host_with_their_hashes_and_addresses(t, monkeypatch):
    ents = [
        {"incident_id": "1", "host_name": "h1", "endpoint_id": "e1", "sha": "aa|bb", "lip": "10.0.0.1", "n": 3},
        {"incident_id": "1", "host_name": "h1", "endpoint_id": "e1", "sha": "aa", "lip": "", "n": 2},
        {"incident_id": "1", "host_name": "h2", "endpoint_id": "e2", "sha": None, "lip": "10.0.0.2|10.0.0.1", "n": 1},
        {"incident_id": "1", "host_name": None, "sha": "cc", "lip": None, "n": 4},
    ]
    _, body, _ = analysed(t, monkeypatch, shapes=[shape("1", "a", 1), shape("1", "b", 1)],
                          entities=ents, cov=[coverage("1", 2, 2)])
    assert body["hosts"] == [
        {"host_name": "h1", "endpoint_id": "e1", "n": 5, "hashes": ["aa", "bb"], "ips": ["10.0.0.1"]},
        {"host_name": "h2", "endpoint_id": "e2", "n": 1, "hashes": [], "ips": ["10.0.0.1", "10.0.0.2"]},
    ]
    assert body["file_hashes"] == [{"file_sha256": "aa", "n": 5}, {"file_sha256": "cc", "n": 4},
                                   {"file_sha256": "bb", "n": 3}]
    assert body["ips"] == [{"local_ip": "10.0.0.1", "n": 4}, {"local_ip": "10.0.0.2", "n": 1}]


def test_the_payload_carries_the_candidate_fields(t, monkeypatch):
    _, body, _ = analysed(t, monkeypatch, shapes=[shape("1", "a", 1), shape("1", "b", 1)],
                          cov=[coverage("1", 2, 2)],
                          cand={"host_count": 2, "user_count": 1, "predicted_score": 80,
                                "severity": "HIGH", "users": ["u@x"]})
    assert {k: body[k] for k in ("case_id", "issue_count", "host_count", "user_count",
                                 "predicted_score", "severity", "users")} == {
        "case_id": "1", "issue_count": 4, "host_count": 2, "user_count": 1,
        "predicted_score": 80, "severity": "HIGH", "users": ["u@x"]}
    assert "sibling_cases" not in body


def test_siblings_add_a_note_that_missing_stages_are_unknown(t, monkeypatch):
    p, body, _ = analysed(t, monkeypatch, shapes=[shape("1", "a", 1), shape("1", "b", 1)],
                          cov=[coverage("1", 2, 2)], cand={"siblings": ["2", "3"]})
    assert p["Siblings"] == ["2", "3"] and body["sibling_cases"] == ["2", "3"]
    assert "2 other case(s): 2, 3" in body["sibling_note"]
    assert "unknown, not absent" in body["sibling_note"]


def test_the_payload_is_compact_json_text(t, monkeypatch):
    p, _, _ = analysed(t, monkeypatch, shapes=[shape("1", "a", 1), shape("1", "b", 1)],
                       cov=[coverage("1", 2, 2)])
    assert isinstance(p["Payload"], str) and ": " not in p["Payload"] and ", " not in p["Payload"]


# ── what main leaves behind ──────────────────────────────────────────────────

def test_execution_rows_carry_the_run_and_one_row_per_case(t, monkeypatch):
    t.context["SOCFramework"] = {"Case": {"SelectStats": {"scanned": 10, "candidates": 3, "domain": "Security"}}}
    ctx = run(t, monkeypatch, [cand("1"), cand("2"), cand("3", created=now_ms(1))],
              shapes=[shape("1", "a", 2), shape("1", "b", 2), shape("2", "a", 1)],
              entities=[{"incident_id": "1", "host_name": "h1", "n": 4}],
              cov=[coverage("1", 4, 4), coverage("2", 1, 0), coverage("3", 4, 1)])
    run_row, *case_rows = ctx["SOCFramework.Case.ExecutionRows"]
    assert run_row["event_type"] == "case_analysis_run"
    assert {k: run_row[k] for k in ("cases_scanned", "cases_candidates", "cases_analysed",
                                    "cases_uncontracted", "cases_deferred_coverage",
                                    "cases_single_shape", "domain", "xql_queries")} == {
        "cases_scanned": 10, "cases_candidates": 3, "cases_analysed": 1, "cases_uncontracted": 1,
        "cases_deferred_coverage": 1, "cases_single_shape": 0, "domain": "Security", "xql_queries": 3}
    assert [r["case_id"] for r in case_rows] == ["1"]
    assert case_rows[0]["event_type"] == "case_analysis"
    assert case_rows[0]["payload_bytes"] == len(ctx["SOCFramework.Case.Payloads"][0]["Payload"])


def test_the_raw_aggregate_rows_are_cleared_after_collapsing(t, monkeypatch):
    run(t, monkeypatch, [cand("1")], shapes=[shape("1", "a", 1), shape("1", "b", 1)],
        cov=[coverage("1", 2, 2)])
    assert ("DeleteContext", {"key": "PaloAltoNetworksXQL"}) in t.calls
    assert "Cleared raw aggregate context: PaloAltoNetworksXQL" in t.results[-1]["readable_output"]


def test_every_downstream_path_is_assigned(t, monkeypatch):
    ctx = run(t, monkeypatch, [])
    for key in ("Payloads", "Uncontracted", "SingleShape", "ExecutionRows", "QueryCost"):
        assert f"SOCFramework.Case.{key}" in ctx
    # Three aggregates ran and returned nothing: still three queries, still cleared.
    out = t.results[-1]["readable_output"]
    assert "XQL: 3 queries, 0.0 charged, 0 rows" in out
    assert "Cleared raw aggregate context: PaloAltoNetworksXQL" in out
