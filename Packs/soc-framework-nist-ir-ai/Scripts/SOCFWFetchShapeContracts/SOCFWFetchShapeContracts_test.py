"""
SOCFWFetchShapeContracts_test.py

Characterization tests: how each shape in a case payload gets the SOC Framework
contract of one of its issues. Only the evidence keys of the contract travel,
with the configured intel roots alongside; a shape whose issues carry no
contract is marked absent, one whose read failed is marked unreadable and
defers the case until the deferral limit; entry-vector indicators are lifted to
case level before the character budget drops the smallest shapes; and every
truncation is declared in the payload.

Run: pytest Scripts/SOCFWFetchShapeContracts/SOCFWFetchShapeContracts_test.py -v
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
csp.tableToMarkdown = lambda title, rows: f"## {title}\n" + json.dumps(rows)
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWFetchShapeContracts as fsc  # noqa: E402


def contract(**artifacts):
    return {"Artifacts": artifacts or {"Endpoint": {"Hostname": "h1"}}, "Product": {"Category": "Endpoint"},
            "lifecycle": "NIST_IR", "NormalizeFromList": {"big": "x" * 50}, "Enrichment": {"lanes": 3}}


class Tenant:
    """getContext answers per issue id: a dict is that issue's context, an
    Exception is raised, any other value is returned as the command result."""

    def __init__(self):
        self.issues = {}
        self.context = {}
        self.calls = []
        self.results = []

    def execute(self, cmd, args):
        self.calls.append((cmd, args))
        answer = self.issues.get(args["id"], {"context": {}})
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, dict):
            return [{"Type": 1, "Contents": json.dumps(answer)}]
        return answer


@pytest.fixture
def t(monkeypatch):
    tn = Tenant()
    monkeypatch.setattr(demisto, "executeCommand", tn.execute, raising=False)
    monkeypatch.setattr(demisto, "setContext", lambda k, v: tn.context.__setitem__(k, v), raising=False)
    monkeypatch.setattr(fsc, "return_results", tn.results.append, raising=False)
    return tn


def issue(sf=None, **roots):
    ctx = dict(roots)
    if sf is not None:
        ctx["SOCFramework"] = sf
    return {"context": ctx}


def case(cid, shapes, prior=0, **extra):
    p = {"ID": cid, "Payload": json.dumps(dict({"case_id": cid, "shapes": shapes}, **extra))}
    if prior:
        p["PriorDeferrals"] = prior
    return p


def run(t, monkeypatch, payloads, **args):
    a = {"payloads": payloads}
    a.update(args)
    monkeypatch.setattr(demisto, "args", lambda: a, raising=False)
    fsc.main()
    return t.context


def body(ctx, i=0):
    return json.loads(ctx["SOCFramework.Case.Payloads"][i]["Payload"])


# ── collect_indicators / intel_roots ─────────────────────────────────────────

def test_the_entry_vector_is_lifted_from_every_shape_without_duplicates():
    shapes = [
        {"contract": {"Artifacts": {"Email": {"ThreatURL": ["http://a", " http://b "], "From": "x@y",
                                              "To": [], "Subject": ""}}}},
        {"contract": {"Artifacts": {"Email": {"ThreatURL": "http://a", "To": ["v@w"]}}}},
        {"contract": {"Artifacts": {"Endpoint": {"Hostname": "h"}}}},
        {"contract_status": "absent"},
    ]
    assert fsc.collect_indicators(shapes) == {
        "urls": ["http://a", "http://b"], "email_senders": ["x@y"], "email_recipients": ["v@w"]}


def test_no_shapes_lift_nothing():
    assert fsc.collect_indicators(None) == {}


@pytest.mark.parametrize("arg,expected", [
    ("DBotScore, RecordedFuture  GTI", ("DBotScore", "RecordedFuture", "GTI")),
    (["File", 5], ("File", "5")),
    ("", fsc.DEFAULT_INTEL_ROOTS),
    ([], fsc.DEFAULT_INTEL_ROOTS),
    (None, fsc.DEFAULT_INTEL_ROOTS),
])
def test_intel_roots_are_configurable_and_fall_back_to_the_defaults(arg, expected):
    assert fsc.intel_roots(arg) == expected


# ── fetch_contract ───────────────────────────────────────────────────────────

def test_only_the_evidence_keys_of_the_contract_travel(t):
    t.issues["7"] = issue(contract())
    got, err = fsc.fetch_contract(7)
    assert err == "" and set(got) == {"Artifacts", "Product", "lifecycle"}
    assert t.calls == [("getContext", {"id": "7"})]


def test_intel_roots_ride_along_and_empty_ones_are_dropped(t):
    t.issues["7"] = issue(contract(), DBotScore=[{"Score": 3}], File={}, IP="", Whois={"big": 1})
    got, _ = fsc.fetch_contract("7")
    assert got["Intel"] == {"DBotScore": [{"Score": 3}]}


def test_intel_from_the_roots_replaces_an_intel_key_in_the_contract(t):
    t.issues["7"] = issue(dict(contract(), Intel={"old": 1}), WildFire={"Verdict": 1})
    got, _ = fsc.fetch_contract("7", ("WildFire",))
    assert got["Intel"] == {"WildFire": {"Verdict": 1}}


def test_a_contract_intel_key_survives_when_no_root_has_a_value(t):
    t.issues["7"] = issue(dict(contract(), Intel={"old": 1}))
    got, _ = fsc.fetch_contract("7", ("WildFire",))
    assert got["Intel"] == {"old": 1}


@pytest.mark.parametrize("answer,reason", [
    (RuntimeError("boom"), "getContext failed: boom"),
    ([{"Type": 1, "Contents": "not json"}], "unparseable getContext payload"),
    ([{"Type": 1, "Contents": 5}], "unexpected getContext shape"),
    ([], "no SOCFramework contract on this issue"),
    ({"context": {"Other": 1}}, "no SOCFramework contract on this issue"),
    ({"context": {"SOCFramework": {}}}, "no SOCFramework contract on this issue"),
])
def test_why_a_contract_could_not_be_read(t, answer, reason):
    t.issues["7"] = answer
    got, err = fsc.fetch_contract("7")
    assert got is None and err.startswith(reason)


def test_a_bare_dict_result_is_read_too(t):
    t.issues["7"] = [{"context": {"SOCFramework": contract()}}]
    got, _ = fsc.fetch_contract("7")
    assert "Artifacts" in got


# ── main: fetching per shape ─────────────────────────────────────────────────

def test_each_sampled_shape_gets_its_contract_and_its_source(t, monkeypatch):
    t.issues["a1"] = issue(contract())
    ctx = run(t, monkeypatch, [case("1", [{"alert_name": "x", "n": 3, "sample_alert_id": "a1"},
                                          {"alert_name": "y", "n": 1}])])
    b = body(ctx)
    assert b["shapes"][0]["contract_from"] == "a1" and "Artifacts" in b["shapes"][0]["contract"]
    assert "contract" not in b["shapes"][1] and "contract_status" not in b["shapes"][1]
    assert [a["id"] for c, a in t.calls] == ["a1"]
    assert ctx["SOCFramework.Case.Payloads"][0]["ShapeContracts"] == {
        "with_contract": 1, "absent": 0, "unreadable": 0, "shapes": 2, "coverage_pct": 100.0}


def test_candidates_are_tried_in_order_until_one_has_a_contract(t, monkeypatch):
    t.issues["c3"] = issue(contract())
    ctx = run(t, monkeypatch, [case("1", [{"n": 1, "candidate_ids": ["c1", "c2", "c3", "c4"]}])])
    s = body(ctx)["shapes"][0]
    assert s["contract_from"] == "c3" and "candidate_ids" not in s
    assert [a["id"] for c, a in t.calls] == ["c1", "c2", "c3"]


def test_at_most_five_candidates_are_tried_per_shape(t, monkeypatch):
    ctx = run(t, monkeypatch, [case("1", [{"n": 1, "candidate_ids": [f"c{i}" for i in range(9)]}])])
    assert len(t.calls) == 5
    assert body(ctx)["shapes"][0]["contract_status"] == "absent"
    assert "getContext calls: 5" in t.results[-1]["readable_output"]


def test_a_single_candidate_id_is_accepted(t, monkeypatch):
    t.issues["c1"] = issue(contract())
    run(t, monkeypatch, [case("1", [{"n": 1, "candidate_ids": "c1"}])])
    assert [a["id"] for c, a in t.calls] == ["c1"]


def test_no_contract_on_the_issue_is_absent_and_counts_against_coverage(t, monkeypatch):
    t.issues["a1"] = issue(contract())
    ctx = run(t, monkeypatch, [case("1", [{"n": 2, "sample_alert_id": "a1"},
                                          {"n": 1, "sample_alert_id": "a2"}])])
    assert body(ctx)["shapes"][1]["contract_status"] == "absent"
    assert body(ctx)["shape_contract_coverage_pct"] == 50.0
    assert '"kind": "structural"' in t.results[-1]["readable_output"]


def test_no_resolvable_shape_is_zero_coverage(t, monkeypatch):
    ctx = run(t, monkeypatch, [case("1", [{"n": 1}])])
    assert body(ctx)["shape_contract_coverage_pct"] == 0.0


# ── main: deferral ───────────────────────────────────────────────────────────

def test_a_failed_read_defers_the_case(t, monkeypatch):
    t.issues["a1"] = RuntimeError("timeout")
    ctx = run(t, monkeypatch, [case("1", [{"n": 1, "sample_alert_id": "a1"}])])
    assert ctx["SOCFramework.Case.Payloads"] == []
    assert ctx["SOCFramework.Case.Deferred"] == [
        {"case_id": "1", "shapes": 1, "attempt": 1, "reason": "1 contract fetch(es) failed"}]
    assert "No case had full contract coverage this run" in t.results[-1]["readable_output"]
    assert '"kind": "transient"' in t.results[-1]["readable_output"]


def test_after_the_deferral_limit_the_case_is_analysed_without_the_unread_shape(t, monkeypatch):
    t.issues["a1"] = RuntimeError("timeout")
    t.issues["a2"] = issue(contract())
    ctx = run(t, monkeypatch, [case("1", [{"n": 2, "sample_alert_id": "a1"},
                                          {"n": 1, "sample_alert_id": "a2"}], prior=2)])
    b = body(ctx)
    assert b["shapes"][0]["contract_status"] == "fetch_failed"
    assert b["coverage_note"] == "1 shape(s) could not be read after 3 attempt(s). Analysed without them."
    assert b["shape_contract_coverage_pct"] == 100.0
    assert ctx["SOCFramework.Case.Payloads"][0]["ShapeContracts"]["unreadable"] == 1


def test_the_deferral_limit_is_an_argument(t, monkeypatch):
    t.issues["a1"] = RuntimeError("timeout")
    ctx = run(t, monkeypatch, [case("1", [{"n": 1, "sample_alert_id": "a1"}], prior=1)], max_deferrals="1")
    assert len(ctx["SOCFramework.Case.Payloads"]) == 1


# ── main: indicators, budget, notes ──────────────────────────────────────────

def test_indicators_are_attached_at_case_level(t, monkeypatch):
    t.issues["a1"] = issue(contract(Email={"ThreatURL": "http://evil", "From": "a@b"}))
    ctx = run(t, monkeypatch, [case("1", [{"n": 1, "sample_alert_id": "a1"}])])
    assert body(ctx)["indicators"] == {"urls": ["http://evil"], "email_senders": ["a@b"]}


def test_no_indicators_means_no_indicator_key(t, monkeypatch):
    t.issues["a1"] = issue(contract())
    assert "indicators" not in body(run(t, monkeypatch, [case("1", [{"n": 1, "sample_alert_id": "a1"}])]))


def sent(ctx, i=0):
    return ctx["SOCFramework.Case.Payloads"][i]["Payload"]


def test_the_smallest_shapes_are_dropped_to_fit_the_character_budget(t, monkeypatch):
    shapes = [{"alert_name": f"s{i}", "n": 10 - i, "pad": "x" * 200} for i in range(6)]
    ctx = run(t, monkeypatch, [case("1", shapes)], max_payload_chars="900")
    b = body(ctx)
    assert [s["alert_name"] for s in b["shapes"]] == ["s0", "s1"]
    assert b["coverage_note"] == ("4 lowest-occurrence shape(s) dropped to fit the 900 character "
                                  "prompt limit. 2 of 6 carried.")
    assert b["shapes_analysed"] == 2 and b["shapes_in_case"] == 6
    assert len(sent(ctx)) <= 900


def test_the_budget_is_measured_on_the_payload_as_sent(t, monkeypatch):
    """One shape fewer than the limit allows is never dropped, and the payload
    sent, counts and note included, is never over the limit."""
    shapes = [{"alert_name": f"s{i}", "n": 10 - i, "pad": "x" * 200} for i in range(6)]
    for limit in range(700, 1700, 37):
        t.context.clear()
        ctx = run(t, monkeypatch, [case("1", [dict(s) for s in shapes])], max_payload_chars=str(limit))
        b, text = body(ctx), sent(ctx)
        kept = len(b["shapes"])
        assert len(text) <= limit, limit
        if kept < 6:
            bigger = fsc.finish_payload(
                {k: v for k, v in b.items() if k not in ("coverage_note",)},
                shapes[:kept + 1], 6, b["shape_contract_coverage_pct"],
                fsc.budget_note(5 - kept, kept + 1, 6, limit))
            assert len(json.dumps(bigger, separators=(",", ":"))) > limit, limit


def test_the_entry_vector_survives_when_its_shape_is_dropped(t, monkeypatch):
    t.issues["phish"] = issue(contract(Email={"ThreatURL": "http://evil"}))
    shapes = [{"alert_name": "big", "n": 50, "pad": "x" * 300},
              {"alert_name": "phish", "n": 1, "sample_alert_id": "phish"}]
    ctx = run(t, monkeypatch, [case("1", shapes)], max_payload_chars="600")
    b = body(ctx)
    assert [s["alert_name"] for s in b["shapes"]] == ["big"]
    assert b["indicators"] == {"urls": ["http://evil"]}
    assert len(sent(ctx)) <= 600


def test_a_case_over_the_fetch_budget_carries_only_the_budget(t, monkeypatch):
    shapes = [{"alert_name": f"s{i}", "n": 9 - i, "sample_alert_id": f"a{i}"} for i in range(4)]
    ctx = run(t, monkeypatch, [case("1", shapes)], max_fetches_per_case="2")
    b = body(ctx)
    assert len(t.calls) == 2 and [s["alert_name"] for s in b["shapes"]] == ["s0", "s1"]
    assert b["coverage_note"] == "4 shapes in case, 2 within the fetch budget. Highest occurrence counts first."
    assert "candidate_ids" not in json.dumps(b)


def test_both_truncations_are_declared(t, monkeypatch):
    shapes = [{"alert_name": f"s{i}", "n": 9 - i, "pad": "x" * 300, "sample_alert_id": f"a{i}"}
              for i in range(4)]
    ctx = run(t, monkeypatch, [case("1", shapes)], max_fetches_per_case="2", max_payload_chars="700")
    b = body(ctx)
    assert len(b["shapes"]) == 1
    assert b["coverage_note"] == (
        "4 shapes in case, 2 within the fetch budget. Highest occurrence counts first. "
        "1 lowest-occurrence shape(s) dropped to fit the 700 character prompt limit. 1 of 4 carried.")
    assert len(sent(ctx)) <= 700


def test_an_unread_shape_and_a_budget_drop_are_both_declared(t, monkeypatch):
    t.issues["a0"] = RuntimeError("timeout")
    shapes = [{"alert_name": f"s{i}", "n": 9 - i, "pad": "x" * 300, "sample_alert_id": f"a{i}"}
              for i in range(3)]
    b = body(run(t, monkeypatch, [case("1", shapes, prior=2)], max_payload_chars="800"))
    assert b["coverage_note"].startswith("1 shape(s) could not be read after 3 attempt(s). Analysed without them. ")
    assert "dropped to fit the 800 character prompt limit" in b["coverage_note"]


# ── main: input shapes and output ────────────────────────────────────────────

@pytest.mark.parametrize("raw", [
    lambda p: json.dumps([p]),
    lambda p: p,
])
def test_payloads_arrive_as_json_text_or_a_single_object(t, monkeypatch, raw):
    ctx = run(t, monkeypatch, raw(case("1", [{"n": 1}])))
    assert [p["ID"] for p in ctx["SOCFramework.Case.Payloads"]] == ["1"]


def test_unreadable_payloads_mean_no_cases(t, monkeypatch):
    ctx = run(t, monkeypatch, "not json")
    assert ctx["SOCFramework.Case.Payloads"] == [] and ctx["SOCFramework.Case.Deferred"] == []


def test_the_payload_goes_back_as_compact_json_text(t, monkeypatch):
    ctx = run(t, monkeypatch, [case("1", [{"n": 1}], siblings=["2"])])
    p = ctx["SOCFramework.Case.Payloads"][0]
    assert isinstance(p["Payload"], str) and ": " not in p["Payload"]
    assert json.loads(p["Payload"])["siblings"] == ["2"]


def test_a_payload_object_is_read_not_emptied(t, monkeypatch):
    p = {"ID": "1", "Payload": {"case_id": "1", "shapes": [{"n": 1}, {"n": 2}]}}
    assert body(run(t, monkeypatch, [p]))["shapes_in_case"] == 2


def test_misses_listed_in_the_war_room_are_capped_at_twenty(t, monkeypatch):
    shapes = [{"n": 1, "sample_alert_id": f"a{i}"} for i in range(25)]
    run(t, monkeypatch, [case("1", shapes)])
    table = t.results[-1]["readable_output"].split("## Shapes without a contract\n")[1]
    assert len(json.loads(table)) == 20
