"""
SOCEnrichFromList_test.py

Characterization tests: the enrichment engine reads
SOCFrameworkEnrichmentMap_<LIFECYCLE> and, per lane, fires either the built-in
reputation command named by the lane (list form) or the lane's universal
commands through SOCCommandWrapper (object form), only when its source paths
under SOCFramework.* resolve to something. Private addresses never reach the
ip lane. A failed lane is recorded and the rest still run.

The script uses the platform's injected globals (demisto, entryTypes,
CommandResults, ...) without importing them, so the harness puts them in
builtins before import, as the SOCCommandWrapper tests do.

Run: pytest Scripts/SOCEnrichFromList/SOCEnrichFromList_test.py -v
"""
import builtins
import importlib
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)


class Stop(Exception):
    """return_error ends the script on the tenant; here it raises."""


def _get(obj, path):
    for part in str(path).split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


LANES = {
    "ip": ["Artifacts.Network.SourceIP", "Artifacts.Network.DestinationIP"],
    "domain": ["Artifacts.Network.Domain"],
    "file": ["Artifacts.Process.SHA256"],
    "identity": {"actions": ["soc-enrich-user", "soc-enrich-user-manager"],
                 "fire_when": ["Artifacts.Identity.User.UPN"]},
}


class Tenant:
    def __init__(self):
        self.lanes = dict(LANES)
        self.list_reply = None
        self.context = {"SOCFramework": {"Artifacts": {
            "Network": {"SourceIP": ["10.0.0.5", "8.8.8.8"], "DestinationIP": "8.8.8.8", "Domain": ""},
            "Process": {"SHA256": ["  abc  ", "abc", None]},
            "Identity": {"User": {"UPN": "u@x"}},
        }}}
        self.calls = []
        self.results = []
        self.fail = {}

    def execute(self, cmd, args):
        self.calls.append((cmd, args))
        if cmd == "getList":
            if self.list_reply is not None:
                return self.list_reply
            return [{"Type": 1, "Contents": json.dumps({"lanes": self.lanes})}]
        key = args.get("action", cmd)
        if key in self.fail:
            f = self.fail[key]
            if isinstance(f, Exception):
                raise f
            return [{"Type": 4, "Contents": f}]
        return [{"Type": 1, "Contents": "ok"}]


@pytest.fixture
def t(monkeypatch):
    tn = Tenant()
    demisto = types.SimpleNamespace(
        debug=lambda *a: None,
        args=lambda: {},
        context=lambda: tn.context,
        get=_get,
        executeCommand=tn.execute,
        results=lambda r: None,
    )

    def _return_error(msg):
        raise Stop(msg)

    for name, value in {
        "demisto": demisto,
        "entryTypes": {"note": 1, "error": 4},
        "formats": {"json": "json"},
        "CommandResults": lambda **k: k,
        "return_results": tn.results.append,
        "return_error": _return_error,
    }.items():
        monkeypatch.setattr(builtins, name, value, raising=False)
    sys.path.insert(0, HERE)
    sys.modules.pop("SOCEnrichFromList", None)
    tn.mod = importlib.import_module("SOCEnrichFromList")
    tn.demisto = demisto
    return tn


def run(t, **args):
    t.demisto.args = lambda: args
    t.mod.main()
    return t.results[-1]["outputs"]


def fired_commands(t):
    return [(c, a) for c, a in t.calls if c != "getList"]


# ── the list ─────────────────────────────────────────────────────────────────

def test_the_list_is_named_by_the_lifecycle(t):
    run(t, lifecycle="vuln_mgmt")
    assert ("getList", {"listName": "SOCFrameworkEnrichmentMap_VULN_MGMT"}) in t.calls


def test_an_explicit_list_name_wins(t):
    run(t, lifecycle="x", list_name=" MyLanes ")
    assert ("getList", {"listName": "MyLanes"}) in t.calls


@pytest.mark.parametrize("reply,reason", [
    ([], "getList returned no result"),
    ([{"Type": 1, "Contents": None}], "has no contents"),
    ([{"Type": 1, "Contents": "Item not found (8)"}], "not found on tenant"),
    ([{"Type": 1, "Contents": "{bad"}], "is not valid JSON"),
    ([{"Type": 1, "Contents": "[1]"}], "root is not an object"),
    ([{"Type": 1, "Contents": json.dumps({"lanes": {}})}], "has no 'lanes' object"),
])
def test_an_unusable_list_stops_with_the_reason(t, reply, reason):
    t.list_reply = reply
    with pytest.raises(Stop, match=reason):
        run(t)


# ── paths ────────────────────────────────────────────────────────────────────

def test_paths_resolve_under_socframework_flattened_and_deduplicated(t):
    ctx = {"SOCFramework": {"A": ["x", " y ", "x", "", None, {}], "B": "y", "C": 5}}
    assert t.mod.resolve_paths(["A", "SOCFramework.B", "C", "Missing"], ctx) == ["x", "y", "5"]


@pytest.mark.parametrize("values,kept", [
    (["10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "224.0.0.1"], []),
    (["8.8.8.8", "10.0.0.5", "2001:4860:4860::8888"], ["8.8.8.8", "2001:4860:4860::8888"]),
    (["not-an-ip", "fe80::1"], ["not-an-ip"]),
])
def test_only_public_addresses_go_to_reputation(t, values, kept):
    assert t.mod.public_ips_only(values) == kept


# ── lanes ────────────────────────────────────────────────────────────────────

def test_each_lane_fires_its_command_with_the_resolved_values(t):
    out = run(t)
    assert ("ip", {"ip": "8.8.8.8"}) in fired_commands(t)
    assert ("file", {"file": "abc"}) in fired_commands(t)
    assert [r["lane"] for r in out["fired"]] == ["ip", "file", "identity"]
    assert out["lanes_fired"] == 3 and out["lanes_errored"] == 0


def test_an_override_lane_runs_its_actions_in_order_through_the_wrapper(t):
    run(t)
    wrapper = [a for c, a in t.calls if c == "SOCCommandWrapper"]
    assert wrapper == [
        {"action": "soc-enrich-user", "Action_Actor": "automation", "Phase": "Enrichment", "tags": "Enrichment"},
        {"action": "soc-enrich-user-manager", "Action_Actor": "automation", "Phase": "Enrichment",
         "tags": "Enrichment"},
    ]


def test_lanes_with_nothing_to_look_up_are_skipped_with_the_reason(t):
    t.context["SOCFramework"]["Artifacts"]["Network"] = {"SourceIP": "10.0.0.5"}
    t.lanes.update({"url": [], "odd": "text", "noop": {"fire_when": ["Artifacts.X"]}})
    out = run(t)
    reasons = {s["lane"]: s["reason"] for s in out["skipped_empty"]}
    assert reasons == {
        "ip": "no public addresses among 1 resolved",
        "domain": "all source paths empty",
        "url": "no source_paths in list",
        "odd": "unrecognized lane shape",
        "noop": "no actions in list",
    }
    assert not [c for c, a in fired_commands(t) if c in ("ip", "domain", "url")]


def test_an_override_lane_with_no_identity_costs_nothing(t):
    del t.context["SOCFramework"]["Artifacts"]["Identity"]
    run(t)
    assert not [c for c, a in t.calls if c == "SOCCommandWrapper"]


def test_a_failed_lane_is_recorded_and_the_others_still_run(t):
    t.fail["ip"] = "quota exceeded"
    t.fail["file"] = RuntimeError("timeout")
    out = run(t)
    errs = {e["lane"]: e["message"] for e in out["errored"]}
    assert errs == {"ip": "quota exceeded", "file": "timeout"}
    assert [r["lane"] for r in out["fired"]] == ["identity"]


def test_one_failed_action_marks_the_lane_but_the_next_action_still_runs(t):
    t.fail["soc-enrich-user-manager"] = "no manager integration"
    out = run(t)
    lane = [e for e in out["errored"] if e["lane"] == "identity"][0]
    assert lane["actions"] == ["soc-enrich-user"]
    assert lane["message"] == "1 ran, 1 failed: soc-enrich-user-manager (no manager integration)"


def test_the_summary_is_written_under_enrich_from_list(t):
    run(t)
    res = t.results[-1]
    assert res["outputs_prefix"] == "SOCFramework.EnrichFromList"
    assert "- lanes fired: **3**  (ip, file, identity)" in res["readable_output"]
    assert "- list: `SOCFrameworkEnrichmentMap_NIST_IR`" in res["readable_output"]
