"""
SOCFWDisplayIdentityDevice_test.py

Characterization tests: the who-and-where panel. Contract values first, then
vendor output found through SOCFrameworkProfileMap_NIST_IR (labelled with its
namespace); endpoint containment read live through the Universal Command as
the layout actor; identity looked up at render without touching the contract.

Run: pytest Scripts/SOCFWDisplayIdentityDevice/SOCFWDisplayIdentityDevice_test.py -v
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
csp.formats = {"html": "html"}
csp.entryTypes = {"note": 1, "error": 4}
csp.is_error = lambda res: any(isinstance(e, dict) and e.get("Type") == 4 for e in (res or []))
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWDisplayIdentityDevice as did  # noqa: E402


def _get(obj, path):
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


class Tenant:
    def __init__(self, ctx, status="contained", profile=None):
        self.ctx, self.status, self.calls = ctx, status, []
        self.profile = {"fields": profile or {}}
        self.wrapper_error = False

    def execute(self, cmd, args):
        self.calls.append((cmd, args))
        if cmd == "getList":
            return [{"Contents": json.dumps(self.profile)}]
        if cmd == "SOCCommandWrapper" and args["action"] == "soc-enrich-endpoint":
            if self.wrapper_error:
                return [{"Type": 4, "Contents": "boom"}]
            return [{"Contents": {"status": "issue status, not this"}},
                    {"Contents": json.dumps({"success": True, "status": self.status})}]
        return [{"Contents": "ok"}]


def render(monkeypatch, tn):
    out = []
    monkeypatch.setattr(demisto, "context", lambda: tn.ctx, raising=False)
    monkeypatch.setattr(demisto, "get", _get, raising=False)
    monkeypatch.setattr(demisto, "dt", lambda c, p: _get(c, p.replace("[0]", "")), raising=False)
    monkeypatch.setattr(demisto, "debug", lambda *a: None, raising=False)
    monkeypatch.setattr(demisto, "executeCommand", tn.execute, raising=False)
    monkeypatch.setattr(demisto, "results", out.append, raising=False)
    did.main()
    return out[-1]["Contents"]


def art(**groups):
    return {"SOCFramework": {"Artifacts": groups}}


ENDPOINT = art(Endpoint={"Hostname": "host-1", "AgentID": "a1", "OS": "Windows"})


@pytest.mark.parametrize("raw,label", [
    ("contained", "ISOLATED"), ("Isolated", "ISOLATED"), ("pending isolation", "ISOLATION PENDING"),
    ("lift_containment_approved", "ISOLATION PENDING"), ("Not Isolated", "NORMAL"),
    ("something new", "STATUS UNKNOWN"), ("", "STATUS UNKNOWN"),
])
def test_endpoint_containment_is_read_live_and_mapped(monkeypatch, raw, label):
    html = render(monkeypatch, Tenant(ENDPOINT, status=raw))
    assert f">{label}</span>" in html and "host-1" in html


def test_the_status_lookup_runs_as_the_layout_actor(monkeypatch):
    tn = Tenant(ENDPOINT)
    render(monkeypatch, tn)
    calls = [a for c, a in tn.calls if c == "SOCCommandWrapper"]
    assert [a["action"] for a in calls] == ["soc-enrich-user", "soc-enrich-user-manager", "soc-enrich-endpoint"]
    assert all(a["Action_Actor"] == "layout" for a in calls)


def test_a_failed_status_lookup_reads_unknown_not_normal(monkeypatch):
    tn = Tenant(ENDPOINT)
    tn.wrapper_error = True
    assert ">STATUS UNKNOWN</span>" in render(monkeypatch, tn)


def test_no_endpoint_means_no_status_lookup(monkeypatch):
    tn = Tenant(art(Identity={"User": {"Name": "bob"}}))
    html = render(monkeypatch, tn)
    assert not any(a.get("action") == "soc-enrich-endpoint" for c, a in tn.calls if c == "SOCCommandWrapper")
    assert ">User</div>" in html and ">Endpoint" not in html


def test_vendor_output_fills_a_gap_and_says_where_it_came_from(monkeypatch):
    ctx = art(Identity={"User": {"Name": "bob"}})
    ctx["MSGraphUser"] = {"JobTitle": "Engineer"}
    tn = Tenant(ctx, profile={"Identity.User.JobTitle": ["Missing.Path[0]", "MSGraphUser.JobTitle"]})
    html = render(monkeypatch, tn)
    assert ">Engineer</span>" in html and ">MSGraphUser</span>" in html


def test_the_contract_wins_over_vendor_output(monkeypatch):
    ctx = art(Identity={"User": {"Name": "bob", "JobTitle": "Analyst"}})
    ctx["MSGraphUser"] = {"JobTitle": "Engineer"}
    html = render(monkeypatch, Tenant(ctx, profile={"Identity.User.JobTitle": ["MSGraphUser.JobTitle"]}))
    assert "Analyst" in html and "Engineer" not in html


def test_a_vendor_path_the_server_rejects_does_not_take_the_panel_down(monkeypatch):
    ctx = art(Identity={"User": {"Name": "bob"}})
    tn = Tenant(ctx, profile={"Identity.User.JobTitle": ["Vendor.Users[0].Title"]})
    monkeypatch.setattr(demisto, "dt", lambda c, p: (_ for _ in ()).throw(RuntimeError("HTTP 400")), raising=False)
    out = []
    monkeypatch.setattr(demisto, "context", lambda: tn.ctx, raising=False)
    monkeypatch.setattr(demisto, "get", _get, raising=False)
    monkeypatch.setattr(demisto, "debug", lambda *a: None, raising=False)
    monkeypatch.setattr(demisto, "executeCommand", tn.execute, raising=False)
    monkeypatch.setattr(demisto, "results", out.append, raising=False)
    did.main()
    assert "bob" in out[-1]["Contents"]


def test_nothing_resolved_says_so(monkeypatch):
    assert "No identity or device context resolved" in render(monkeypatch, Tenant({}))


def test_attacker_text_is_escaped(monkeypatch):
    html = render(monkeypatch, Tenant(art(Identity={"Source": {"UserAgent": "<img src=x> & co"}})))
    assert "&lt;img src=x&gt; &amp; co" in html
