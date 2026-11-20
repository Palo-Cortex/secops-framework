"""
SOCFWDisplayAlertDetail_test.py

Characterization tests: what fired, drawn from SOCFramework.Artifacts.* in the
issue layout. Only groups with data are drawn; nothing at all means the alert's
source has no category.

Run: pytest Scripts/SOCFWDisplayAlertDetail/SOCFWDisplayAlertDetail_test.py -v
"""
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)

demisto = types.ModuleType("demistomock")
sys.modules["demistomock"] = demisto
csp = types.ModuleType("CommonServerPython")
csp.formats = {"html": "html"}
csp.entryTypes = {"note": 1}
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, HERE)
import SOCFWDisplayAlertDetail as dad  # noqa: E402


def _get(obj, path):
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


def render(monkeypatch, artifacts):
    out = []
    ctx = {"SOCFramework": {"Artifacts": artifacts}} if artifacts is not None else {}
    monkeypatch.setattr(demisto, "context", lambda: ctx, raising=False)
    monkeypatch.setattr(demisto, "get", _get, raising=False)
    monkeypatch.setattr(demisto, "results", out.append, raising=False)
    dad.main()
    assert out[-1]["ContentsFormat"] == "html"
    return out[-1]["Contents"]


ENDPOINT = {"Source": {"Action": "blocked", "Module": "Behavioral"},
            "MITRE": {"Tactic": "Execution", "TechniqueID": "T1204"},
            "Process": {"Name": "winword.exe", "PID": 4012, "CommandLine": "winword.exe /q doc.docm",
                        "Parent": {"Name": "explorer.exe"}}}


def test_only_the_groups_with_data_are_drawn(monkeypatch):
    html = render(monkeypatch, ENDPOINT)
    for title in ("Detection", "MITRE", "Process"):
        assert f">{title}</div>" in html
    for title in ("Network", "Email", "Target file"):
        assert f">{title}</div>" not in html
    assert "winword.exe /q doc.docm" in html and ">4012</span>" in html and "explorer.exe" in html


def test_list_values_are_joined(monkeypatch):
    html = render(monkeypatch, {"Email": {"To": ["a@x.com", "", "b@x.com"], "Subject": "hi"}})
    assert "a@x.com, b@x.com" in html and ">Email</div>" in html


@pytest.mark.parametrize("artifacts", [None, {}, {"Process": {"Name": "", "PID": None}, "Email": {"To": []}}])
def test_no_contract_points_at_the_category_map(monkeypatch, artifacts):
    html = render(monkeypatch, artifacts)
    assert "No normalized contract for this alert" in html and "SOCProductCategoryMap_V3" in html


def test_attacker_text_in_the_artifacts_is_escaped(monkeypatch):
    html = render(monkeypatch, {"Email": {"Subject": "Invoice <b>due</b> & overdue"}})
    assert "Invoice &lt;b&gt;due&lt;/b&gt; &amp; overdue" in html
