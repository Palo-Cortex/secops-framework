"""
test_panel_endpoint_status.py

The Identity & Device panel (SOCFWDisplayIdentityDevice, soc-framework-nist-ir-ai)
reads the endpoint's containment state from the wrapper's own record of the
soc-enrich-endpoint call - the entry whose Contents carries success and status -
and nothing else. Before, it took the first entry with any status field, which
on a real run is never the vendor's state, so it always showed STATUS UNKNOWN.

Run: pytest tools/test_panel_endpoint_status.py -v
"""
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)
SCRIPT = os.path.join(HERE, "..", "Packs", "soc-framework-nist-ir-ai", "Scripts", "SOCFWDisplayIdentityDevice")

mock = types.ModuleType("demistomock")
mock.debug = lambda *a, **k: None


def _get(data, path, default=None):
    cur = data
    for part in str(path).split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return default
    return default if cur is None else cur


mock.get = _get
sys.modules["demistomock"] = mock
csp = types.ModuleType("CommonServerPython")
csp.is_error = lambda res: any(isinstance(e, dict) and e.get("Type") == 4 for e in (res or []))
sys.modules["CommonServerPython"] = csp
sys.path.insert(0, SCRIPT)
import SOCFWDisplayIdentityDevice as panel  # noqa: E402

panel.is_error = csp.is_error
CTX = {"SOCFramework": {"Artifacts": {"Endpoint": {"AgentID": "aid-1"}}}}


def _entries(status=None, success=True):
    """What the wrapper returns for soc-enrich-endpoint, in order."""
    resolved = {"Type": 1, "Contents": {"action": "soc-enrich-endpoint", "shadow_mode": False},
                "HumanReadable": "### SOC Framework - Universal Command Resolved"}
    executing = {"Type": 1, "Contents": {"command": "cs-falcon-search-device", "args": {}}}
    record = {"action": "soc-enrich-endpoint", "vendor": "CrowdStrike Falcon", "success": success,
              "shadow_mode": False}
    if status is not None:
        record.update(status=status, status_raw=status)
    raw = {"Type": 1, "Contents": [{"device_id": "aid-1", "status": "contained"}]}
    return [resolved, executing, {"Type": 1, "Contents": record}, raw]


def _render(entries):
    mock.executeCommand = lambda cmd, args: entries
    return panel._endpoint_status(CTX)


@pytest.mark.parametrize("status, label", [("contained", "ISOLATED"), ("containment_pending", "ISOLATION PENDING"),
                                           ("normal", "NORMAL"), ("unknown", "STATUS UNKNOWN")])
def test_the_panel_shows_the_wrappers_status(status, label):
    assert label in _render(_entries(status))


def test_no_status_on_the_record_reads_unknown_not_another_entrys_field():
    """The raw vendor entry says contained; only the wrapper's mapped value counts."""
    assert "STATUS UNKNOWN" in _render(_entries(None))


def test_a_dataset_row_status_is_never_read():
    entries = [{"Type": 1, "Contents": {"status": "In Progress", "incident_id": "1"}}] + _entries("normal")
    assert "NORMAL" in _render(entries)


def test_a_failed_call_reads_unknown():
    assert "STATUS UNKNOWN" in _render(_entries("contained", success=False))


def test_an_error_reads_unknown():
    assert "STATUS UNKNOWN" in _render([{"Type": 4, "Contents": "boom"}])


def test_the_render_is_a_layout_call():
    seen = {}
    mock.executeCommand = lambda cmd, args: seen.update(args) or _entries("normal")
    panel._endpoint_status(CTX)
    assert seen["Action_Actor"] == "layout" and seen["action"] == "soc-enrich-endpoint"
