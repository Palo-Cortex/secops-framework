"""
SOCCommandWrapper_test_target.py

target= on the Universal Command: an analyst names what to act on from the War
Room CLI, replacing the issue's artifact for the action's target_arg. Against the
shipped soc-block-domain row (ThreatStop ioc_domain, Zscaler url, fan-out).

Run: pytest Scripts/SOCCommandWrapper/SOCCommandWrapper_test_target.py -v
"""

import copy
import json
import os

import pytest

from SOCCommandWrapper_test import load_script

_LISTS = os.path.join(os.path.dirname(__file__), "..", "..", "Lists")
ACTIONS = json.load(open(os.path.join(_LISTS, "SOCFrameworkActions_V3", "SOCFrameworkActions_V3_data.json")))
TENANT = {"ThreatStopv2": {"list_id": "L-1"}, "Zscaler": {"category-id": "CUSTOM_99"}}
ANALYST_LIVE = {"shadow": {"soc-block-domain": {"analyst": False}}}


CS = {"key": "ds_crowdstrike_falcon_event", "category": "Endpoint", "response": "CrowdStrike Falcon"}


def _run(target=None, issue_domains=None, tenant=None, actor="analyst", action="soc-block-domain",
         product=CS):
    script, demisto = load_script()
    demisto._args = {"action": action, "list_name": "SOCFrameworkActions_V3",
                     "output_key": "UCTest.Executions", "Action_Actor": actor}
    if target is not None:
        demisto._args["target"] = target
    art = {"Network": {"DNS": {"Query": issue_domains}}} if issue_domains is not None else {}
    demisto._context = {"SOCFramework": {"Artifacts": art, "RunID": "run-1",
                                         "Product": product}}
    cfg = dict(TENANT, **(tenant or {}))

    def _route(args):
        name = (args or {}).get("listName")
        if name == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps({action: copy.deepcopy(ACTIONS[action])})}]
        if name == "SOCFWTenantConfig":
            return [{"Contents": json.dumps(cfg)}]
        return [{"Type": 4, "Contents": f" - Item not found (8) on list [{name}] (2609)"}]

    demisto._command_responses = {
        "getList": _route,
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "threatstopv2-update-domain-list": [{"Type": 1, "Contents": "ok"}],
        "zscaler-category-add-url": [{"Type": 1, "Contents": "ok"}],
        "cs-falcon-contain-host": [{"Type": 1, "Contents": "ok"}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }
    script.main()
    return demisto


def _calls(d, name):
    return [a for c, a in d._commands if c == name]


def _rows(d):
    out = []
    for a in _calls(d, "socfw-post-to-dataset"):
        r = json.loads(a["JSON"])
        out += r if isinstance(r, list) else [r]
    return out


def test_target_blocks_a_domain_on_an_issue_that_has_none():
    d = _run(target="bad.example", tenant=ANALYST_LIVE)
    ts, zs = _calls(d, "threatstopv2-update-domain-list"), _calls(d, "zscaler-category-add-url")
    assert [c["ioc_domain"] for c in ts] == ["bad.example"] and ts[0]["list_id"] == "L-1"
    assert [c["url"] for c in zs] == ["bad.example"] and zs[0]["category-id"] == "CUSTOM_99"


def test_target_replaces_the_issue_domains():
    d = _run(target="bad.example", issue_domains=["login.microsoftonline.com", "cdn.example"],
             tenant=ANALYST_LIVE)
    assert [c["ioc_domain"] for c in _calls(d, "threatstopv2-update-domain-list")] == ["bad.example"]
    assert [c["url"] for c in _calls(d, "zscaler-category-add-url")] == ["bad.example"]


def test_several_targets_one_call_each_blanks_and_repeats_dropped():
    d = _run(target=" a.example, b.example,,a.example ", tenant=ANALYST_LIVE)
    assert [c["ioc_domain"] for c in _calls(d, "threatstopv2-update-domain-list")] == ["a.example", "b.example"]
    assert [c["url"] for c in _calls(d, "zscaler-category-add-url")] == ["a.example", "b.example"]


def test_target_as_a_list_from_a_playbook():
    d = _run(target=["a.example", "b.example"], tenant=ANALYST_LIVE)
    assert len(_calls(d, "zscaler-category-add-url")) == 2


def test_target_is_still_shadowed_by_default():
    d = _run(target="bad.example")
    assert _calls(d, "threatstopv2-update-domain-list") == []
    assert _calls(d, "zscaler-category-add-url") == []
    assert any(r.get("execution_mode") == "shadow" for r in _rows(d))


@pytest.mark.parametrize("actor", ["automation", "ai", "issue_emergency"])
def test_target_does_not_bypass_other_actors_shadow(actor):
    d = _run(target="bad.example", tenant=ANALYST_LIVE, actor=actor)
    assert _calls(d, "zscaler-category-add-url") == []


def test_target_is_recorded_on_the_dataset_rows():
    d = _run(target="bad.example", tenant=ANALYST_LIVE)
    targets = {r.get("action_target") for r in _rows(d) if r.get("event_type") == "command"}
    assert targets == {"bad.example"}


def test_without_target_the_issue_domains_still_drive_it():
    d = _run(issue_domains=["evil.example"], tenant=ANALYST_LIVE)
    assert [c["url"] for c in _calls(d, "zscaler-category-add-url")] == ["evil.example"]


def test_blank_target_is_ignored():
    d = _run(target=" , ", issue_domains=["evil.example"], tenant=ANALYST_LIVE)
    assert [c["url"] for c in _calls(d, "zscaler-category-add-url")] == ["evil.example"]


def test_action_without_a_target_refuses_target():
    with pytest.raises(Exception, match="takes no target"):
        _run(target="host-1", action="soc-isolate-endpoint")


def test_refusal_does_not_depend_on_the_source():
    # Live on a Prisma Cloud issue the no-vendor skip used to win, so target was
    # silently ignored. The refusal reads the action, not the routing.
    with pytest.raises(Exception, match="takes no target"):
        _run(target="host-1", action="soc-isolate-endpoint",
             product={"key": "ds_prisma_cloud", "category": "Workload"})
