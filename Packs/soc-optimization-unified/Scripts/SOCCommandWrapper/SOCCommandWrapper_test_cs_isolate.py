"""
SOCCommandWrapper_test_cs_isolate.py

CrowdStrike isolate / lift, against the lists as they ship (27 Oct 2026):

- Both rows say shadow per actor and every actor ships shadowed, so nothing
  isolates until a customer turns one actor live in SOCFWTenantConfig
  (!SOCFWConfig command=shadow ... apply=yes).
- Turning the analyst live does not turn automation, ai or issue_emergency live.
- The CrowdStrike instance comes from SOCFWTenantConfig "CrowdStrike Falcon".using
  (set with !SOCFWConfig command=set), which covers buttons and playbooks. A CLI
  using= overrides it for one call. Unset, no using is sent.

Run: pytest Scripts/SOCCommandWrapper/SOCCommandWrapper_test_cs_isolate.py -v
"""

import copy
import json
import os

import pytest

from SOCCommandWrapper_test import load_script

_LISTS = os.path.join(os.path.dirname(__file__), "..", "..", "Lists")
ACTIONS = json.load(open(os.path.join(
    _LISTS, "SOCFrameworkActions_V3", "SOCFrameworkActions_V3_data.json")))
PRODUCT_MAP = json.load(open(os.path.join(
    _LISTS, "SOCProductCategoryMap_V3", "SOCProductCategoryMap_V3_data.json")))
CLASS_MAP = json.load(open(os.path.join(
    _LISTS, "SOCActionClassMap_V3", "SOCActionClassMap_V3_data.json")))

CS = PRODUCT_MAP["ds_crowdstrike_falcon_event"]
AGENT = "agent-0123456789abcdef"
COMMANDS = {"soc-isolate-endpoint": "cs-falcon-contain-host",
            "soc-deisolate-endpoint": "cs-falcon-lift-host-containment"}
ANALYST_LIVE = {"shadow": {"soc-isolate-endpoint": {"analyst": False},
                           "soc-deisolate-endpoint": {"analyst": False}}}


def _run(action, actor="analyst", tenant=None, using=None):
    row = copy.deepcopy(ACTIONS[action])          # the shipped row, unmodified
    script, demisto = load_script()
    demisto._args = {"action": action, "list_name": "SOCFrameworkActions_V3",
                     "output_key": "UCTest.Executions", "Action_Actor": actor}
    if using is not None:
        demisto._args["using"] = using
    demisto._context = {"SOCFramework": {
        "Product": {"key": "ds_crowdstrike_falcon_event", "category": CS["category"],
                    "response": CS.get("response"), "responses": CS.get("responses")},
        "Artifacts": {"Endpoint": {"AgentID": AGENT}},
        "RunID": "run-1"}}

    def _route(args):
        name = (args or {}).get("listName")
        if name == "SOCFrameworkActions_V3":
            return [{"Contents": json.dumps({action: row})}]
        if name == "SOCActionClassMap_V3":
            return [{"Contents": json.dumps(CLASS_MAP)}]
        if name == "SOCFWTenantConfig" and tenant is not None:
            return [{"Contents": json.dumps(tenant)}]
        return [{"Type": 4, "Contents": f" - Item not found (8) on list [{name}] (2609)"}]

    demisto._command_responses = {
        "getList": _route,
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        COMMANDS[action]: [{"Type": 1, "Contents": "ok"}],
        "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }
    script.main()
    return demisto


def _calls(demisto, action):
    return [a for c, a in demisto._commands if c == COMMANDS[action]]


def _rows(demisto):
    out = []
    for c, a in demisto._commands:
        if c == "socfw-post-to-dataset":
            r = json.loads(a["JSON"])
            out += r if isinstance(r, list) else [r]
    return out


@pytest.mark.parametrize("action", list(COMMANDS))
def test_shipped_row_says_shadow_per_actor_and_every_actor_is_shadowed(action):
    row = ACTIONS[action]
    assert "shadow_mode" not in row
    assert row["shadow_mode_by_actor"] == {"analyst": True, "ai": True,
                                           "automation": True, "issue_emergency": True}
    assert row["responses"]["CrowdStrike Falcon"]["inline_args"]["using"] == ""


@pytest.mark.parametrize("action", list(COMMANDS))
@pytest.mark.parametrize("actor", ["analyst", "ai", "automation", "issue_emergency", ""])
def test_as_shipped_nothing_isolates(action, actor):
    demisto = _run(action, actor=actor)
    assert _calls(demisto, action) == []
    assert any(r.get("execution_mode") == "shadow" for r in _rows(demisto))


@pytest.mark.parametrize("action", list(COMMANDS))
def test_analyst_live_dispatches_with_agent_id_and_no_using(action):
    demisto = _run(action, tenant=ANALYST_LIVE)
    calls = _calls(demisto, action)
    assert len(calls) == 1
    assert calls[0]["ids"] == AGENT
    assert "using" not in calls[0]


@pytest.mark.parametrize("action", list(COMMANDS))
@pytest.mark.parametrize("actor", ["ai", "automation", "issue_emergency"])
def test_analyst_live_leaves_other_actors_shadowed(action, actor):
    demisto = _run(action, actor=actor, tenant=ANALYST_LIVE)
    assert _calls(demisto, action) == []


@pytest.mark.parametrize("action", list(COMMANDS))
def test_tenant_using_pins_the_instance(action):
    tenant = dict(ANALYST_LIVE, **{"CrowdStrike Falcon": {"using": "CrowdStrike_Prod"}})
    calls = _calls(_run(action, tenant=tenant), action)
    assert len(calls) == 1 and calls[0]["using"] == "CrowdStrike_Prod" and calls[0]["ids"] == AGENT


@pytest.mark.parametrize("action", list(COMMANDS))
def test_cli_using_overrides_tenant_using(action):
    tenant = dict(ANALYST_LIVE, **{"CrowdStrike Falcon": {"using": "CrowdStrike_Prod"}})
    calls = _calls(_run(action, tenant=tenant, using="CrowdStrike_Dev"), action)
    assert len(calls) == 1 and calls[0]["using"] == "CrowdStrike_Dev"


@pytest.mark.parametrize("action", list(COMMANDS))
def test_cli_using_without_tenant_using(action):
    calls = _calls(_run(action, tenant=ANALYST_LIVE, using="CrowdStrike_Dev"), action)
    assert len(calls) == 1 and calls[0]["using"] == "CrowdStrike_Dev"


def test_shadow_run_still_logs_the_instance_it_would_use():
    tenant = {"CrowdStrike Falcon": {"using": "CrowdStrike_Prod"}}
    demisto = _run("soc-isolate-endpoint", tenant=tenant)
    assert _calls(demisto, "soc-isolate-endpoint") == []
    assert "CrowdStrike_Prod" in json.dumps(demisto._commands + [str(r) for r in demisto._results])


def _executing_logs(demisto):
    out = []
    for c, a in demisto._commands:
        blob = json.dumps(a)
        if "Executing Command" in blob:
            out.append(blob)
    return out + [str(r) for r in demisto._results if "Executing Command" in str(r)]


def test_executing_log_shows_the_instance_actually_used():
    tenant = dict(ANALYST_LIVE, **{"CrowdStrike Falcon": {"using": "CrowdStrike_Prod"}})
    demisto = _run("soc-isolate-endpoint", tenant=tenant, using="CrowdStrike_Dev")
    logs = _executing_logs(demisto)
    assert logs, "no Executing Command entry"
    assert all("CrowdStrike_Dev" in x and "CrowdStrike_Prod" not in x for x in logs)
