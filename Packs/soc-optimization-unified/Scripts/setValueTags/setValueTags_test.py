"""
setValueTags_test.py

setValueTags writes an action's value to SOCFWTenantConfig ("value" section),
never to SOCActionTimeMap_V3 — the platform refuses script writes to that pack
list, so the fake here refuses them too. The value it reports is the value
SOCCommandWrapper records (resolve_action_value), checked against the wrapper
itself.

Run: pytest Scripts/setValueTags/setValueTags_test.py -v
"""

import importlib
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)
PACK = os.path.dirname(os.path.dirname(HERE))
SHIPPED = os.path.join(PACK, "Lists", "SOCActionTimeMap_V3", "SOCActionTimeMap_V3_data.json")
TENANT = "SOCFWTenantConfig"


class Results:
    def __init__(self, readable_output=None, outputs_prefix=None, outputs=None, **kw):
        self.readable_output, self.outputs_prefix, self.outputs = readable_output, outputs_prefix, outputs


def shipped():
    return {"id": "SOCActionTimeMap_V3", "name": "SOCActionTimeMap_V3", "version": 1, "description": "d",
            "soc-isolate-endpoint": {"time_minutes": 15, "action_category": "containment"},
            "soc-enrich-user": {"time_minutes": 3, "action_category": "enrichment"}}


class Fake:
    """Lists on a tenant. SOCActionTimeMap_V3 is a system list: writes to it are refused."""

    def __init__(self, tenant=None, time_map=None, actions=("soc-isolate-endpoint", "soc-enrich-user", "soc-star-case"),
                 core_api=True):
        self.lists = {"SOCActionTimeMap_V3": shipped() if time_map is None else time_map}
        if tenant is not None:
            self.lists[TENANT] = tenant
        if actions is not None:
            self.lists["SOCFrameworkActions_V3"] = {a: {"shadow_mode": True} for a in actions}
        self.core_api = core_api
        self.writes = []

    def raw(self, command, args):
        if command == "getList":
            name = args["listName"]
            if name not in self.lists:
                return [{"Type": 4, "Contents": f" - Item not found (8) on list [{name}] (2609)"}]
            v = self.lists[name]
            return [{"Type": 1, "Contents": v if isinstance(v, str) else json.dumps(v)}]
        if command == "setList":
            name = args["listName"]
            if name == "SOCActionTimeMap_V3":
                return [{"Type": 4, "Contents": "Item is system and cannot be modified (100001)"}]
            self.writes.append(name)
            self.lists[name] = json.loads(args["listData"])
            return [{"Type": 1, "Contents": "Done"}]
        if command == "core-api-post" and args["uri"].endswith("lists/save"):
            if not self.core_api:
                return [{"Type": 4, "Contents": "Unsupported Command : core-api-post"}]
            body = json.loads(args["body"])
            assert body["type"] == "json"
            self.writes.append(body["name"])
            self.lists[body["name"]] = json.loads(body["data"])
            return [{"Type": 1, "Contents": {"response": {}}}]
        raise AssertionError(f"unexpected command {command}")


def load(fake):
    demisto = types.ModuleType("demistomock")
    demisto.args = lambda: {}
    demisto.executeCommand = fake.raw
    demisto.debug = lambda *a, **k: None
    csp = types.ModuleType("CommonServerPython")
    csp.CommandResults = Results
    csp.return_results = lambda r: None
    csp.return_error = lambda m: (_ for _ in ()).throw(SystemExit(m))
    csp.tableToMarkdown = lambda title, rows, headers=None: f"### {title}\n" + "\n".join(
        " | ".join(str(r[h]) for h in headers) for r in rows)
    sys.modules["demistomock"], sys.modules["CommonServerPython"] = demisto, csp
    sys.path.insert(0, HERE)
    module = importlib.import_module("setValueTags")
    importlib.reload(module)
    return module


def run(fake, **args):
    return load(fake).main_logic(args)


def refused(fake, **args):
    module = load(fake)
    before = json.dumps(fake.lists, sort_keys=True)
    with pytest.raises(module.ValueTagError) as e:
        module.main_logic(args)
    assert json.dumps(fake.lists, sort_keys=True) == before, "a refused request changed a list"
    return str(e.value)


def by_action(rows):
    return {r["Action"]: r for r in rows}


# ── lists ────────────────────────────────────────────────────────────────────

def test_list_all_shows_shipped_values_and_names_actions_with_none():
    r = run(Fake(), action="list_all")
    rows = by_action(r.outputs)
    assert rows["soc-isolate-endpoint"] == {"Action": "soc-isolate-endpoint", "Minutes": 15,
                                            "Category": "containment", "From": "shipped"}
    assert "1 actions have no value and record 0 minutes" in r.readable_output and "`soc-star-case`" in r.readable_output


def test_list_all_shows_tenant_values_over_shipped():
    f = Fake(tenant={"value": {"soc-isolate-endpoint": {"time_minutes": 25}}})
    rows = by_action(run(f, action="list_all").outputs)
    assert rows["soc-isolate-endpoint"]["Minutes"] == 25 and rows["soc-isolate-endpoint"]["From"] == "tenant"
    assert rows["soc-isolate-endpoint"]["Category"] == "containment"


def test_list_all_without_the_actions_list_still_lists():
    r = run(Fake(actions=None), action="list_all")
    assert len(r.outputs) == 2 and "no value" not in r.readable_output


def test_list_by_type_and_by_name():
    assert [x["Action"] for x in run(Fake(), action="list_by_type", category="containment").outputs] == [
        "soc-isolate-endpoint"]
    assert [x["Action"] for x in run(Fake(), action="list_by_tag_or_name", tag="ENRICH").outputs] == [
        "soc-enrich-user"]


# ── writes go to SOCFWTenantConfig only ──────────────────────────────────────

def test_add_writes_the_tenant_config_never_the_pack_list():
    f = Fake(tenant={"Zscaler": {"using": "z"}})
    run(f, action="add", tag="soc-star-case", time="5", category="triage")
    assert f.writes == [TENANT]
    assert f.lists[TENANT] == {"Zscaler": {"using": "z"},
                               "value": {"soc-star-case": {"time_minutes": 5, "action_category": "triage"}}}
    assert f.lists["SOCActionTimeMap_V3"] == shipped()


def test_add_creates_the_tenant_config_when_missing():
    f = Fake()
    run(f, action="add", tag="soc-star-case", time="5", category="triage")
    assert f.lists[TENANT] == {"value": {"soc-star-case": {"time_minutes": 5, "action_category": "triage"}}}


def test_creating_the_tenant_config_without_core_api_is_reported():
    msg = refused(Fake(core_api=False), action="add", tag="soc-star-case", time="5", category="triage")
    assert "could not write SOCFWTenantConfig" in msg and "Core REST API" in msg


def test_add_of_an_action_the_framework_does_not_know_says_so():
    r = run(Fake(), action="add", tag="soc-made-up", time="5", category="triage")
    assert "not in SOCFrameworkActions_V3" in r.readable_output


def test_update_of_a_shipped_action_sets_a_tenant_value():
    f = Fake()
    r = run(f, action="update", tag="soc-isolate-endpoint", time="20")
    assert f.lists[TENANT] == {"value": {"soc-isolate-endpoint": {"time_minutes": 20}}}
    assert "15 -> 20 minutes" in r.readable_output and r.outputs[0]["From"] == "tenant"


def test_update_of_a_tenant_value_changes_only_what_is_given():
    f = Fake(tenant={"value": {"soc-star-case": {"time_minutes": 5, "action_category": "triage"}}})
    run(f, action="update", tag="soc-star-case", category="comms")
    assert f.lists[TENANT]["value"]["soc-star-case"] == {"time_minutes": 5, "action_category": "comms"}


def test_update_to_the_same_tenant_value_writes_nothing():
    f = Fake(tenant={"value": {"soc-star-case": {"time_minutes": 5, "action_category": "triage"}}})
    r = run(f, action="update", tag="soc-star-case", time="5")
    assert f.writes == [] and "No change" in r.readable_output


def test_update_to_zero_stops_a_shipped_action_counting():
    f = Fake()
    r = run(f, action="update", tag="soc-enrich-user", time="0")
    assert r.outputs[0]["Minutes"] == 0 and r.outputs[0]["From"] == "tenant"


def test_delete_goes_back_to_the_shipped_value():
    f = Fake(tenant={"Zscaler": {"using": "z"}, "value": {"soc-isolate-endpoint": {"time_minutes": 20}}})
    r = run(f, action="delete", tag="soc-isolate-endpoint")
    assert f.lists[TENANT] == {"Zscaler": {"using": "z"}}
    assert "back to the shipped 15 minutes" in r.readable_output


def test_delete_of_a_tenant_only_action_records_zero():
    f = Fake(tenant={"value": {"soc-star-case": {"time_minutes": 5, "action_category": "triage"}}})
    r = run(f, action="delete", tag="soc-star-case")
    assert "records 0 minutes" in r.readable_output and f.lists[TENANT] == {}


# ── refusals write nothing ───────────────────────────────────────────────────

@pytest.mark.parametrize("args, says", [
    ({"action": "add", "tag": "soc-isolate-endpoint", "time": "5", "category": "triage"}, "use action=update"),
    ({"action": "add", "tag": "soc-star-case", "time": "5"}, "add needs time and category"),
    ({"action": "add", "tag": "soc-star-case", "time": "five", "category": "triage"}, "whole minutes"),
    ({"action": "add", "tag": "soc-star-case", "time": "-1", "category": "triage"}, "negative"),
    ({"action": "add", "tag": "soc-star-case", "time": "5", "category": "use_case"}, "category is one of"),
    ({"action": "update", "tag": "soc-star-case", "time": "5"}, "use action=add"),
    ({"action": "update", "tag": "soc-isolate-endpoint"}, "needs time, category or both"),
    ({"action": "delete", "tag": "soc-isolate-endpoint"}, "only the shipped value"),
    ({"action": "delete", "tag": "soc-star-case"}, "has no value"),
    ({"action": "delete"}, "needs tag"),
    ({"action": "list_by_type"}, "needs category"),
    ({"action": "sync"}, "action is one of"),
    ({"action": "list_all", "output_format": "csv"}, "output_format is one of"),
])
def test_bad_requests_are_refused_and_write_nothing(args, says):
    assert says in refused(Fake(), **args)


def test_deleting_a_shipped_value_says_how_to_stop_it_counting():
    assert "action=update tag=soc-isolate-endpoint time=0" in refused(Fake(), action="delete", tag="soc-isolate-endpoint")


@pytest.mark.parametrize("arg", ["playbook_name", "scriptid", "vendor", "product", "type", "playbookid"])
def test_lookup_era_arguments_are_refused_with_the_new_shape(arg):
    msg = refused(Fake(), action="add", tag="soc-star-case", time="5", category="triage", **{arg: "x"})
    assert "no longer used" in msg and "tag=<action>" in msg


@pytest.mark.parametrize("tenant, says", [("not json", "not a JSON object"), ({"value": "5"}, "must be an object")])
def test_an_unusable_tenant_config_is_never_written_over(tenant, says):
    assert says in refused(Fake(tenant=tenant), action="add", tag="soc-star-case", time="5", category="triage")


@pytest.mark.parametrize("time_map", ["not json", "[]"])
def test_an_unusable_shipped_list_is_refused(time_map):
    assert "reinstall soc-optimization-unified" in refused(Fake(time_map=time_map), action="list_all")


# ── agrees with the wrapper ──────────────────────────────────────────────────

def _wrapper():
    sys.path.insert(0, os.path.join(PACK, "Scripts", "SOCCommandWrapper"))
    from SOCCommandWrapper_test import load_script
    script, _ = load_script()
    return script


@pytest.mark.parametrize("tenant", [
    {},
    {"value": {"soc-isolate-endpoint": {"time_minutes": 25}}},
    {"value": {"soc-isolate-endpoint": {"action_category": "eradication"}}},
    {"value": {"soc-isolate-endpoint": {"time_minutes": "bad"}}},
    {"value": {"soc-isolate-endpoint": {"time_minutes": 0, "action_category": "triage"}}},
    {"value": {"soc-star-case": {"time_minutes": 5, "action_category": "triage"}}},
])
def test_reported_value_is_what_the_wrapper_records(tenant):
    module = load(Fake())
    ship = {k: v for k, v in shipped().items() if isinstance(v, dict)}
    script = _wrapper()
    for action in ("soc-isolate-endpoint", "soc-star-case", "soc-enrich-user"):
        mine = module.effective(ship, module.tenant_values(tenant), action)
        minutes, category, _ = script.resolve_action_value(shipped(), tenant, action)
        assert (mine["Minutes"], mine["Category"]) == (minutes, category), (action, tenant)


def test_the_shipped_list_reads_and_every_category_is_accepted():
    ship = json.load(open(SHIPPED))
    r = run(Fake(time_map=ship), action="list_all")
    assert {x["Action"] for x in r.outputs} == {k for k, v in ship.items() if isinstance(v, dict)}
    module = load(Fake())
    assert {v["action_category"] for v in ship.values() if isinstance(v, dict)} <= set(module.CATEGORIES)


def test_yml_matches_the_script():
    import yaml
    spec = yaml.safe_load(open(os.path.join(HERE, "setValueTags.yml")))
    args = {a["name"]: a for a in spec["args"]}
    module = load(Fake())
    assert sorted(args["action"]["predefined"]) == sorted(module.ACTIONS)
    assert tuple(args["category"]["predefined"]) == module.CATEGORIES
    # The retired arguments are declared so the platform passes them through and the script can
    # refuse them; an undeclared argument is dropped before the script sees it.
    assert set(args) == {"action", "tag", "time", "category", "output_format"} | set(module.RETIRED_ARGS)
    assert all("Retired" in args[a]["description"] for a in module.RETIRED_ARGS)
    assert {o["contextPath"] for o in spec["outputs"]} == {f"SOCValueTags.{k}" for k in ("Action", "Minutes", "Category", "From")}
