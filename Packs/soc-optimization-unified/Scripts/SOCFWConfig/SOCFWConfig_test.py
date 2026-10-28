"""
SOCFWConfig_test.py

status, shadow and set against the shipped SOCFrameworkActions_V3, with an
in-memory tenant standing in for lists, the REST call that creates a JSON list,
and the dataset writer. One test checks that status reports what
SOCCommandWrapper would actually do, for every action and actor.

Run: pytest Scripts/SOCFWConfig/SOCFWConfig_test.py -v
"""

import builtins
import importlib
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(__file__)
ACTIONS = json.load(open(os.path.join(
    HERE, "..", "..", "Lists", "SOCFrameworkActions_V3", "SOCFrameworkActions_V3_data.json")))
NEW = "SOCFWTenantConfig"
OLD = "SOCFrameworkTenantConfig_V3"  # removed name; must never be read or written


class Tenant:
    """Lists by name with their type, every command run, and dataset rows."""

    def __init__(self, core_api=True, **lists):
        self.lists = {"SOCFrameworkActions_V3": json.dumps(ACTIONS)}
        self.types = {"SOCFrameworkActions_V3": "json"}
        for k, v in lists.items():
            self.lists[k] = v if isinstance(v, str) else json.dumps(v)
            self.types[k] = "json"
        self.commands, self.rows = [], []
        self.dataset_down = False
        self.core_api = core_api
        # As shipped: off, placeholder owner (jobs/search shape on deathstar, 27 Oct 2026).
        self.jobs = {n: {"id": f"id-{i}", "version": 1, "name": n, "owner": "set-owner-with-SOCFWConfig",
                         "scheduled": False, "playbookId": "JOB - " + n, "nextRunTime": "2026-10-27T13:23:48Z"}
                     for i, n in enumerate(("Auto Triage V3", "SOC Case Analysis"))}
        self.users = [{"id": "ana@example.com", "username": "ana@example.com",
                       "email": "ana@example.com", "name": "Ana"}]
        self.jobs_ignore_writes = False

    def execute(self, command, args):
        self.commands.append((command, args))
        name = args.get("listName")
        if command == "getList":
            if name not in self.lists:
                # What getList returns inside a script for a missing list (deathstar, 26 Oct 2026).
                return [{"Type": 4, "Contents": f" - Item not found (8) on list [{name}] (2609)"}]
            return [{"Type": 1, "Contents": self.lists[name]}]
        if command == "setList":
            if name not in self.lists:
                return [{"Type": 4, "Contents": "Item not found"}]
            self.lists[name] = args["listData"]
            return [{"Type": 1, "Contents": "Done"}]
        if command == "createList":
            # The built-in: always plain text (deathstar, 27 Oct 2026).
            self.lists[name] = args["listData"]
            self.types[name] = "plain_text"
            return [{"Type": 1, "Contents": "Done"}]
        if command == "core-api-post":
            if not self.core_api:
                return [{"Type": 4, "Contents": "Unsupported Command: core-api-post"}]
            body = json.loads(args["body"])
            if args["uri"] == "/xsoar/public/v1/jobs/search":
                return [{"Type": 1, "Contents": {"response": {"data": [dict(j) for j in self.jobs.values()],
                                                              "total": len(self.jobs)}}}]
            if args["uri"] == "/xsoar/public/v1/jobs":
                if not self.jobs_ignore_writes:
                    body["version"] = body.get("version", 0) + 1
                    self.jobs[body["name"]] = body
                return [{"Type": 1, "Contents": {"response": body}}]
            assert args["uri"] == "/xsoar/public/v1/lists/save"
            self.lists[body["name"]] = body["data"]
            self.types[body["name"]] = body.get("type", "plain_text")
            return [{"Type": 1, "Contents": {"response": {"id": body["name"]}}}]
        if command == "getUsers":
            return [{"Type": 1, "Contents": list(self.users)}]
        if command == "socfw-post-to-dataset":
            self.rows.append(json.loads(args["JSON"]))
            return ([{"Type": 4, "Contents": "writer down"}] if self.dataset_down
                    else [{"Type": 1, "Contents": "ok"}])
        return []

    def config(self, name=NEW):
        return json.loads(self.lists[name]) if name in self.lists else None

    def writes(self):
        return [c for c, a in self.commands if c in ("setList", "createList", "core-api-post")
                and a.get("uri") != "/xsoar/public/v1/jobs/search"]


class Results:
    def __init__(self, readable_output=None, outputs_prefix=None, outputs=None, **kw):
        self.readable_output, self.outputs_prefix, self.outputs = (
            readable_output, outputs_prefix, outputs)


def run(tenant, **args):
    out = []
    demisto = types.SimpleNamespace(args=lambda: args, executeCommand=lambda c, a: tenant.execute(c, a),
                                    debug=lambda *a: None)

    def return_error(msg):
        raise RuntimeError(msg)

    for name, value in (("demisto", demisto), ("CommandResults", Results),
                        ("return_results", out.append), ("return_error", return_error)):
        setattr(builtins, name, value)
    sys.path.insert(0, HERE)
    module = importlib.import_module("SOCFWConfig")
    importlib.reload(module)
    module.main()
    return out[0]


def cell(result, action, actor):
    return next(r for r in result.outputs["rows"]
                if r["action"] == action and r["actor"] == actor)


# ── status ───────────────────────────────────────────────────────────────────

def test_status_names_the_exact_field_behind_each_cell():
    t = Tenant(**{NEW: {"shadow": {"soc-star-case": {"automation": False}}}})
    r = run(t, command="status", action="soc-star-case")
    assert r.outputs["contract_version"] == 2
    assert (cell(r, "soc-star-case", "analyst")["field"]
            == "SOCFrameworkActions_V3 soc-star-case.shadow_mode_by_actor.analyst")
    assert cell(r, "soc-star-case", "analyst")["decided_by"] == "action_actor"
    assert cell(r, "soc-star-case", "automation")["field"] == "SOCFWTenantConfig shadow.soc-star-case.automation"
    assert cell(r, "soc-star-case", "automation")["decided_by"] == "tenant_config"
    assert "| soc-star-case | live | shadow | live ✱ | shadow |" in r.readable_output
    iso = run(t, command="status", action="soc-kill-process")
    assert cell(iso, "soc-kill-process", "analyst")["field"] == "SOCFrameworkActions_V3 soc-kill-process.shadow_mode"
    assert cell(iso, "soc-kill-process", "analyst")["decided_by"] == "action_default"
    assert "| soc-kill-process | shadow † | shadow † | shadow † | shadow † |" in iso.readable_output


def test_status_lists_mutating_actions_only_by_default():
    r = run(Tenant(), command="status")
    listed = {row["action"] for row in r.outputs["rows"]}
    assert "soc-enrich-domain" not in listed and "soc-isolate-endpoint" in listed
    assert "read-only actions" in r.readable_output


def test_status_shows_customer_values_and_what_is_missing():
    t = Tenant(**{NEW: {"Zscaler": {"category-id": "CAT-1"}}})
    r = run(t, command="status")
    values = {(v["vendor"], v["arg"]): v for v in r.outputs["values"]}
    assert set(values) == {("Zscaler", "category-id"), ("Zscaler", "using"), ("ThreatStopv2", "list_id"),
                           ("CrowdStrike Falcon", "using")}
    assert values[("Zscaler", "category-id")]["value"] == "CAT-1"
    assert values[("ThreatStopv2", "list_id")]["set"] is False
    assert values[("ThreatStopv2", "list_id")]["required"] is True
    assert values[("Zscaler", "using")]["required"] is False
    assert "**missing** — required" in r.readable_output


def test_status_never_reads_the_removed_list_name():
    t = Tenant(**{OLD: {"shadow": {"soc-star-case": {"ai": False}}, "Zscaler": {"category-id": "x"}}})
    r = run(t, command="status")
    assert cell(r, "soc-star-case", "ai")["state"] == "shadow"
    assert r.outputs["tenant_config_exists"] is False
    assert all(a.get("listName") != OLD for _, a in t.commands)


def test_status_agrees_with_the_wrapper_for_every_action_and_actor():
    sys.path.insert(0, os.path.join(HERE, "..", "SOCCommandWrapper"))
    from SOCCommandWrapper_test import load_script
    all_actions = ",".join(k for k, v in ACTIONS.items() if isinstance(v, dict) and "responses" in v)
    for cfg in (None,
                {"shadow": {"soc-star-case": {"ai": False, "automation": False},
                            "soc-isolate-endpoint": {"analyst": False}}},
                {"shadow": {"soc-star-case": {"framework": False, "automation": True}}}):
        r = run(Tenant(**({NEW: cfg} if cfg else {})), command="status", action=all_actions)
        wrapper, _ = load_script()
        for row in r.outputs["rows"]:
            expected = wrapper.resolve_shadow_mode(
                ACTIONS[row["action"]], row["actor"],
                wrapper.tenant_shadow_override(cfg, row["action"], row["actor"]))
            assert row["shadow"] == expected, (cfg, row)
        # framework is not shown, but must resolve the same way in both
        import SOCFWConfig as cfgmod
        for name, action_row in ACTIONS.items():
            if isinstance(action_row, dict) and "responses" in action_row:
                mine = cfgmod.effective(cfg or {}, name, action_row, "framework")[0]
                theirs = wrapper.resolve_shadow_mode(
                    action_row, "framework", wrapper.tenant_shadow_override(cfg, name, "framework"))
                assert mine == theirs, (cfg, name)


# ── shadow ───────────────────────────────────────────────────────────────────

def test_shadow_dry_run_by_default_writes_nothing():
    t = Tenant()
    r = run(t, command="shadow", action="soc-star-case", actor="ai,automation", value="off")
    assert r.outputs["dry_run"] and not r.outputs["applied"]
    assert [(c["actor"], c["from"], c["to"]) for c in r.outputs["changes"]] == [
        ("ai", "shadow", "live"), ("automation", "shadow", "live")]
    assert t.writes() == [] and t.rows == []
    assert r.outputs["creates_list"] is True
    assert "Will create SOCFWTenantConfig as a JSON list." in r.readable_output


def test_first_write_creates_a_json_list_through_the_rest_api():
    t = Tenant()
    r = run(t, command="shadow", action="soc-star-case", actor="ai,automation",
            value="off", apply="yes")
    assert r.outputs["applied"]
    assert t.writes() == ["core-api-post"]          # never the plain-text createList
    assert t.types[NEW] == "json"
    assert t.config() == {"shadow": {"soc-star-case": {"ai": False, "automation": False}}}
    assert OLD not in t.lists


def test_first_write_without_core_rest_api_names_the_integration():
    t = Tenant(core_api=False)
    with pytest.raises(RuntimeError, match="Core REST API integration"):
        run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert NEW not in t.lists


def test_existing_list_is_updated_in_place_and_keeps_its_type():
    t = Tenant(**{NEW: {"Zscaler": {"category-id": "cat-1"}}})
    run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert t.writes() == ["setList"] and t.types[NEW] == "json"
    assert t.config() == {"Zscaler": {"category-id": "cat-1"},
                          "shadow": {"soc-star-case": {"ai": False}}}


def test_default_removes_the_setting_and_reverses_the_change():
    t = Tenant(**{NEW: {"Zscaler": {"category-id": "cat-1"},
                        "shadow": {"soc-star-case": {"ai": False, "automation": False}}}})
    r = run(t, command="shadow", action="soc-star-case", actor="ai,automation",
            value="default", apply="yes")
    assert [(c["from"], c["to"]) for c in r.outputs["changes"]] == [
        ("live", "shadow"), ("live", "shadow")]
    assert t.config() == {"Zscaler": {"category-id": "cat-1"}}


def test_repeat_apply_is_a_no_op():
    t = Tenant(**{NEW: {"shadow": {"soc-star-case": {"ai": False}}}})
    r = run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert t.writes() == [] and t.rows == [] and not r.outputs["applied"]
    assert "nothing to change" in r.readable_output


def test_read_only_action_is_refused_and_not_written():
    t = Tenant()
    r = run(t, command="shadow", action="soc-enrich-domain", actor="ai", value="on", apply="yes")
    assert r.outputs["refused"] and "read-only" in r.outputs["refused"][0]["reason"]
    assert t.writes() == []


@pytest.mark.parametrize("args, message", [
    ({"action": "soc-star-case", "actor": "ai"}, "value must be"),
    ({"action": "soc-star-case", "value": "off"}, "actor is required"),
    ({"actor": "ai", "value": "off"}, "action is required"),
    ({"action": "soc-nope", "actor": "ai", "value": "off"}, "unknown action"),
    ({"action": "soc-star-case", "actor": "robot", "value": "off"}, "unknown actor"),
    ({"action": "soc-star-case", "actor": "framework", "value": "off"}, "framework is now automation"),
])
def test_shadow_bad_arguments_name_the_fix(args, message):
    t = Tenant()
    with pytest.raises(RuntimeError, match=message):
        run(t, command="shadow", **args)
    assert t.writes() == []


def test_shadow_records_one_row_per_changed_actor_outside_any_incident():
    t = Tenant(**{NEW: {"shadow": {"soc-star-case": {"ai": False}}}})
    r = run(t, command="shadow", action="soc-star-case", actor="ai,automation",
            value="off", apply="yes")
    assert r.outputs["recorded"] is True
    assert [{k: v for k, v in row.items() if k != "timestamp"} for row in t.rows] == [
        {"event_type": "config_change", "universal_command": "soc-star-case",
         "action_actor": "automation", "shadow_mode_state": "live",
         "action_status": "set off", "action_taken": "shadow -> live"}]
    assert all("incident_id" not in row and "phase" not in row for row in t.rows)


def test_failed_record_does_not_fail_the_change():
    t = Tenant(**{NEW: {}})
    t.dataset_down = True
    r = run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert r.outputs["applied"] is True and r.outputs["recorded"] is False
    assert t.config() == {"shadow": {"soc-star-case": {"ai": False}}}
    assert "record in the execution dataset was not" in r.readable_output


def test_malformed_tenant_list_is_never_overwritten():
    t = Tenant(**{NEW: "not json"})
    with pytest.raises(RuntimeError, match="not a JSON object"):
        run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")
    assert t.lists[NEW] == "not json"


def test_write_that_does_not_land_is_reported():
    t = Tenant(**{NEW: {}})
    real = t.execute

    def silent_set(command, args):
        if command == "setList":
            t.commands.append((command, args))
            return [{"Type": 1, "Contents": "Done"}]  # claims success, changes nothing
        return real(command, args)

    t.execute = silent_set
    with pytest.raises(RuntimeError, match="could not write SOCFWTenantConfig"):
        run(t, command="shadow", action="soc-star-case", actor="ai", value="off", apply="yes")


# ── set ──────────────────────────────────────────────────────────────────────

def test_set_dry_run_shows_the_change_and_writes_nothing():
    t = Tenant(**{NEW: {"Zscaler": {"category-id": "OLD-1"}}})
    r = run(t, command="set", vendor="Zscaler", arg="category-id", value="NEW-2")
    assert (r.outputs["from"], r.outputs["to"], r.outputs["dry_run"]) == ("OLD-1", "NEW-2", True)
    assert r.outputs["used_by"] == ["soc-block-domain", "soc-block-network-indicator"]
    assert t.writes() == []


def test_set_apply_writes_only_that_value_and_records_it():
    t = Tenant(**{NEW: {"Zscaler": {"category-id": "OLD-1", "using": "zia_1"},
                        "shadow": {"soc-star-case": {"automation": False}}}})
    r = run(t, command="set", vendor="zscaler", arg="Category-ID", value="NEW-2", apply="yes")
    assert r.outputs["applied"] and r.outputs["recorded"]
    assert t.config() == {"Zscaler": {"category-id": "NEW-2", "using": "zia_1"},
                          "shadow": {"soc-star-case": {"automation": False}}}
    assert [{k: v for k, v in row.items() if k != "timestamp"} for row in t.rows] == [
        {"event_type": "config_change", "vendor": "Zscaler", "action_status": "set category-id",
         "action_taken": "category-id: OLD-1 -> NEW-2"}]


def test_set_on_a_new_tenant_creates_a_json_list():
    t = Tenant()
    run(t, command="set", vendor="ThreatStopv2", arg="list_id", value="L-9", apply="yes")
    assert t.writes() == ["core-api-post"] and t.types[NEW] == "json"
    assert t.config() == {"ThreatStopv2": {"list_id": "L-9"}}


def test_set_default_removes_the_value_and_warns_when_required():
    t = Tenant(**{NEW: {"ThreatStopv2": {"list_id": "L-9"}, "Zscaler": {"category-id": "C"}}})
    r = run(t, command="set", vendor="ThreatStopv2", arg="list_id", value="default", apply="yes")
    assert t.config() == {"Zscaler": {"category-id": "C"}}
    assert r.outputs["to"] is None and "not configured" in r.readable_output


def test_set_optional_using_is_settable():
    t = Tenant(**{NEW: {}})
    run(t, command="set", vendor="Zscaler", arg="using", value="Zscaler_prod", apply="yes")
    assert t.config() == {"Zscaler": {"using": "Zscaler_prod"}}


def test_set_repeat_is_a_no_op():
    t = Tenant(**{NEW: {"Zscaler": {"category-id": "C"}}})
    r = run(t, command="set", vendor="Zscaler", arg="category-id", value="C", apply="yes")
    assert t.writes() == [] and t.rows == [] and "nothing to change" in r.readable_output


@pytest.mark.parametrize("args, message", [
    ({"vendor": "Zscaler", "arg": "url", "value": "x"}, "not a customer value any action uses"),
    ({"vendor": "Okta", "arg": "list_id", "value": "x"}, "not a customer value any action uses"),
    ({"vendor": "Zscaler", "value": "x"}, "vendor and arg are required"),
    ({"vendor": "Zscaler", "arg": "category-id"}, "value is required"),
])
def test_set_bad_arguments_name_the_fix(args, message):
    t = Tenant()
    with pytest.raises(RuntimeError, match=message):
        run(t, command="set", **args)
    assert t.writes() == []


def test_unknown_command():
    with pytest.raises(RuntimeError, match="unknown command"):
        run(Tenant(), command="pov")


# ── fail closed, reported the same way the wrapper decides it ────────────────

def _mangled_actions():
    mangled = json.loads(json.dumps(ACTIONS))
    mangled["soc-kill-process"].pop("shadow_mode")
    mangled["soc-close-issue"]["shadow_mode"] = "yes"
    mangled["soc-star-case"]["shadow_mode_by_actor"]["analyst"] = "no"     # garbled
    mangled["soc-star-case"]["shadow_mode_by_actor"].pop("automation")      # not named
    mangled["soc-enrich-domain"].pop("shadow_mode")
    return mangled


def test_status_reports_missing_or_garbled_settings_as_simulated():
    t = Tenant()
    t.lists["SOCFrameworkActions_V3"] = json.dumps(_mangled_actions())
    r = run(t, command="status", action="soc-kill-process,soc-close-issue,soc-star-case,soc-enrich-domain")
    for actor in ("analyst", "ai", "automation", "issue_emergency"):
        assert cell(r, "soc-close-issue", actor)["state"] == "shadow"
        assert cell(r, "soc-star-case", actor)["state"] == "shadow"
    assert cell(r, "soc-star-case", "automation")["field"].endswith("(not named)")
    assert cell(r, "soc-kill-process", "automation")["field"].endswith("(missing or unreadable)")
    assert cell(r, "soc-enrich-domain", "automation")["state"] == "live"


def test_status_agrees_with_the_wrapper_on_a_mangled_list():
    sys.path.insert(0, os.path.join(HERE, "..", "SOCCommandWrapper"))
    from SOCCommandWrapper_test import load_script
    mangled = _mangled_actions()
    t = Tenant()
    t.lists["SOCFrameworkActions_V3"] = json.dumps(mangled)
    names = [k for k, v in mangled.items() if isinstance(v, dict) and "responses" in v]
    r = run(t, command="status", action=",".join(names))
    wrapper, _ = load_script()
    for row in r.outputs["rows"]:
        assert row["shadow"] == wrapper.resolve_shadow_mode(mangled[row["action"]], row["actor"]), row



def test_actor_dropdown_matches_actors():
    """The actor dropdown in the YAML offers exactly the actors the script accepts."""
    import yaml
    with open(os.path.join(HERE, "SOCFWConfig.yml")) as f:
        spec = yaml.safe_load(f)
    actor = next(a for a in spec["args"] if a["name"] == "actor")
    assert actor.get("auto") == "PREDEFINED"
    assert actor.get("isArray") is True
    run(Tenant(), command="status")  # loads the module
    assert tuple(actor["predefined"]) == sys.modules["SOCFWConfig"].ACTORS


def test_shadow_accepts_actor_list_from_dropdown():
    """A multi-select arrives as a list; it must give the same change as a comma string."""
    as_list = run(Tenant(), command="shadow", action="soc-star-case",
                  actor=["ai", "automation"], value="off").outputs
    as_text = run(Tenant(), command="shadow", action="soc-star-case",
                  actor="ai,automation", value="off").outputs
    assert as_list["changes"] and as_list["changes"] == as_text["changes"]


# ── job and owner ────────────────────────────────────────────────────────────

AT = "Auto Triage V3"
ANA = "ana@example.com"


def owned(t, scheduled=False):
    t.jobs[AT].update(owner=ANA, scheduled=scheduled)
    return t


def test_owner_dry_run_writes_nothing():
    t = Tenant()
    o = run(t, command="owner", job=AT, owner=ANA).outputs
    assert o["dry_run"] and not o["applied"] and o["changed"]
    assert o["to"] == {"owner": ANA, "scheduled": False}
    assert t.jobs[AT]["owner"] == "set-owner-with-SOCFWConfig" and t.writes() == [] and t.rows == []
    assert o["apply_command"] == f'!SOCFWConfig command=owner job="{AT}" owner={ANA} apply=yes'


def test_owner_apply_sets_owner_only_reads_back_and_records():
    t = Tenant()
    r = run(t, command="owner", job="auto triage v3", owner="ANA@example.com", apply="yes")
    assert r.outputs["applied"] and r.outputs["recorded"]
    assert t.jobs[AT]["owner"] == "ANA@example.com" and t.jobs[AT]["scheduled"] is False
    assert t.jobs[AT]["id"] == "id-0"
    row = t.rows[-1]
    assert row["event_type"] == "config_change" and row["job"] == AT and row["action_status"] == "owner"
    assert "incident_id" not in row and "phase" not in row
    assert "owner: set-owner-with-SOCFWConfig -> ANA@example.com" in row["action_taken"]


def test_owner_refuses_someone_who_is_not_a_user():
    t = Tenant()
    with pytest.raises(RuntimeError, match="not a user on this tenant"):
        run(t, command="owner", job=AT, owner="nobody@example.com", apply="yes")
    assert t.writes() == []


def test_owner_users_unreadable_refused():
    t = Tenant()
    t.users = []
    with pytest.raises(RuntimeError, match="could not read the tenant's users"):
        run(t, command="owner", job=AT, owner=ANA, apply="yes")


def test_owner_required():
    with pytest.raises(RuntimeError, match="owner is required"):
        run(Tenant(), command="owner", job=AT)


def test_job_turns_schedule_on_and_keeps_owner():
    t = owned(Tenant())
    r = run(t, command="job", job=AT, value="on", apply="yes")
    assert r.outputs["applied"] and r.outputs["recorded"]
    assert t.jobs[AT]["scheduled"] is True and t.jobs[AT]["owner"] == ANA
    assert t.rows[-1]["action_status"] == "job"
    assert "schedule: off -> on" in t.rows[-1]["action_taken"]
    assert "Next run:" in r.readable_output


def test_job_dry_run_writes_nothing():
    t = owned(Tenant())
    o = run(t, command="job", job=AT, value="on").outputs
    assert o["dry_run"] and o["changed"] and t.jobs[AT]["scheduled"] is False and t.writes() == []


def test_job_cannot_turn_on_without_owner_and_names_the_fix():
    t = Tenant()
    with pytest.raises(RuntimeError, match='command=owner job="Auto Triage V3"'):
        run(t, command="job", job=AT, value="on", apply="yes")
    assert t.jobs[AT]["scheduled"] is False


def test_job_off_needs_no_owner():
    t = Tenant()
    t.jobs[AT]["scheduled"] = True
    r = run(t, command="job", job=AT, value="off", apply="yes")
    assert r.outputs["applied"] and t.jobs[AT]["scheduled"] is False
    assert "set an owner" in r.readable_output


def test_job_does_not_take_owner():
    t = Tenant()
    with pytest.raises(RuntimeError, match="set the owner with !SOCFWConfig command=owner"):
        run(t, command="job", job=AT, owner=ANA, value="on")
    assert t.writes() == []


def test_job_unknown_name_and_bad_value_refused():
    with pytest.raises(RuntimeError, match="job is required"):
        run(owned(Tenant()), command="job", job="Something Else", value="on")
    with pytest.raises(RuntimeError, match="on or off"):
        run(Tenant(), command="job", job=AT, value="default")
    with pytest.raises(RuntimeError, match="on or off"):
        run(Tenant(), command="job", job=AT)


def test_no_change_is_said_and_not_written():
    t = owned(Tenant(), scheduled=True)
    r = run(t, command="job", job=AT, value="on", apply="yes")
    assert not r.outputs["changed"] and "nothing to change" in r.readable_output and t.rows == []
    r = run(t, command="owner", job=AT, owner=ANA, apply="yes")
    assert not r.outputs["changed"] and t.rows == []


def test_write_that_does_not_land_is_reported():
    t = owned(Tenant())
    t.jobs_ignore_writes = True
    with pytest.raises(RuntimeError, match="did not change on the tenant"):
        run(t, command="job", job=AT, value="on", apply="yes")
    with pytest.raises(RuntimeError, match="did not change on the tenant"):
        run(t, command="owner", job=AT, owner="ANA@example.com", apply="yes")
    assert t.rows == []


def test_job_without_core_api_says_what_is_missing():
    with pytest.raises(RuntimeError, match="Core REST API"):
        run(Tenant(core_api=False), command="job", job=AT, value="off")


def test_status_shows_jobs_and_whether_owner_is_a_user():
    t = owned(Tenant(), scheduled=True)
    r = run(t, command="status")
    jobs = {j["job"]: j for j in r.outputs["jobs"]}
    assert jobs[AT]["scheduled"] is True and jobs[AT]["owner_is_user"] is True
    assert jobs["SOC Case Analysis"]["owner_is_user"] is False
    assert "| SOC Case Analysis | off | `set-owner-with-SOCFWConfig` | **no** |" in r.readable_output
    assert "command=owner" in r.readable_output
    assert t.writes() == []


def test_status_without_core_api_still_works():
    r = run(Tenant(core_api=False), command="status")
    assert r.outputs["jobs"] == [] and "Could not read the jobs" in r.readable_output


def test_job_dropdown_matches_jobs():
    import yaml
    with open(os.path.join(HERE, "SOCFWConfig.yml")) as f:
        spec = yaml.safe_load(f)
    arg = next(a for a in spec["args"] if a["name"] == "job")
    run(Tenant(), command="status")
    assert tuple(arg["predefined"]) == sys.modules["SOCFWConfig"].JOBS
    cmd = next(a for a in spec["args"] if a["name"] == "command")
    assert {"job", "owner"} <= set(cmd["predefined"])


# ── CrowdStrike isolate: per actor, and the instance ────────────────────────

CS = "CrowdStrike Falcon"


def test_set_accepts_crowdstrike_using_and_status_lists_it():
    t = Tenant()
    r = run(t, command="set", vendor="crowdstrike falcon", arg="using", value="CrowdStrike_Prod", apply="yes")
    assert r.outputs["applied"] and t.config()[CS] == {"using": "CrowdStrike_Prod"}
    assert set(r.outputs["used_by"]) == {"soc-isolate-endpoint", "soc-deisolate-endpoint"}
    assert r.outputs["required"] is False
    s = run(t, command="status")
    row = [v for v in s.outputs["values"] if v["vendor"] == CS and v["arg"] == "using"]
    assert row and row[0]["value"] == "CrowdStrike_Prod"


def test_shadow_takes_isolate_live_for_analyst_only():
    t = Tenant()
    run(t, command="shadow", action="soc-isolate-endpoint", actor="analyst", value="off", apply="yes")
    assert t.config()["shadow"]["soc-isolate-endpoint"] == {"analyst": False}
    r = run(t, command="status", action="soc-isolate-endpoint")
    assert cell(r, "soc-isolate-endpoint", "analyst")["shadow"] is False
    assert cell(r, "soc-isolate-endpoint", "analyst")["decided_by"] == "tenant_config"
    for actor in ("ai", "automation", "issue_emergency"):
        c = cell(r, "soc-isolate-endpoint", actor)
        assert c["shadow"] is True and c["decided_by"] == "action_actor"
        assert c["field"] == f"SOCFrameworkActions_V3 soc-isolate-endpoint.shadow_mode_by_actor.{actor}"


# ── emergency ────────────────────────────────────────────────────────────────

POLICY = json.load(open(os.path.join(
    HERE, "..", "..", "Lists", "SOCFrameworkPhasePolicy_V3", "SOCFrameworkPhasePolicy_V3_data.json")))
PL = "SOCFrameworkPhasePolicy_V3"
IDENTITY = "soc-clear-sessions,soc-revoke-tokens,soc-reset-password"


def em_tenant(cfg=None):
    lists = {PL: POLICY}
    if cfg is not None:
        lists[NEW] = cfg
    return Tenant(**lists)


def test_emergency_lists_the_shipped_policies_with_each_action_state():
    r = run(em_tenant(), command="emergency")
    views = {v["policy"]: v for v in r.outputs["policies"]}
    assert set(views) == {"identity_compromise", "endpoint_execution", "email_delivered"}
    assert r.outputs["enabled"] is True
    assert [a["action"] for a in views["identity_compromise"]["actions"]] == IDENTITY.split(",")
    assert {a["state"] for v in views.values() for a in v["actions"]} == {"shadow"}
    assert all(v["origin"] == "shipped" for v in views.values())


def test_emergency_action_state_follows_the_tenant_shadow_setting():
    t = em_tenant({"shadow": {"soc-clear-sessions": {"issue_emergency": False}}})
    r = run(t, command="emergency")
    acts = next(v for v in r.outputs["policies"] if v["policy"] == "identity_compromise")["actions"]
    assert acts[0] == {"action": "soc-clear-sessions", "state": "live"}


def test_emergency_add_is_a_dry_run_by_default():
    t = em_tenant()
    r = run(t, command="emergency", policy="okta_spamhaus", rule_id="345", action=IDENTITY)
    assert r.outputs["dry_run"] and not r.outputs["applied"] and r.outputs["changed"]
    assert t.writes() == []
    assert "apply=yes" in r.outputs["apply_command"] and "rule_id=345" in r.outputs["apply_command"]


def test_emergency_add_writes_the_policy_and_records_it():
    t = em_tenant({})
    r = run(t, command="emergency", policy="okta_spamhaus", rule_id="345", verdict=["any"],
            confidence="any", action=IDENTITY, apply="yes")
    assert r.outputs["applied"] and r.outputs["recorded"]
    assert t.config()["emergency"]["policies"]["okta_spamhaus"] == {
        "rule_id": ["345"], "verdict": ["any"], "confidence": "any",
        "actions": IDENTITY.split(",")}
    assert t.rows[-1]["event_type"] == "config_change" and "incident_id" not in t.rows[-1]
    listed = run(t, command="emergency").outputs["policies"]
    assert listed[-1]["policy"] == "okta_spamhaus" and listed[-1]["origin"] == "this tenant"


def test_emergency_edit_of_a_shipped_policy_stores_only_what_changed():
    t = em_tenant({})
    run(t, command="emergency", policy="identity_compromise", confidence="medium",
        source="DS_OKTA_SYSTEMLOG", apply="yes")
    assert t.config()["emergency"]["policies"]["identity_compromise"] == {
        "confidence": "medium", "source": ["ds_okta_systemlog"]}
    v = next(v for v in run(t, command="emergency").outputs["policies"]
             if v["policy"] == "identity_compromise")
    assert v["origin"] == "shipped, edited on this tenant" and v["about"] == ["identity"]


def test_emergency_off_then_default_returns_to_shipped():
    t = em_tenant({})
    run(t, command="emergency", policy="identity_compromise", enabled="off", apply="yes")
    assert t.config()["emergency"]["policies"]["identity_compromise"] == {"enabled": False}
    r = run(t, command="emergency", policy="identity_compromise", enabled="default", apply="yes")
    assert r.outputs["applied"] and "emergency" not in t.config()


def test_emergency_default_removes_a_tenant_policy():
    t = em_tenant({"emergency": {"policies": {"x": {"about": ["identity"], "actions": ["soc-disable-user"]}}}})
    r = run(t, command="emergency", policy="x", enabled="default", apply="yes")
    assert r.outputs["to"] is None and "emergency" not in t.config()


def test_emergency_repeat_is_a_no_op():
    t = em_tenant({"emergency": {"policies": {"identity_compromise": {"confidence": "medium"}}}})
    r = run(t, command="emergency", policy="identity_compromise", confidence="medium", apply="yes")
    assert not r.outputs["changed"] and t.writes() == []


def test_emergency_name_only_policy_is_flagged():
    t = em_tenant({})
    r = run(t, command="emergency", policy="spam", name_contains="Spamhaus", action=IDENTITY)
    assert r.outputs["to"]["name_only"] is True
    assert "issue name alone" in r.readable_output


@pytest.mark.parametrize("args, message", [
    ({"policy": "identity_compromise", "rule_id": "345"}, "policy of this tenant's own"),
    ({"policy": "identity_compromise", "name_contains": "x"}, "policy of this tenant's own"),
    ({"policy": "new_one", "action": IDENTITY}, "needs at least one of about"),
    ({"policy": "new_one", "rule_id": "345"}, "needs action="),
    ({"policy": "new_one"}, "no policy new_one"),
    ({"policy": "x", "rule_id": "1", "action": "soc-made-up"}, "unknown action soc-made-up"),
    ({"policy": "x", "rule_id": "1", "action": "soc-enrich-domain"}, "only read"),
    ({"policy": "x", "rule_id": "1", "action": IDENTITY, "confidence": "very"}, "confidence must be"),
    ({"policy": "x", "rule_id": "1", "action": IDENTITY, "verdict": "evil"}, "verdict evil"),
    ({"policy": "identity_compromise", "enabled": "default", "confidence": "low"}, "on its own"),
    ({"confidence": "low"}, "policy is required"),
])
def test_emergency_bad_arguments_name_the_fix(args, message):
    with pytest.raises(RuntimeError, match=message):
        run(em_tenant({}), command="emergency", **args)


@pytest.mark.parametrize("command, args, message", [
    ("shadow", {"action": "soc-star-case", "actor": "ai", "value": "on", "policy": "x"},
     "policy is for command=emergency, not shadow"),
    ("emergency", {"vendor": "Zscaler"}, "vendor is for command=set, not emergency"),
    ("status", {"rule_id": "345"}, "rule_id is for command=emergency, not status"),
    ("set", {"vendor": "Zscaler", "arg": "category-id", "value": "x", "actor": ["ai"]},
     "actor is for command=shadow"),
])
def test_an_argument_for_another_command_is_refused(command, args, message):
    with pytest.raises(RuntimeError, match=message):
        run(em_tenant({}), command=command, **args)


def test_empty_arguments_from_the_cli_are_not_refused():
    r = run(em_tenant({}), command="status", policy="", rule_id=None, actor=[], apply="no")
    assert r.outputs["command"] == "status"


def test_status_summarises_emergency_response():
    t = em_tenant({"emergency": {"policies": {"x": {"rule_id": ["1"], "actions": ["soc-disable-user"]}}}})
    r = run(t, command="status")
    assert r.outputs["emergency"] == {"enabled": True, "policies": 4, "tenant_policies": 1}
    assert "command=emergency" in r.readable_output


def test_emergency_arguments_are_all_declared_and_marked():
    import yaml
    spec = yaml.safe_load(open(os.path.join(HERE, "SOCFWConfig.yml")))
    declared = {a["name"]: a for a in spec["args"]}
    module = importlib.import_module("SOCFWConfig")
    used = set().union(*module.COMMAND_ARGS.values()) | module.ALWAYS_ARGS
    assert used == set(declared)
    assert "emergency" in declared["command"]["predefined"]
    for name in module.COMMAND_ARGS["emergency"] - {"action"}:
        assert declared[name]["description"].startswith("[emergency]"), name
