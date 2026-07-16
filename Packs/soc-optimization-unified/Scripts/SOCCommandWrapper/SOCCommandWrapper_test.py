import builtins
import importlib
import json
import sys
import types

import pytest


SCRIPT_MODULE_NAME = "SOCCommandWrapper"


def load_script():
    """
    Import/reload the script with mocked XSOAR runtime globals.

    The script is authored the way XSIAM executes it: `demisto`,
    `entryTypes`, `return_error`, `CommandResults` etc. are ambient
    globals injected by the platform, not imports. The script has no
    `import demistomock as demisto` line and must not gain one — adding
    imports would diverge the source from what the bundle installer ships.

    So the harness injects the same names into `builtins` before import.
    Registering them only in `sys.modules` is not enough: nothing in the
    script imports those modules, and the module-level
    `demisto.debug(...)` pack-version header executes at import time.
    """
    demisto_mock = types.SimpleNamespace()
    demisto_mock._context = {}
    demisto_mock._args = {}
    demisto_mock._incidents = [{"id": "100"}]
    demisto_mock._results = []
    demisto_mock._commands = []
    demisto_mock._command_responses = {}

    def _get(data, path, default=None):
        if data is None or path in (None, ""):
            return default

        cur = data
        for part in str(path).split("."):
            if isinstance(cur, dict):
                cur = cur.get(part, default)
            else:
                return default
        return cur

    def _set_context(key, value):
        parts = key.split(".")
        cur = demisto_mock._context
        for part in parts[:-1]:
            if part not in cur or not isinstance(cur[part], dict):
                cur[part] = {}
            cur = cur[part]
        cur[parts[-1]] = value

    def _execute_command(command, args):
        demisto_mock._commands.append((command, args))
        response = demisto_mock._command_responses.get(command)
        if callable(response):
            return response(args)
        return response if response is not None else []

    demisto_mock.args = lambda: demisto_mock._args
    demisto_mock.context = lambda: demisto_mock._context
    demisto_mock.setContext = _set_context
    demisto_mock.get = _get
    demisto_mock.executeCommand = _execute_command
    demisto_mock.incidents = lambda: demisto_mock._incidents
    demisto_mock.results = lambda x: demisto_mock._results.append(x)
    demisto_mock.debug = lambda x: None

    sys.modules["demistomock"] = demisto_mock

    common = types.ModuleType("CommonServerPython")

    class EntryType:
        NOTE = 1
        ERROR = 4
        WARNING = 11

    def return_results(value):
        demisto_mock._results.append(value)

    def return_error(message):
        raise RuntimeError(message)

    def return_warning(message, exit=False, **kwargs):
        # Mirrors CommonServerPython: non-terminal by default. The wrapper's
        # degraded-mode path relies on this NOT raising, so the playbook can
        # continue after a soft-failed vendor command.
        demisto_mock._results.append({"Type": EntryType.WARNING, "Contents": message})
        if exit:
            raise RuntimeError(message)

    class CommandResults:
        def __init__(self, readable_output=None, outputs_prefix=None,
                     outputs=None, **kwargs):
            self.readable_output = readable_output
            self.outputs_prefix = outputs_prefix
            self.outputs = outputs

    def register_module_line(*args, **kwargs):
        return None

    def __line__():
        return 0

    class EntryFormat:
        JSON = "json"

    common.EntryType = EntryType
    common.EntryFormat = EntryFormat
    common.entryTypes = {"error": 4}
    common.return_results = return_results
    common.return_error = return_error
    common.return_warning = return_warning
    common.CommandResults = CommandResults
    common.register_module_line = register_module_line
    common.__line__ = __line__

    sys.modules["CommonServerPython"] = common

    # Inject the platform-ambient globals. This is the load-bearing part —
    # the script resolves these off builtins, not off an import.
    builtins.demisto = demisto_mock
    builtins.EntryType = EntryType
    builtins.EntryFormat = EntryFormat
    builtins.entryTypes = {"error": 4}
    builtins.return_results = return_results
    builtins.return_error = return_error
    builtins.return_warning = return_warning
    builtins.CommandResults = CommandResults
    builtins.register_module_line = register_module_line

    if SCRIPT_MODULE_NAME in sys.modules:
        del sys.modules[SCRIPT_MODULE_NAME]

    module = importlib.import_module(SCRIPT_MODULE_NAME)
    return module, demisto_mock


def test_parse_tags_from_comma_string():
    script, _ = load_script()

    result = script.parse_tags("one, two,three")

    assert result == ["one", "two", "three"]


def test_parse_tags_from_json_list_string():
    script, _ = load_script()

    result = script.parse_tags('["alpha", "beta"]')

    assert result == ["alpha", "beta"]


def test_normalize_action_actor_shadow_mode_defaults_to_shadow():
    script, _ = load_script()

    assert script.normalize_action_actor("", True) == "shadow"
    assert script.normalize_action_actor("analyst", True) == "shadow"


def test_resolve_templates_resolves_context_paths():
    script, demisto = load_script()

    ctx = {
        "SOCFramework": {
            "Artifacts": {
                "EndpointID": "abc-123"
            }
        },
        "incident": {
            "id": "42"
        }
    }

    obj = {
        "endpoint_id": "SOCFramework.Artifacts.EndpointID",
        "incident_id": "${incident.id}",
        "static": "hello"
    }

    result = script._resolve_templates(obj, ctx)

    assert result == {
        "endpoint_id": "abc-123",
        "incident_id": "42",
        "static": "hello"
    }


def test_get_or_create_run_id_reuses_existing():
    script, demisto = load_script()

    demisto._context = {
        "SOCFramework": {
            "RunID": "existing-run-id"
        }
    }

    result = script.get_or_create_run_id(demisto._context)

    assert result == "existing-run-id"


def test_append_context_appends_to_existing_list():
    script, demisto = load_script()

    demisto._context = {
        "WrapperResults": [
            {"run_id": "1"}
        ]
    }

    script.append_context("WrapperResults", {"run_id": "2"})

    assert demisto._context["WrapperResults"] == [
        {"run_id": "1"},
        {"run_id": "2"}
    ]


def test_integration_failed_detects_error_entry():
    script, _ = load_script()

    failed, error_msg = script.integration_failed([
        {"Type": 4, "Contents": "boom"}
    ])

    assert failed is True
    assert error_msg == "boom"


def test_main_shadow_mode_success():
    script, demisto = load_script()

    demisto._args = {
        "action": "isolate-endpoint",
        "list_name": "SOCFrameworkActions",
        "output_key": "WrapperResults",
        "shadow_mode": "true",
        "tags": '["tag1","tag2"]',
        "LifeCycle": "NISTIR",
        "Phase": "Containment",
        "Action_Actor": "analyst"
    }

    demisto._context = {
        "SOCFramework": {
            "Product": {
                "response": "CrowdStrikeFalcon"
            },
            "lifecycle": "NISTIR",
            "phase": "Containment"
        },
        "issue": {
            "id": "100",
            "name": "Test Incident"
        }
    }

    def get_list_response(args):
        if args["listName"] == "SOCFrameworkActions":
            return [{
                "Contents": json.dumps({
                    "isolate-endpoint": {
                        "shadow_mode": True,
                        "responses": {
                            "CrowdStrikeFalcon": {
                                "command": "cs-falcon-contain-host",
                                "inline_args": {
                                    "ids": "SOCFramework.Artifacts.EndpointID"
                                }
                            }
                        }
                    }
                })
            }]
        if args["listName"] in (
                "SOCFrameworkSchema_NISTIR",
                "SOCFrameworkSchema",
                "SOCFrameworkExecutionSchema"
        ):
            return [{"Contents": "[]"}]
        return [{"Contents": ""}]

    def execute_router(args):
        return get_list_response(args)

    demisto._command_responses = {
        "getList": execute_router,
        "getIssues": [{
            "Contents": {
                "data": [
                    {
                        "id": "100",
                        "name": "Test Incident",
                        "severity": "high"
                    }
                ]
            }
        }],
        "xql-post-to-dataset": [{"Type": 1, "Contents": "ok"}]
    }

    demisto._context["SOCFramework"]["Artifacts"] = {"EndpointID": "endpoint-123"}

    script.main()

    assert demisto._results[-1] == "Shadow Mode: command not executed"
    assert demisto._context["WrapperResults"][0]["shadow_mode"] is True
    assert demisto._context["WrapperResults"][0]["command"] == "cs-falcon-contain-host"

    command_names = [c[0] for c in demisto._commands]
    assert "xql-post-to-dataset" in command_names
    assert "cs-falcon-contain-host" not in command_names


def test_main_production_success():
    script, demisto = load_script()

    demisto._args = {
        "action": "unisolate-endpoint",
        "list_name": "SOCFrameworkActions",
        "output_key": "WrapperResults",
        "shadow_mode": "false",
        "tags": "prod",
        "Action_Actor": "automation"
    }

    demisto._context = {
        "SOCFramework": {
            "Product": {
                "response": "CrowdStrikeFalcon"
            }
        }
    }

    def get_list_response(args):
        if args["listName"] == "SOCFrameworkActions":
            return [{
                "Contents": json.dumps({
                    "unisolate-endpoint": {
                        "responses": {
                            "CrowdStrikeFalcon": {
                                "command": "cs-falcon-lift-containment",
                                "inline_args": {
                                    "ids": "endpoint-456"
                                }
                            }
                        }
                    }
                })
            }]
        return [{"Contents": "[]"}]

    demisto._command_responses = {
        "getList": get_list_response,
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "cs-falcon-lift-containment": [{"Type": 1, "Contents": "ok"}],
        "xql-post-to-dataset": [{"Type": 1, "Contents": "ok"}]
    }

    script.main()

    assert demisto._context["WrapperResults"][0]["success"] is True
    assert demisto._context["WrapperResults"][0]["command"] == "cs-falcon-lift-containment"

    executed = [c[0] for c in demisto._commands]
    assert "cs-falcon-lift-containment" in executed
    assert "xql-post-to-dataset" in executed

    last_result = demisto._results[-1]
    assert isinstance(last_result, list)
    assert last_result[0]["Contents"] == "ok"


def test_main_production_failure_returns_error():
    script, demisto = load_script()

    demisto._args = {
        "action": "delete-file",
        "list_name": "SOCFrameworkActions",
        "output_key": "WrapperResults"
    }

    demisto._context = {
        "SOCFramework": {
            "Product": {
                "response": "CrowdStrikeFalcon"
            }
        }
    }

    def get_list_response(args):
        if args["listName"] == "SOCFrameworkActions":
            return [{
                "Contents": json.dumps({
                    "delete-file": {
                        "responses": {
                            "CrowdStrikeFalcon": {
                                "command": "cs-falcon-delete-file",
                                "inline_args": {
                                    "sha256": "abc"
                                }
                            }
                        }
                    }
                })
            }]
        return [{"Contents": "[]"}]

    demisto._command_responses = {
        "getList": get_list_response,
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "cs-falcon-delete-file": [{"Type": 4, "Contents": "deletion failed"}],
        "xql-post-to-dataset": [{"Type": 1, "Contents": "ok"}]
    }

    with pytest.raises(RuntimeError, match="deletion failed"):
        script.main()

    assert demisto._context["WrapperResults"][0]["success"] is False
    assert demisto._context["WrapperResults"][0]["error"] == "deletion failed"


def test_main_production_rate_limited_soft_fails():
    """
    Reproduces the Proofpoint TAP 429 that halted EP_IR_NIST (800-61)_V3.

    A transient vendor API refusal must NOT kill the lifecycle. The wrapper
    should record the failure (context record + dataset row), null the UC.*
    output keys so downstream conditions evaluate cleanly, and return —
    letting Containment/Eradication/Recovery still run.

    RED until the failure gate at SOCCommandWrapper.py:895 is widened beyond
    error 23 (integration_unavailable).
    """
    script, demisto = load_script()

    demisto._args = {
        "action": "soc-get-email-forensics",
        "list_name": "SOCFrameworkActions_V3",
        "output_key": "SOCFramework.Execution",
        "Phase": "Analysis",
        "LifeCycle": "NIST_IR",
        "Action_Actor": "automation",
    }

    demisto._context = {
        "SOCFramework": {"Product": {"response": "Proofpoint TAP v2"}}
    }

    def get_list_response(args):
        if args["listName"] == "SOCFrameworkActions_V3":
            return [{
                "Contents": json.dumps({
                    "soc-get-email-forensics": {
                        "shadow_mode": False,
                        "responses": {
                            "Proofpoint TAP v2": {
                                "command": "proofpoint-get-forensics",
                                "inline_args": {"threatId": "abc123"},
                                "output_map": {
                                    "UC.Email.Forensics.behavior":
                                        "Proofpoint.Report.Behavior"
                                },
                            }
                        },
                    }
                })
            }]
        return [{"Contents": "[]"}]

    # Verbatim shape of the observed TAP failure entry.
    tap_429 = (
        "Failed to execute proofpoint-get-forensics command. "
        "Error in API call to Proofpoint TAP 429. "
        "Reason: <html><h2>HTTP ERROR 429 Too Many Requests</h2></html>"
    )

    demisto._command_responses = {
        "getList": get_list_response,
        "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
        "proofpoint-get-forensics": [{"Type": 4, "Contents": tap_429}],
        "xql-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
    }

    # Must not raise / must not sys.exit — the lifecycle continues.
    script.main()

    record = demisto._context["SOCFramework"]["Execution"][0]
    assert record["success"] is False
    assert "429" in record["error"]

    # UC.* nulled so downstream conditions take the default path
    # rather than erroring on a missing key.
    assert demisto._context["UC"]["Email"]["Forensics"]["behavior"] is None

    # Telemetry still lands.
    posted = [
        json.loads(a["JSON"])
        for c, a in demisto._commands
        if c == "xql-post-to-dataset"
    ]
    assert posted, "no dataset row posted for the failed command"
    assert posted[0]["has_error"] is True
    assert posted[0]["action_status"] != "success"


def test_main_missing_action_raises_error():
    script, demisto = load_script()

    demisto._args = {
        "list_name": "SOCFrameworkActions"
    }

    with pytest.raises(RuntimeError, match="Missing action"):
        script.main()


def test_main_invalid_action_list_json_raises_error():
    script, demisto = load_script()

    demisto._args = {
        "action": "contain",
        "list_name": "SOCFrameworkActions"
    }

    demisto._command_responses = {
        "getList": [{"Contents": "{bad json"}]
    }

    with pytest.raises(RuntimeError, match="Invalid JSON in action list"):
        script.main()
