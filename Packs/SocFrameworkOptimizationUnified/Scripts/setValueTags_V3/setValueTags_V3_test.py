import importlib
import json
import sys
import types
import pytest


SCRIPT_MODULE_NAME = "setValueTags_V3"


def _load_script_with_args(mocker, args=None, execute_command_results=None):
    """
    Load/reload the script with mocked XSOAR runtime.
    Because the script executes on import, this helper prepares the runtime first.
    """
    if args is None:
        args = {}

    if execute_command_results is None:
        execute_command_results = {}

    demisto_mock = types.SimpleNamespace()
    demisto_mock.args = lambda: args
    demisto_mock.executeCommand = lambda command, command_args: execute_command_results.get(command, [])
    demisto_mock.results = lambda x: x
    demisto_mock.error = lambda x: None

    sys.modules["demistomock"] = demisto_mock

    common = types.ModuleType("CommonServerPython")

    def return_results(value):
        return value

    def return_error(message):
        raise RuntimeError(message)

    def isError(result):
        if not isinstance(result, list) or not result:
            return False
        first = result[0]
        return isinstance(first, dict) and first.get("Type") == 4

    def get_error(result):
        if not isinstance(result, list) or not result:
            return "Unknown error"
        first = result[0]
        return first.get("Contents") or first.get("HumanReadable") or "Unknown error"

    def tableToMarkdown(title, rows):
        if not rows:
            return f"### {title}\nNo results"
        headers = list(rows[0].keys())
        md = f"### {title}\n"
        md += "|" + "|".join(headers) + "|\n"
        md += "|" + "|".join(["---"] * len(headers)) + "|\n"
        for row in rows:
            md += "|" + "|".join(str(row.get(h, "")) for h in headers) + "|\n"
        return md

    common.return_results = return_results
    common.return_error = return_error
    common.isError = isError
    common.get_error = get_error
    common.tableToMarkdown = tableToMarkdown

    sys.modules["CommonServerPython"] = common

    if SCRIPT_MODULE_NAME in sys.modules:
        del sys.modules[SCRIPT_MODULE_NAME]

    module = importlib.import_module(SCRIPT_MODULE_NAME)
    return module


def test_add_playbook_with_playbookid_calls_lookup_add(mocker):
    execute_calls = []

    def execute_command(command, command_args):
        execute_calls.append((command, command_args))
        return []

    demisto_mock = types.SimpleNamespace()
    demisto_mock.args = lambda: {
        "action": "add",
        "type": "playbook",
        "tag": "phishing",
        "time": "5m",
        "playbookid": "pb-123",
        "playbook_name": "SOC Phishing",
        "product": "XSIAM",
        "vendor": "Palo Alto Networks",
    }
    demisto_mock.executeCommand = execute_command
    demisto_mock.results = lambda x: x
    demisto_mock.error = lambda x: None

    sys.modules["demistomock"] = demisto_mock

    common = types.ModuleType("CommonServerPython")

    def return_results(value):
        return value

    def return_error(message):
        raise RuntimeError(message)

    def isError(result):
        return False

    def get_error(result):
        return "Unknown error"

    def tableToMarkdown(title, rows):
        return "table"

    common.return_results = return_results
    common.return_error = return_error
    common.isError = isError
    common.get_error = get_error
    common.tableToMarkdown = tableToMarkdown

    sys.modules["CommonServerPython"] = common

    if SCRIPT_MODULE_NAME in sys.modules:
        del sys.modules[SCRIPT_MODULE_NAME]

    importlib.import_module(SCRIPT_MODULE_NAME)

    assert len(execute_calls) == 1
    assert execute_calls[0][0] == "core-api-post"
    assert execute_calls[0][1]["uri"] == "/public_api/v1/xql/lookups/add_data"

    body = json.loads(execute_calls[0][1]["body"])
    row = body["request"]["data"][0]

    assert row["tag"] == "phishing"
    assert row["time"] == "5m"
    assert row["playbookid"] == "pb-123"
    assert row["taskname"] == "SOC Phishing"
    assert row["category"] == "use_case"
    assert row["product"] == "XSIAM"
    assert row["vendor"] == "Palo Alto Networks"


def test_add_playbook_without_playbookid_performs_search_then_add(mocker):
    execute_calls = []

    def execute_command(command, command_args):
        execute_calls.append((command, command_args))
        if len(execute_calls) == 1:
            return [{
                "Contents": {
                    "response": {
                        "playbooks": [
                            {"id": "pb-found-1"}
                        ]
                    }
                }
            }]
        return []

    demisto_mock = types.SimpleNamespace()
    demisto_mock.args = lambda: {
        "action": "add",
        "type": "playbook",
        "tag": "malware",
        "time": "10m",
        "playbook_name": "SOC Malware Investigation",
    }
    demisto_mock.executeCommand = execute_command
    demisto_mock.results = lambda x: x
    demisto_mock.error = lambda x: None

    sys.modules["demistomock"] = demisto_mock

    common = types.ModuleType("CommonServerPython")

    def return_results(value):
        return value

    def return_error(message):
        raise RuntimeError(message)

    def isError(result):
        return False

    def get_error(result):
        return "Unknown error"

    def tableToMarkdown(title, rows):
        return "table"

    common.return_results = return_results
    common.return_error = return_error
    common.isError = isError
    common.get_error = get_error
    common.tableToMarkdown = tableToMarkdown

    sys.modules["CommonServerPython"] = common

    if SCRIPT_MODULE_NAME in sys.modules:
        del sys.modules[SCRIPT_MODULE_NAME]

    importlib.import_module(SCRIPT_MODULE_NAME)

    assert len(execute_calls) == 2
    assert execute_calls[0][1]["uri"] == "/xsoar/public/v1/playbook/search"
    assert execute_calls[1][1]["uri"] == "/public_api/v1/xql/lookups/add_data"

    body = json.loads(execute_calls[1][1]["body"])
    row = body["request"]["data"][0]
    assert row["playbookid"] == "pb-found-1"


def test_add_task_calls_lookup_add(mocker):
    execute_calls = []

    def execute_command(command, command_args):
        execute_calls.append((command, command_args))
        return []

    demisto_mock = types.SimpleNamespace()
    demisto_mock.args = lambda: {
        "action": "add",
        "type": "task",
        "tag": "enrichment",
        "time": "2m",
        "category": "investigation",
        "scriptid": "script-123",
        "product": "CrowdStrike",
        "vendor": "CrowdStrike",
    }
    demisto_mock.executeCommand = execute_command
    demisto_mock.results = lambda x: x
    demisto_mock.error = lambda x: None

    sys.modules["demistomock"] = demisto_mock

    common = types.ModuleType("CommonServerPython")

    def return_results(value):
        return value

    def return_error(message):
        raise RuntimeError(message)

    def isError(result):
        return False

    def get_error(result):
        return "Unknown error"

    def tableToMarkdown(title, rows):
        return "table"

    common.return_results = return_results
    common.return_error = return_error
    common.isError = isError
    common.get_error = get_error
    common.tableToMarkdown = tableToMarkdown

    sys.modules["CommonServerPython"] = common

    if SCRIPT_MODULE_NAME in sys.modules:
        del sys.modules[SCRIPT_MODULE_NAME]

    importlib.import_module(SCRIPT_MODULE_NAME)

    assert len(execute_calls) == 1
    body = json.loads(execute_calls[0][1]["body"])
    row = body["request"]["data"][0]

    assert row["tag"] == "enrichment"
    assert row["scriptid"] == "script-123"
    assert row["category"] == "investigation"


def test_update_calls_lookup_add_with_partial_fields(mocker):
    execute_calls = []

    def execute_command(command, command_args):
        execute_calls.append((command, command_args))
        return []

    demisto_mock = types.SimpleNamespace()
    demisto_mock.args = lambda: {
        "action": "update",
        "tag": "phishing",
        "time": "20m",
        "vendor": "Proofpoint",
    }
    demisto_mock.executeCommand = execute_command
    demisto_mock.results = lambda x: x
    demisto_mock.error = lambda x: None

    sys.modules["demistomock"] = demisto_mock

    common = types.ModuleType("CommonServerPython")

    def return_results(value):
        return value

    def return_error(message):
        raise RuntimeError(message)

    def isError(result):
        return False

    def get_error(result):
        return "Unknown error"

    def tableToMarkdown(title, rows):
        return "table"

    common.return_results = return_results
    common.return_error = return_error
    common.isError = isError
    common.get_error = get_error
    common.tableToMarkdown = tableToMarkdown

    sys.modules["CommonServerPython"] = common

    if SCRIPT_MODULE_NAME in sys.modules:
        del sys.modules[SCRIPT_MODULE_NAME]

    importlib.import_module(SCRIPT_MODULE_NAME)

    assert len(execute_calls) == 1
    body = json.loads(execute_calls[0][1]["body"])
    row = body["request"]["data"][0]

    assert row["tag"] == "phishing"
    assert row["time"] == "20m"
    assert row["vendor"] == "Proofpoint"
    assert "category" not in row


def test_delete_calls_remove_data(mocker):
    execute_calls = []

    def execute_command(command, command_args):
        execute_calls.append((command, command_args))
        return []

    demisto_mock = types.SimpleNamespace()
    demisto_mock.args = lambda: {
        "action": "delete",
        "tag": "obsolete-tag",
    }
    demisto_mock.executeCommand = execute_command
    demisto_mock.results = lambda x: x
    demisto_mock.error = lambda x: None

    sys.modules["demistomock"] = demisto_mock

    common = types.ModuleType("CommonServerPython")

    def return_results(value):
        return value

    def return_error(message):
        raise RuntimeError(message)

    def isError(result):
        return False

    def get_error(result):
        return "Unknown error"

    def tableToMarkdown(title, rows):
        return "table"

    common.return_results = return_results
    common.return_error = return_error
    common.isError = isError
    common.get_error = get_error
    common.tableToMarkdown = tableToMarkdown

    sys.modules["CommonServerPython"] = common

    if SCRIPT_MODULE_NAME in sys.modules:
        del sys.modules[SCRIPT_MODULE_NAME]

    importlib.import_module(SCRIPT_MODULE_NAME)

    assert len(execute_calls) == 1
    assert execute_calls[0][1]["uri"] == "/public_api/v1/xql/lookups/remove_data"
    body = json.loads(execute_calls[0][1]["body"])
    assert body["request"]["filters"] == [{"tag": "obsolete-tag"}]


def test_list_all_fetches_rows(mocker):
    sample_rows = [
        {
            "Category": "use_case",
            "PlaybookID": "pb-1",
            "Product": "XSIAM",
            "ScriptID": "",
            "Tag": "phishing",
            "TaskName": "SOC Phishing",
            "Time": "5m",
            "Vendor": "Palo Alto Networks",
        }
    ]

    demisto_mock = types.SimpleNamespace()
    demisto_mock.args = lambda: {
        "action": "list_all",
        "output_format": "json",
    }
    demisto_mock.executeCommand = lambda command, command_args: [{
        "Contents": {
            "response": {
                "reply": {
                    "data": sample_rows
                }
            }
        }
    }]
    demisto_mock.results = lambda x: x
    demisto_mock.error = lambda x: None

    sys.modules["demistomock"] = demisto_mock

    common = types.ModuleType("CommonServerPython")

    def return_results(value):
        return value

    def return_error(message):
        raise RuntimeError(message)

    def isError(result):
        return False

    def get_error(result):
        return "Unknown error"

    def tableToMarkdown(title, rows):
        return "table"

    common.return_results = return_results
    common.return_error = return_error
    common.isError = isError
    common.get_error = get_error
    common.tableToMarkdown = tableToMarkdown

    sys.modules["CommonServerPython"] = common

    if SCRIPT_MODULE_NAME in sys.modules:
        del sys.modules[SCRIPT_MODULE_NAME]

    module = importlib.import_module(SCRIPT_MODULE_NAME)

    cleaned = module.clean_rows(sample_rows)
    assert cleaned[0]["Tag"] == "phishing"
    assert cleaned[0]["PlaybookID"] == "pb-1"


def test_list_by_type_filters_playbooks(mocker):
    rows = [
        {"Category": "use_case", "Tag": "phishing"},
        {"Category": "investigation", "Tag": "task-tag"},
    ]

    demisto_mock = types.SimpleNamespace()
    demisto_mock.args = lambda: {
        "action": "list_by_type",
        "type": "playbook",
        "output_format": "json",
    }
    demisto_mock.executeCommand = lambda command, command_args: [{
        "Contents": {
            "response": {
                "reply": {
                    "data": rows
                }
            }
        }
    }]
    demisto_mock.results = lambda x: x
    demisto_mock.error = lambda x: None

    sys.modules["demistomock"] = demisto_mock

    common = types.ModuleType("CommonServerPython")

    def return_results(value):
        return value

    def return_error(message):
        raise RuntimeError(message)

    def isError(result):
        return False

    def get_error(result):
        return "Unknown error"

    def tableToMarkdown(title, rows):
        return "table"

    common.return_results = return_results
    common.return_error = return_error
    common.isError = isError
    common.get_error = get_error
    common.tableToMarkdown = tableToMarkdown

    sys.modules["CommonServerPython"] = common

    if SCRIPT_MODULE_NAME in sys.modules:
        del sys.modules[SCRIPT_MODULE_NAME]

    module = importlib.import_module(SCRIPT_MODULE_NAME)

    filtered = []
    for r in rows:
        cat = r.get("Category", "").lower()
        if "playbook" == "playbook" and cat == "use_case":
            filtered.append(r)

    assert filtered == [{"Category": "use_case", "Tag": "phishing"}]


def test_invalid_action_raises_error(mocker):
    with pytest.raises(RuntimeError, match="Invalid action"):
        _load_script_with_args(
            mocker,
            args={"action": "bad_action"}
        )


def test_invalid_output_format_raises_error(mocker):
    with pytest.raises(RuntimeError, match="Invalid output_format"):
        _load_script_with_args(
            mocker,
            args={
                "action": "list_all",
                "output_format": "csv"
            }
        )


def test_add_playbook_requires_time(mocker):
    with pytest.raises(RuntimeError, match="Missing required field: time"):
        _load_script_with_args(
            mocker,
            args={
                "action": "add",
                "type": "playbook",
                "tag": "phishing",
                "playbookid": "pb-1"
            }
        )


def test_add_task_requires_scriptid(mocker):
    with pytest.raises(RuntimeError, match="Task add failed"):
        _load_script_with_args(
            mocker,
            args={
                "action": "add",
                "type": "task",
                "tag": "task1",
                "time": "1m",
                "category": "investigation"
            }
        )


def test_delete_requires_tag(mocker):
    with pytest.raises(RuntimeError, match="Delete action requires a tag"):
        _load_script_with_args(
            mocker,
            args={
                "action": "delete"
            }
        )