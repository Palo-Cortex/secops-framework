import sys
import types
import json
import pytest

# ---- Mock XSOAR runtime modules before importing the script ----

demisto_mock = types.SimpleNamespace()
demisto_mock.params = lambda: {}
demisto_mock.args = lambda: {}
demisto_mock.command = lambda: "test-module"
demisto_mock.debug = lambda x: None

sys.modules["demistomock"] = demisto_mock

common = types.ModuleType("CommonServerPython")


def return_results(x):
    return x


def return_error(message):
    raise RuntimeError(message)


def send_events_to_xsiam(events, vendor=None, product=None):
    return {"events": events, "vendor": vendor, "product": product}


common.return_results = return_results
common.return_error = return_error
common.send_events_to_xsiam = send_events_to_xsiam

sys.modules["CommonServerPython"] = common

import SystemXQLHTTPCollector as script


def test_test_module_command_returns_ok():
    result = script.test_module_command()
    assert result == "ok"


def test_main_test_module_calls_return_results(mocker):
    mocker.patch.object(script.demisto, "params", return_value={})
    mocker.patch.object(script.demisto, "args", return_value={})
    mocker.patch.object(script.demisto, "command", return_value="test-module")
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once_with("ok")


def test_main_xql_post_to_dataset_uses_args_vendor_and_product(mocker):
    mocker.patch.object(script.demisto, "params", return_value={
        "vendor": "ParamVendor",
        "product": "ParamProduct"
    })
    mocker.patch.object(script.demisto, "args", return_value={
        "vendor": "ArgVendor",
        "JSON": json.dumps({
            "message": "test-event"
        })
    })
    mocker.patch.object(script.demisto, "command", return_value="xql-post-to-dataset")

    send_mock = mocker.patch.object(script, "send_events_to_xsiam")
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    send_mock.assert_called_once_with(
        [{"message": "test-event"}],
        vendor="ArgVendor",
        product="ParamProduct"
    )
    return_results_mock.assert_not_called()


def test_main_xql_post_to_dataset_uses_params_when_args_missing(mocker):
    mocker.patch.object(script.demisto, "params", return_value={
        "vendor": "Trend Micro",
        "product": "Vision One"
    })
    mocker.patch.object(script.demisto, "args", return_value={
        "JSON": json.dumps({
            "id": "evt-1"
        })
    })
    mocker.patch.object(script.demisto, "command", return_value="xql-post-to-dataset")

    send_mock = mocker.patch.object(script, "send_events_to_xsiam")

    script.main()

    send_mock.assert_called_once_with(
        [{"id": "evt-1"}],
        vendor="Trend Micro",
        product="Vision One"
    )


def test_main_xql_post_to_dataset_wraps_single_event_in_list(mocker):
    mocker.patch.object(script.demisto, "params", return_value={})
    mocker.patch.object(script.demisto, "args", return_value={
        "vendor": "CrowdStrike",
        "product": "Falcon",
        "JSON": json.dumps({
            "event_type": "alert"
        })
    })
    mocker.patch.object(script.demisto, "command", return_value="xql-post-to-dataset")

    send_mock = mocker.patch.object(script, "send_events_to_xsiam")

    script.main()

    send_mock.assert_called_once_with(
        [{"event_type": "alert"}],
        vendor="CrowdStrike",
        product="Falcon"
    )


def test_main_xql_post_to_dataset_keeps_list_as_list(mocker):
    mocker.patch.object(script.demisto, "params", return_value={})
    mocker.patch.object(script.demisto, "args", return_value={
        "vendor": "CrowdStrike",
        "product": "Falcon",
        "JSON": json.dumps([
            {"id": "1"},
            {"id": "2"}
        ])
    })
    mocker.patch.object(script.demisto, "command", return_value="xql-post-to-dataset")

    send_mock = mocker.patch.object(script, "send_events_to_xsiam")

    script.main()

    send_mock.assert_called_once_with(
        [{"id": "1"}, {"id": "2"}],
        vendor="CrowdStrike",
        product="Falcon"
    )


def test_main_returns_error_on_invalid_json(mocker):
    mocker.patch.object(script.demisto, "params", return_value={})
    mocker.patch.object(script.demisto, "args", return_value={
        "vendor": "CrowdStrike",
        "product": "Falcon",
        "JSON": "{not-valid-json}"
    })
    mocker.patch.object(script.demisto, "command", return_value="xql-post-to-dataset")

    with pytest.raises(RuntimeError, match="Failed to execute xql-post-to-dataset command"):
        script.main()


def test_main_returns_error_when_send_events_fails(mocker):
    mocker.patch.object(script.demisto, "params", return_value={})
    mocker.patch.object(script.demisto, "args", return_value={
        "vendor": "CrowdStrike",
        "product": "Falcon",
        "JSON": json.dumps({"id": "1"})
    })
    mocker.patch.object(script.demisto, "command", return_value="xql-post-to-dataset")
    mocker.patch.object(script, "send_events_to_xsiam", side_effect=Exception("upload failed"))

    with pytest.raises(RuntimeError, match="upload failed"):
        script.main()