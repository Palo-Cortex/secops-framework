import demistomock as demisto  # type: ignore
from CommonServerPython import *  # type: ignore

import json
import urllib.request
import urllib.error


def _get_api_key(params: dict) -> str:
    """Type 4 credential params return either a plain string or {'password': '...'}."""
    val = params.get("api_key", "")
    if isinstance(val, dict):
        return val.get("password", "")
    return str(val or "").strip()


def test_module_command(params: dict) -> str:
    url     = (params.get("url") or "").strip()
    api_key = _get_api_key(params)
    source  = (params.get("source_name") or "").strip()
    if not url:
        return "Configuration error: HTTP Collector URL is required."
    if not api_key:
        return "Configuration error: API Key is required."
    if not source:
        return "Configuration error: Source Name is required (e.g. crowdstrike or proofpoint)."
    return "ok"


def send_data_command(params: dict, args: dict) -> CommandResults:
    """
    Receives pre-processed events as a JSON string from SOCFWPoVSend script
    and POSTs to the configured HTTP Collector endpoint as NDJSON.
    All normalization and timestamp rebasing is done in the script layer.
    """
    url     = (params.get("url") or "").rstrip("/")
    api_key = _get_api_key(params)

    json_arg = args.get("JSON", "")
    if not json_arg:
        raise ValueError("JSON argument is required.")

    events = json.loads(json_arg)
    if not isinstance(events, list):
        events = [events]

    if not events:
        return CommandResults(readable_output="No events to send.")

    # XSIAM HTTP Collector expects newline-delimited JSON (NDJSON)
    body = "\n".join(json.dumps(ev) for ev in events).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": api_key,
    }

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status = resp.getcode()
            if status not in (200, 204):
                raise ValueError(f"HTTP {status} from collector")
    except urllib.error.HTTPError as e:
        raise ValueError(f"HTTP {e.code} from collector: {e.reason}")
    except urllib.error.URLError as e:
        raise ValueError(f"URL error: {e.reason}")

    return CommandResults(
        readable_output=f"SOCFWPoVSender: {len(events)} events sent to {url}"
    )


def main() -> None:
    params  = demisto.params()
    command = demisto.command()
    args    = demisto.args()

    demisto.debug(f"SOCFWPoVSender: command={command}")

    try:
        if command == "test-module":
            return_results(test_module_command(params))
        elif command == "socfw-pov-send-data":
            return_results(send_data_command(params, args))
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")
    except Exception as e:
        return_error(f"SOCFWPoVSender error [{command}]: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
