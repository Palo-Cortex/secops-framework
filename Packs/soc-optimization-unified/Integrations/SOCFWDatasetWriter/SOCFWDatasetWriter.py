import demistomock as demisto  # type: ignore
from CommonServerPython import *  # type: ignore

import json
import ssl
import urllib.request
import urllib.error

OK_STATUSES = (200, 201, 204)


def get_api_key(params: dict) -> str:
    """Type 4 credential params return either a plain string or {'password': '...'}."""
    val = params.get("api_key", "")
    if isinstance(val, dict):
        return val.get("password", "")
    return str(val or "").strip()


def build_headers(api_key: str, vendor: str, product: str) -> dict:
    """Vendor and product headers control which dataset the collector routes to.
    When empty, the collector's own configured defaults apply."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": api_key,
        "format": "json",
    }
    if vendor:
        headers["vendor"] = vendor
    if product:
        headers["product"] = product
    return headers


def normalize_events(raw) -> list:
    """Accept a JSON array, a single JSON object, or NDJSON text."""
    if isinstance(raw, (list, dict)):
        return raw if isinstance(raw, list) else [raw]
    text = str(raw or "").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return parsed
    raise ValueError("JSON must be an object or an array of objects.")


def post_events(url: str, headers: dict, events: list, insecure: bool = False) -> int:
    """POST events to the HTTP Collector as NDJSON."""
    body = "\n".join(json.dumps(e) for e in events).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    context = None
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=30, context=context) as resp:
        return resp.getcode()


def test_module_command(params: dict) -> str:
    url = (params.get("url") or "").strip()
    api_key = get_api_key(params)
    if not url:
        return "Configuration error: HTTP Collector URL is required."
    if not api_key:
        return "Configuration error: API Key is required."

    headers = build_headers(api_key, (params.get("vendor") or "").strip(),
                            (params.get("product") or "").strip())
    probe = [{"_time": "2020-01-01T00:00:00.000Z", "socfw_connectivity_test": True}]
    try:
        status = post_events(url, headers, probe, argToBoolean(params.get("insecure", False)))
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code} from collector - check the URL and API key."
    except Exception as e:
        return f"Could not reach the collector: {e}"

    if status not in OK_STATUSES:
        return f"HTTP {status} from collector - check the URL and API key."
    return "ok"


def post_to_dataset_command(params: dict, args: dict) -> CommandResults:
    url = (params.get("url") or "").strip()
    api_key = get_api_key(params)
    events = normalize_events(args.get("JSON"))
    if not events:
        return CommandResults(readable_output="No events to send.")

    headers = build_headers(api_key, (params.get("vendor") or "").strip(),
                            (params.get("product") or "").strip())
    status = post_events(url, headers, events, argToBoolean(params.get("insecure", False)))
    if status not in OK_STATUSES:
        raise ValueError(f"HTTP {status} from collector")
    return CommandResults(readable_output=f"Posted {len(events)} event(s) to the HTTP Collector.")


def main():
    params = demisto.params()
    command = demisto.command()
    if argToBoolean(params.get("proxy", False)):
        handle_proxy()
    try:
        if command == "test-module":
            return_results(test_module_command(params))
        elif command == "socfw-post-to-dataset":
            return_results(post_to_dataset_command(params, demisto.args()))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command}. Error: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
