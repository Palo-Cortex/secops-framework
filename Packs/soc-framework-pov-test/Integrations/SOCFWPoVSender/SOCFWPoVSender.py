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



# Seed schemas — fields each correlation rule references.
# test-module sends one event with these fields to create the dataset
# and populate its schema so correlation rules install without 101704.
_SEED_SCHEMAS = {
    "crowdstrike": {
        "_time": "2020-01-01T00:00:00.000Z",
        "_name": "schema_seed", "name": "schema_seed",
        "scenario": "seed", "confidence": 0, "severity": 0,
        "severity_name": "Informational", "agent_id": "SEED",
        "hostname": "SEED", "local_ip": "10.0.0.1",
        "external_ip": "192.0.2.1", "platform": "Windows",
        "os_version": "Windows 10", "machine_domain": "seed.local",
        "site_name": "Default", "agent_version": "0.0.0",
        "filename": "seed.exe", "filepath": "C:\\seed.exe",
        "cmdline": "seed.exe", "sha256": "0" * 64, "md5": "0" * 32,
        "parent_filename": "explorer.exe", "parent_cmdline": "explorer.exe",
        "grandparent_filename": "userinit.exe", "grandparent_cmdline": "userinit.exe",
        "tactic": "None", "tactic_id": "TA0000",
        "technique": "None", "technique_id": "T0000",
        "ioc_type": "", "ioc_value": "", "ioc_source": "",
        "pattern_disposition": "none",
        "pattern_disposition_description": "seed",
        "files_written": "[]", "dns_requests": "[]",
        "network_accesses": "[]", "user_name": "seed_user",
    },
    "proofpoint": {
        "_time": "2020-01-01T00:00:00.000Z",
        "type": "messages delivered", "GUID": "SEED-0000", "id": "SEED-0000",
        "messageID": "<seed@seed.local>", "sender": "seed@seed.local",
        "senderIP": "192.0.2.1", "recipient": "seed@seed.local",
        "subject": "seed", "headerFrom": "seed@seed.local",
        "headerReplyTo": "", "replyToAddress": "",
        "campaignId": "seed", "threatStatus": "cleared",
        "threatTime": "2020-01-01T00:00:00.000Z",
        "threatsInfoMap": "[]", "messageParts": "[]",
        "phishScore": 0, "spamScore": 0, "malwareScore": 0,
        "impostorScore": 0, "messageSize": 100,
        "messageTime": "2020-01-01T00:00:00.000Z",
        "policyRoutes": "[]", "modulesRun": "[]",
        "QID": "SEED-0000", "toAddresses": "", "ccAddresses": "",
        "completelyRewritten": False,
    },
    "defender": {
        "_time": "2020-01-01T00:00:00.000Z",
        "providerAlertId": "SEED-0000", "id": "SEED-0000",
        "incidentId": "0", "title": "seed", "severity": "informational",
        "status": "new", "category": "seed",
        "hostName": "SEED", "fileName": "seed.exe",
        "sha256": "0" * 64, "accountName": "seed_user",
        "domainName": "seed.local",
    },
}


def test_module_command(params: dict) -> str:
    url     = (params.get("url") or "").strip().rstrip("/")
    api_key = _get_api_key(params)
    source  = (params.get("source_name") or "").strip().lower()
    vendor  = (params.get("vendor") or "").strip()
    product = (params.get("product") or "").strip()

    if not url:
        return "Configuration error: HTTP Collector URL is required."
    if not api_key:
        return "Configuration error: API Key is required."
    if not source:
        return "Configuration error: Source Name is required (e.g. crowdstrike or proofpoint)."

    # Send a seed event to create the dataset and populate its schema.
    # Uses a 2020 timestamp so it never triggers correlation rules.
    seed_event = _SEED_SCHEMAS.get(source)
    if not seed_event:
        return f"Configuration error: Unknown source '{source}'. Known: {list(_SEED_SCHEMAS.keys())}"

    body = json.dumps(seed_event).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": api_key,
        "format": "json",
    }
    if vendor:
        headers["vendor"] = vendor
    if product:
        headers["product"] = product

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status = resp.getcode()
            if status not in (200, 201, 204):
                return f"HTTP {status} from collector — check URL and API key."
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code} from collector: {e.reason}"
    except urllib.error.URLError as e:
        return f"Connection failed: {e.reason}"

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
        "format": "json",
    }

    # Add vendor/product headers if configured — controls dataset routing
    vendor  = (params.get("vendor") or "").strip()
    product = (params.get("product") or "").strip()
    if vendor:
        headers["vendor"] = vendor
    if product:
        headers["product"] = product

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
