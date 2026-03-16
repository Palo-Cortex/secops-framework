"""
SOCFWHealthCheck
================
Tenant-side SOC Framework health check automation.
Runs inside XSIAM — no API key, no base URL, no network config required.
Uses demisto.internalHttpRequest() and demisto.executeCommand() throughout.

Checks:
  1. Integration instances  — brands declared vs actually enabled in tenant
  2. Installed playbooks    — expected entry points / jobs present & enabled
  3. Active jobs            — scheduled jobs exist and are not paused / erroring
  4. Datasets & lists       — lookup tables / XSIAM datasets are populated

Output:
  - Structured warroom entry (pass / warn / fail per check)
  - CommandResults table for incident context
  - Optional dataset write for PoV trend tracking

Usage (from incident, layout button, or scheduled job):
  !SOCFWHealthCheck config_list="SOCFWConfig" write_dataset="true"

Author : SOC Framework Team
Pack   : soc-framework-manager
Script : SOCFWHealthCheck
Docker : demisto/python3:3.12.12.6796194
"""

import json
import traceback
from datetime import datetime, timezone
from typing import Any

import demistomock as demisto
from CommonServerPython import *  # noqa: F401,F403


# ─── Constants ────────────────────────────────────────────────────────────────

SCRIPT_NAME = "SOCFWHealthCheck"
SCRIPT_VERSION = "1.0.0"

# Default expected entry-point prefixes — overridable via config list
DEFAULT_ENTRY_POINT_PREFIXES = [
    "EP_NIST_IR",
    "EP_Phishing",
    "EP_SOCFramework",
    "JOB - ",
    "JOB-",
]

# Brands that are always present (platform-native) — never flag as missing
BUILTIN_BRANDS = {
    "Builtin",
    "BuiltIn",
    "built-in",
    "Built-In",
    "Scripts",
}

# XSIAM internal API paths
API_INTEGRATIONS = "/xsoar/public/v1/settings/integration/search"
API_PLAYBOOKS    = "/xsoar/public/v1/playbook/search"
API_JOBS         = "/xsoar/public/v1/jobs"
API_LISTS        = "/xsoar/public/v1/lists/names"
API_XQL_START    = "/public_api/v1/xql/start_xql_query"
API_XQL_RESULT   = "/public_api/v1/xql/get_query_results_iterator"

# Dataset used for PoV trend tracking
HEALTH_DATASET = "socfw_health_checks"


# ─── Status helpers ───────────────────────────────────────────────────────────

STATUS_PASS = "PASS"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"
STATUS_SKIP = "SKIP"

ICONS = {STATUS_PASS: "✅", STATUS_WARN: "⚠️", STATUS_FAIL: "❌", STATUS_SKIP: "⬜"}


def _icon(status: str) -> str:
    return ICONS.get(status, "?")


# ─── Internal HTTP helpers ────────────────────────────────────────────────────

def _api_get(path: str, body: dict | None = None) -> dict:
    """
    Thin wrapper around demisto.internalHttpRequest.
    GET when body is None, POST when body is provided (some XSIAM search
    endpoints use POST with a JSON body even though they are read-only).
    """
    method = "POST" if body is not None else "GET"
    kwargs: dict[str, Any] = {"method": method, "uri": path}
    if body is not None:
        kwargs["body"] = json.dumps(body)
        kwargs["headers"] = {"Content-Type": "application/json"}

    resp = demisto.internalHttpRequest(**kwargs)

    status_code = resp.get("statusCode", 0)
    if status_code not in (200, 201):
        raise RuntimeError(
            f"Internal API {method} {path} returned HTTP {status_code}: "
            f"{resp.get('body', '')[:300]}"
        )

    raw = resp.get("body", "{}")
    return json.loads(raw) if isinstance(raw, str) else raw


# ─── Config loader ────────────────────────────────────────────────────────────

def _load_config(config_list_name: str) -> dict:
    """
    Load SOCFramework config from an XSIAM list (same list SOCFWPackManager uses).
    Falls back to sensible defaults if the list is absent or unparseable.
    """
    try:
        result = demisto.executeCommand("getList", {"listName": config_list_name})
        if is_error(result):
            demisto.debug(f"[{SCRIPT_NAME}] Config list '{config_list_name}' not found — using defaults")
            return {}
        content = result[0].get("Contents", "{}")
        return json.loads(content) if isinstance(content, str) else content
    except Exception as exc:
        demisto.debug(f"[{SCRIPT_NAME}] Config load error: {exc} — using defaults")
        return {}


# ─── Check 1 : Integration instances ─────────────────────────────────────────

def check_integrations(expected_brands: list[str]) -> dict:
    """
    Fetch all enabled integration instances from the tenant.
    Compare against the list of brands that the SOC Framework requires.

    Returns a result dict with status, details list, and raw findings.
    """
    findings: list[dict] = []
    overall = STATUS_PASS

    try:
        data = _api_get(API_INTEGRATIONS, body={"size": 500, "query": ""})
        instances: list[dict] = data.get("instances", [])

        # Build a map: brand → list of instance names that are enabled
        enabled_by_brand: dict[str, list[str]] = {}
        for inst in instances:
            brand = inst.get("brand", "")
            name  = inst.get("name", "")
            enabled = inst.get("enabled", False)
            if brand and enabled:
                enabled_by_brand.setdefault(brand, []).append(name)

        # Check each required brand
        for brand in expected_brands:
            if brand in BUILTIN_BRANDS:
                continue

            matched_names = enabled_by_brand.get(brand, [])

            if not matched_names:
                # Check if it exists but is disabled
                disabled_names = [
                    i.get("name", "") for i in instances
                    if i.get("brand") == brand and not i.get("enabled", False)
                ]
                if disabled_names:
                    status = STATUS_WARN
                    note   = f"Instance(s) exist but DISABLED: {', '.join(disabled_names)}"
                    if overall == STATUS_PASS:
                        overall = STATUS_WARN
                else:
                    status = STATUS_FAIL
                    note   = "No instance found — integration not configured"
                    overall = STATUS_FAIL
            elif len(matched_names) > 1:
                status = STATUS_WARN
                note   = f"Multiple enabled instances: {', '.join(matched_names)} — may cause routing ambiguity"
                if overall == STATUS_PASS:
                    overall = STATUS_WARN
            else:
                status = STATUS_PASS
                note   = f"Instance: {matched_names[0]}"

            findings.append({
                "check":  "Integration",
                "item":   brand,
                "status": status,
                "note":   note,
            })

    except Exception as exc:
        overall = STATUS_FAIL
        findings.append({
            "check":  "Integration",
            "item":   "API call",
            "status": STATUS_FAIL,
            "note":   f"API error: {exc}",
        })

    return {"name": "Integration Instances", "status": overall, "findings": findings}


# ─── Check 2 : Installed playbooks ───────────────────────────────────────────

def check_playbooks(expected_prefixes: list[str]) -> dict:
    """
    Search for playbooks whose names start with any of the expected prefixes.
    Flags missing entry points and disabled playbooks.
    """
    findings: list[dict] = []
    overall = STATUS_PASS

    try:
        data = _api_get(API_PLAYBOOKS, body={"page": 0, "size": 500, "query": ""})
        playbooks: list[dict] = data.get("playbooks", [])

        pb_map: dict[str, dict] = {pb.get("name", ""): pb for pb in playbooks}

        for prefix in expected_prefixes:
            matched = [name for name in pb_map if name.startswith(prefix)]

            if not matched:
                status  = STATUS_FAIL
                note    = f"No playbook found matching prefix '{prefix}'"
                overall = STATUS_FAIL
            else:
                for pb_name in matched:
                    pb      = pb_map[pb_name]
                    enabled = not pb.get("deprecated", False)
                    version = pb.get("version", "?")

                    if not enabled:
                        status  = STATUS_WARN
                        note    = f"v{version} — marked deprecated"
                        if overall == STATUS_PASS:
                            overall = STATUS_WARN
                    else:
                        status = STATUS_PASS
                        note   = f"v{version} — installed and active"

                    findings.append({
                        "check":  "Playbook",
                        "item":   pb_name,
                        "status": status,
                        "note":   note,
                    })
                continue  # skip the "no match" append below

            findings.append({
                "check":  "Playbook",
                "item":   prefix + "*",
                "status": status,
                "note":   note,
            })

    except Exception as exc:
        overall = STATUS_FAIL
        findings.append({
            "check":  "Playbook",
            "item":   "API call",
            "status": STATUS_FAIL,
            "note":   f"API error: {exc}",
        })

    return {"name": "Installed Playbooks", "status": overall, "findings": findings}


# ─── Check 3 : Active jobs ────────────────────────────────────────────────────

def check_jobs(expected_job_prefixes: list[str]) -> dict:
    """
    Verify that scheduled SOC Framework jobs exist and are not paused or in error.
    """
    findings: list[dict] = []
    overall = STATUS_PASS

    try:
        data = _api_get(API_JOBS)
        jobs: list[dict] = data if isinstance(data, list) else data.get("jobs", [])

        job_map: dict[str, dict] = {j.get("name", ""): j for j in jobs}

        for prefix in expected_job_prefixes:
            matched = [name for name in job_map if name.startswith(prefix)]

            if not matched:
                findings.append({
                    "check":  "Job",
                    "item":   prefix + "*",
                    "status": STATUS_WARN,
                    "note":   "No scheduled job found — may not be required for this customer",
                })
                if overall == STATUS_PASS:
                    overall = STATUS_WARN
                continue

            for job_name in matched:
                job       = job_map[job_name]
                is_paused = job.get("isPaused", False)
                last_run  = job.get("lastRunTime", "never")
                schedule  = job.get("cronView", job.get("scheduleInterval", "?"))

                if is_paused:
                    status  = STATUS_WARN
                    note    = f"Job is PAUSED — schedule: {schedule}"
                    if overall == STATUS_PASS:
                        overall = STATUS_WARN
                else:
                    status = STATUS_PASS
                    note   = f"Active — schedule: {schedule} — last run: {last_run}"

                findings.append({
                    "check":  "Job",
                    "item":   job_name,
                    "status": status,
                    "note":   note,
                })

    except Exception as exc:
        overall = STATUS_FAIL
        findings.append({
            "check":  "Job",
            "item":   "API call",
            "status": STATUS_FAIL,
            "note":   f"API error: {exc}",
        })

    return {"name": "Scheduled Jobs", "status": overall, "findings": findings}


# ─── Check 4 : Lists & datasets ───────────────────────────────────────────────

def check_lists_and_datasets(expected_lists: list[str], expected_datasets: list[str]) -> dict:
    """
    Verify that required XSIAM lists exist and that key datasets are non-empty.
    Uses getList for lists, and XQL for dataset row count checks.
    """
    findings: list[dict] = []
    overall = STATUS_PASS

    # 4a — Lists
    for list_name in expected_lists:
        try:
            result = demisto.executeCommand("getList", {"listName": list_name})
            if is_error(result) or not result[0].get("Contents"):
                status  = STATUS_FAIL
                note    = "List missing or empty"
                overall = STATUS_FAIL
            else:
                content = result[0].get("Contents", "")
                size    = len(content) if isinstance(content, str) else len(json.dumps(content))
                status  = STATUS_PASS
                note    = f"Present — {size} bytes"
        except Exception as exc:
            status  = STATUS_FAIL
            note    = f"Error: {exc}"
            overall = STATUS_FAIL

        findings.append({
            "check":  "List",
            "item":   list_name,
            "status": status,
            "note":   note,
        })

    # 4b — Datasets (XQL row count)
    for dataset_name in expected_datasets:
        try:
            xql_body = {
                "request_data": {
                    "query": f"dataset = {dataset_name} | limit 1",
                    "timeframe": {"relativeTime": 2592000000},  # 30 days
                }
            }
            start_resp = _api_get(API_XQL_START, body=xql_body)
            query_id   = start_resp.get("reply", {}).get("execution_id", "")

            if not query_id:
                raise ValueError("No execution_id returned from XQL start")

            result_resp = _api_get(
                API_XQL_RESULT,
                body={"request_data": {"execution_id": query_id, "max_results": 1}},
            )
            results = result_resp.get("reply", {}).get("results", {}).get("data", [])

            if results:
                status = STATUS_PASS
                note   = "Dataset has rows — populated"
            else:
                status = STATUS_WARN
                note   = "Dataset exists but returned 0 rows in last 30 days"
                if overall == STATUS_PASS:
                    overall = STATUS_WARN

        except Exception as exc:
            status  = STATUS_WARN
            note    = f"Could not verify (may not exist yet): {exc}"
            if overall == STATUS_PASS:
                overall = STATUS_WARN

        findings.append({
            "check":  "Dataset",
            "item":   dataset_name,
            "status": status,
            "note":   note,
        })

    return {"name": "Lists & Datasets", "status": overall, "findings": findings}


# ─── Warroom report ───────────────────────────────────────────────────────────

def _build_warroom_report(results: list[dict], run_ts: str) -> str:
    lines = [
        f"## {SCRIPT_NAME} v{SCRIPT_VERSION}",
        f"**Run:** {run_ts}",
        "",
    ]

    for section in results:
        section_status = section["status"]
        icon = _icon(section_status)
        lines.append(f"### {icon} {section['name']} — {section_status}")

        findings = section.get("findings", [])
        if not findings:
            lines.append("_No items checked_")
        else:
            lines.append("| Item | Status | Note |")
            lines.append("|------|--------|------|")
            for f in findings:
                lines.append(
                    f"| `{f['item']}` | {_icon(f['status'])} {f['status']} | {f['note']} |"
                )
        lines.append("")

    # Summary footer
    statuses   = [r["status"] for r in results]
    fail_count = statuses.count(STATUS_FAIL)
    warn_count = statuses.count(STATUS_WARN)
    pass_count = statuses.count(STATUS_PASS)

    lines.append("---")
    lines.append(
        f"**Summary:** "
        f"{_icon(STATUS_PASS)} {pass_count} pass · "
        f"{_icon(STATUS_WARN)} {warn_count} warn · "
        f"{_icon(STATUS_FAIL)} {fail_count} fail"
    )

    return "\n".join(lines)


# ─── Dataset writer ───────────────────────────────────────────────────────────

def _write_health_dataset(results: list[dict], run_ts: str) -> None:
    """
    Write a summary row to the SOC Framework health check dataset.
    Enables PoV trend tracking — show the customer health improving over time.
    """
    statuses   = [r["status"] for r in results]
    fail_count = statuses.count(STATUS_FAIL)
    warn_count = statuses.count(STATUS_WARN)
    pass_count = statuses.count(STATUS_PASS)

    overall = STATUS_FAIL if fail_count else (STATUS_WARN if warn_count else STATUS_PASS)

    row = {
        "timestamp":   run_ts,
        "overall":     overall,
        "pass_count":  pass_count,
        "warn_count":  warn_count,
        "fail_count":  fail_count,
        "sections":    json.dumps({r["name"]: r["status"] for r in results}),
    }

    try:
        demisto.executeCommand(
            "xdr-xql-generic-query",
            {
                "query": (
                    f"dataset = {HEALTH_DATASET} "
                    f"| insert json_object("
                    + ", ".join(f'"{k}", "{v}"' for k, v in row.items())
                    + ")"
                )
            },
        )
    except Exception as exc:
        demisto.debug(f"[{SCRIPT_NAME}] Dataset write skipped: {exc}")


# ─── CommandResults table ─────────────────────────────────────────────────────

def _build_command_results(results: list[dict], run_ts: str) -> CommandResults:
    rows = []
    for section in results:
        for f in section.get("findings", []):
            rows.append({
                "Category": section["name"],
                "Item":     f["item"],
                "Status":   f"{_icon(f['status'])} {f['status']}",
                "Note":     f["note"],
            })

    readable = tableToMarkdown(
        f"SOC Framework Health Check — {run_ts}",
        rows,
        headers=["Category", "Item", "Status", "Note"],
        removeNull=True,
    )

    overall_statuses = [r["status"] for r in results]
    overall = (
        STATUS_FAIL if STATUS_FAIL in overall_statuses
        else STATUS_WARN if STATUS_WARN in overall_statuses
        else STATUS_PASS
    )

    return CommandResults(
        readable_output=readable,
        outputs_prefix="SOCFWHealth",
        outputs_key_field="timestamp",
        outputs={
            "timestamp": run_ts,
            "overall":   overall,
            "sections":  results,
        },
    )


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    args = demisto.args()

    config_list_name = args.get("config_list", "SOCFWConfig")
    write_dataset    = argToBoolean(args.get("write_dataset", "false"))
    verbose          = argToBoolean(args.get("verbose", "false"))

    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    demisto.debug(f"[{SCRIPT_NAME}] Starting health check at {run_ts}")

    # Load config (from XSIAM list — same format as SOCFWPackManager)
    config = _load_config(config_list_name)

    # Resolve expected items from config or fall back to defaults
    expected_brands: list[str] = config.get("required_brands", [
        "System XQL HTTP Collector",
        "Cortex XDR - IR",
        "Active Directory Query v2",
    ])

    expected_pb_prefixes: list[str] = config.get("entry_point_prefixes", DEFAULT_ENTRY_POINT_PREFIXES)

    expected_job_prefixes: list[str] = config.get("job_prefixes", [
        "JOB - SOCFramework",
        "JOB - Foundation",
    ])

    expected_lists: list[str] = config.get("required_lists", [
        "SOCFWConfig",
        "SOCFW_UniversalCommand",
    ])

    expected_datasets: list[str] = config.get("required_datasets", [
        "socfw_playbook_actions",
    ])

    # Run all checks
    results: list[dict] = []

    demisto.debug(f"[{SCRIPT_NAME}] Checking integration instances...")
    results.append(check_integrations(expected_brands))

    demisto.debug(f"[{SCRIPT_NAME}] Checking installed playbooks...")
    results.append(check_playbooks(expected_pb_prefixes))

    demisto.debug(f"[{SCRIPT_NAME}] Checking scheduled jobs...")
    results.append(check_jobs(expected_job_prefixes))

    demisto.debug(f"[{SCRIPT_NAME}] Checking lists and datasets...")
    results.append(check_lists_and_datasets(expected_lists, expected_datasets))

    # Warroom report
    report = _build_warroom_report(results, run_ts)
    demisto.results({"Type": 1, "ContentsFormat": "markdown", "Contents": report})

    # Optional dataset write for PoV trend tracking
    if write_dataset:
        _write_health_dataset(results, run_ts)
        demisto.debug(f"[{SCRIPT_NAME}] Health row written to {HEALTH_DATASET}")

    # Structured CommandResults for incident context / layout widgets
    return_results(_build_command_results(results, run_ts))


if __name__ in ("__main__", "__builtin__", "builtins"):
    try:
        main()
    except Exception:
        return_error(
            f"{SCRIPT_NAME} failed: {traceback.format_exc()}",
            error=traceback.format_exc(),
        )
