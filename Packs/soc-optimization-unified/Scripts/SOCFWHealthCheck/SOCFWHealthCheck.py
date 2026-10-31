register_module_line('SOCFWHealthCheck', 'start', __line__())
# ============================================================
# SOCFWHealthCheck
# ============================================================
# Read-only. Grades a tenant for SOC Framework work in two parts:
#
#   Configuration  what SOCFWConfig status reports: the tenant config list,
#                  the mode the tenant matches, the framework JOBs (on/off and
#                  whether the owner is a user), Auto Triage settings,
#                  emergency response, and required customer values; with the
#                  analyst assignment JOB on, who is on its roster.
#   Installation   what is on the tenant. With config_url, the items named in
#                  an xsoar_config.json (lists, integration instances, jobs,
#                  lookup datasets, packs, correlation rules); without it,
#                  prefix matching on playbooks and jobs.
#
# Usage:
#   !SOCFWHealthCheck
#   !SOCFWHealthCheck config_url="https://.../xsoar_config.json" write_dataset=true
# ============================================================

import json
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_VERSION = "2.0.0"
SCRIPT_NAME    = "SOCFWHealthCheck"

STATUS_OK   = "OK"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"

HEALTH_DATASET = "socfw_health_checks"

ASSIGNMENT_JOB = "SOCFW Analyst Assignment"

# Instances the framework calls by name (using=). A same-brand instance under any
# other name does not satisfy these: the call fails, and for the dataset writer
# every framework row (decisions, commands, assignments) is lost.
REQUIRED_INSTANCES: Dict[str, Tuple[str, str]] = {
    "socfw_ir_execution_writer": ("SOCFWDatasetWriter",
                                  "every row to xsiam_socfw_ir_execution_raw"),
    "socfw_case_ledger_writer": ("SOCFWDatasetWriter", "case ledger rows"),
    "Unit_42_Intelligence_SOCFW": ("Unit 42 Intelligence", "the Unit 42 enrichment action"),
}
ROSTER_LOOKUP = "socfw_on_duty"
ROLE_SOURCE = "xsiam_role"

# ── Fallback defaults (used when no config_url is provided) ──
DEFAULT_ENTRY_POINT_PREFIXES: List[str] = [
    "EP_IR_NIST",
    "Foundation - ",
    "JOB - ",
]
DEFAULT_JOB_PLAYBOOK_PREFIXES: List[str] = ["JOB - "]


# ============================================================
# Core API helper
# ============================================================

def _call_core_api(
        method: str,
        uri: str,
        body: Optional[Dict] = None,
        using: Optional[str] = None,
) -> Tuple[bool, Any]:
    command = f"core-api-{method}"
    args: Dict[str, Any] = {"uri": uri}
    if body is not None:
        args["body"] = body
    if using:
        args["using"] = using

    status, res = execute_command(command, args, fail_on_error=False)
    if not status:
        return False, res
    if isinstance(res, list):
        res = res[0] if res else {}
    if isinstance(res, dict):
        return True, res.get("response", res)
    return True, res


# ============================================================
# Fetch & parse xsoar_config.json
# ============================================================

def fetch_xsoar_config(config_url: str) -> Tuple[bool, Any]:
    """
    Download the xsoar_config.json from GitHub (or any raw URL)
    using HttpV2 — the same mechanism the Starter Configuration
    Setup playbook uses to download the config file.
    Returns (success, parsed_dict_or_error_string).
    """
    try:
        res = demisto.executeCommand("http", {
            "url": config_url,
            "method": "GET",
            "headers": "Accept: application/json",
        })
        entry = res[0] if res else {}
        if entry.get("Type") == entryTypes.get("error", 4):
            return False, f"HttpV2 error: {entry.get('Contents', '')}"

        contents = entry.get("Contents", {})
        # HttpV2 returns body under 'Body' key
        body_raw = contents.get("Body") if isinstance(contents, dict) else str(contents)
        if not body_raw:
            return False, "Empty response from config URL"

        return True, json.loads(body_raw)
    except Exception as e:
        return False, f"Exception fetching config: {e}"


# ============================================================
# Configuration — graded from SOCFWConfig status (always runs)
# ============================================================

CONFIG_COMMAND = "SOCFWConfig"
AUTOMATED_ACTORS = ("ai", "automation", "issue_emergency")


def _check(name: str, status: str, detail: str) -> Dict[str, Any]:
    return {"check": name, "status": status, "detail": detail}


def _config_status() -> Tuple[Optional[Dict], str]:
    """SOCFWConfig.Status from !SOCFWConfig command=status, or (None, why)."""
    try:
        res = demisto.executeCommand(CONFIG_COMMAND, {"command": "status"})
    except Exception as e:  # noqa: BLE001
        return None, f"{CONFIG_COMMAND} did not run: {e}"
    for entry in res or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("Type") == entryTypes.get("error", 4):
            return None, f"{CONFIG_COMMAND} failed: {str(entry.get('Contents', ''))[:300]}"
        for key, value in (entry.get("EntryContext") or {}).items():
            if key.split("(")[0] == "SOCFWConfig.Status" and isinstance(value, dict):
                return value, ""
    return None, f"{CONFIG_COMMAND} returned no status"


def _triage_detail(view: Dict) -> Tuple[str, str]:
    score = (view or {}).get("score_threshold") or {}
    window = (view or {}).get("window_hours") or {}
    s_eff, w_eff = score.get("effective"), window.get("effective")
    detail = (f"score below {s_eff} ({score.get('from', '?')}), "
              f"older than {w_eff}h ({window.get('from', '?')})")
    if s_eff in (None, "off"):
        return STATUS_WARN, ("score gate is off: Auto Triage closes any unstarred new case past the "
                             f"window, whatever its score; window {w_eff}h ({window.get('from', '?')})")
    return STATUS_OK, detail


def check_roster() -> Dict[str, Any]:
    """Who the on assignment job would assign to, from the socfw_on_duty lookup."""
    name = "Analyst assignment roster"
    fix = '!SOCFWOnDutySync analysts="<the customer\'s analyst emails>"'
    ok, resp = _call_core_api("post", "/public_api/v1/xql/lookups/get_data",
                              {"request_data": {"dataset_name": ROSTER_LOOKUP}})
    if not ok:
        if "not found" in str(resp).lower():
            return _check(name, STATUS_WARN, f"no roster yet; the job builds one on its next run, or set "
                                             f"the customer's analysts now: {fix}")
        return _check(name, STATUS_WARN, f"{ROSTER_LOOKUP} unreadable: {str(resp)[:200]}")
    rows = ((resp or {}).get("reply") or {}).get("data") or []
    counts: Dict[str, int] = {}
    for r in rows:
        if isinstance(r, dict) and r.get("email"):
            counts[r.get("source") or "?"] = counts.get(r.get("source") or "?", 0) + 1
    if not counts:
        return _check(name, STATUS_WARN, f"nobody on duty, so nothing is assigned: {fix}")
    if set(counts) == {ROLE_SOURCE}:
        return _check(name, STATUS_WARN,
                      f"all {counts[ROLE_SOURCE]} on duty come from the role and group fallback (AssignmentRoles, AssignmentGroups); "
                      "on a PoV tenant those roles usually include Palo Alto Networks staff, who would "
                      f"get the customer's cases: {fix}")
    return _check(name, STATUS_OK, f"{sum(counts.values())} on duty: "
                  + ", ".join(f"{n} {src}" for src, n in sorted(counts.items())))


def check_configuration() -> List[Dict[str, Any]]:
    status, why = _config_status()
    if status is None:
        return [_check("Configuration (SOCFWConfig)", STATUS_FAIL,
                       why + " — install or repair soc-optimization-unified.")]
    checks = []

    exists = status.get("tenant_config_exists")
    checks.append(_check(
        "Tenant config (SOCFWTenantConfig)", STATUS_OK,
        "present and readable" if exists
        else "not created yet; the framework runs on the shipped settings"))

    mode = status.get("mode")
    live = sorted({f"{r['action']} ({r['actor']})" for r in status.get("rows") or []
                   if r.get("actor") in AUTOMATED_ACTORS and r.get("state") == "live"
                   and not r.get("read_only")})
    live_text = ("nothing automated runs for real" if not live
                 else f"runs for real: {', '.join(live)}")
    if mode is None:
        checks.append(_check("Mode", STATUS_WARN, f"modes unreadable; {live_text}"))
    else:
        checks.append(_check("Mode", STATUS_OK, f"matches {mode}; {live_text}"))

    missing = [f"{v.get('vendor')} {v.get('arg')}" for v in status.get("values") or []
               if v.get("required") and not v.get("set")]
    checks.append(_check(
        "Customer values", STATUS_WARN if missing else STATUS_OK,
        ("required and not set: " + ", ".join(missing)
         + " — !SOCFWConfig command=set vendor=<vendor> arg=<setting> value=<value>")
        if missing else "every required value is set"))

    jobs = status.get("jobs") or []
    if not jobs:
        checks.append(_check("Framework JOBs", STATUS_WARN,
                             "could not read the jobs (Core REST API integration)"))
    for j in jobs:
        name = f"JOB: {j.get('job')}"
        if not j.get("installed"):
            checks.append(_check(name, STATUS_WARN, "not installed"))
            continue
        on, owner, ok = j.get("scheduled"), j.get("owner") or "(none)", j.get("owner_is_user")
        fix = f'!SOCFWConfig command=owner job="{j.get("job")}" owner=<email> apply=yes'
        if on and ok is False:
            checks.append(_check(name, STATUS_FAIL,
                                 f"on, but owner {owner} is not a user on this tenant, so every run "
                                 f"errors — {fix}"))
        elif ok is None:
            checks.append(_check(name, STATUS_WARN,
                                 f"{'on' if on else 'off'}, owner {owner}; could not check the owner"))
        elif on:
            checks.append(_check(name, STATUS_OK, f"on, owner {owner}"))
        else:
            checks.append(_check(name, STATUS_OK,
                                 f"off, owner {owner}" + ("" if ok else f" (set one before turning it on: {fix})")))

    if any(j.get("job") == ASSIGNMENT_JOB and j.get("installed") and j.get("scheduled") for j in jobs):
        checks.append(check_roster())

    if "triage" in status:
        checks.append(_check("Auto Triage settings", *_triage_detail(status["triage"])))
    else:
        checks.append(_check("Auto Triage settings", STATUS_WARN, "unreadable"))

    em = status.get("emergency")
    if isinstance(em, dict):
        checks.append(_check(
            "Emergency response", STATUS_OK,
            f"{'on' if em.get('enabled') else 'off'}: {em.get('policies', 0)} policies, "
            f"{em.get('tenant_policies', 0)} edited or added on this tenant"))
    else:
        checks.append(_check("Emergency response", STATUS_WARN, "policies unreadable"))
    return checks


# ============================================================
# Config-driven checks
# ============================================================

def _get_all_instances(using: Optional[str]) -> Tuple[bool, List[Dict]]:
    """Fetch all integration instances once and reuse."""
    ok, response = _call_core_api(
        "post", "xsoar/public/v1/settings/integration/search",
        body={}, using=using
    )
    if not ok:
        return False, []
    if isinstance(response, dict):
        return True, response.get("instances", [])
    if isinstance(response, list):
        return True, response
    return True, []


def check_lists_from_config(
        lists_config: List[Dict],
) -> List[Dict[str, Any]]:
    """Verify each list defined in xsoar_config.json exists."""
    results = []
    for item in lists_config:
        list_name = item.get("name", "")
        if not list_name:
            continue
        check_name = f"List: {list_name}"
        result = demisto.executeCommand("getList", {"listName": list_name})
        entry  = result[0] if result else {}
        missing = (
                entry.get("Type") == entryTypes.get("error", 4)
                and "Item not found" in str(entry.get("Contents", ""))
        )
        if missing:
            results.append({
                "check": check_name,
                "status": STATUS_FAIL,
                "detail": f"List '{list_name}' not found on tenant.",
            })
        else:
            results.append({
                "check": check_name,
                "status": STATUS_OK,
                "detail": f"List '{list_name}' exists.",
            })
    return results


def check_named_instances(
        all_instances: List[Dict],
        api_ok: bool,
        required: Optional[Dict[str, Tuple[str, str]]] = None,
) -> List[Dict[str, Any]]:
    """One check per instance the framework calls by exact name.

    Missing or disabled is FAIL. When the name is missing but the brand exists
    under another name, the detail names that instance so the fix is a rename.
    """
    required = REQUIRED_INSTANCES if required is None else required
    results = []
    for name, (brand, purpose) in required.items():
        check = f"Instance: {name}"
        if not api_ok:
            results.append(_check(check, STATUS_WARN, "Core REST API unreachable — cannot verify."))
            continue
        exact = [x for x in all_instances if x.get("name") == name]
        if exact:
            if any(x.get("enabled") == "true" for x in exact):
                results.append(_check(check, STATUS_OK, f"enabled ({brand})"))
            else:
                results.append(_check(check, STATUS_FAIL,
                                      f"exists but is disabled — {purpose} fails until it is enabled."))
            continue
        others = sorted(x.get("name", "?") for x in all_instances if x.get("brand") == brand)
        if others:
            results.append(_check(check, STATUS_FAIL,
                                  f"missing — {purpose} calls it by this exact name. Found {brand} "
                                  f"instance(s) named {', '.join(others)}: rename one to {name} "
                                  "or create a new one with that name."))
        else:
            results.append(_check(check, STATUS_FAIL,
                                  f"missing — create a {brand} instance named exactly {name} "
                                  f"({purpose} calls it by name)."))
    return results


def check_integration_instances_from_config(
        instances_config: List[Dict],
        all_instances: List[Dict],
        api_ok: bool,
) -> List[Dict[str, Any]]:
    """
    Verify each integration instance defined in xsoar_config.json is present
    and enabled.  Deduplicates by brand so we only report once per brand.
    Brands of REQUIRED_INSTANCES are left to check_named_instances, which
    checks them by exact name.
    """
    results = []
    seen_brands = {brand for brand, _ in REQUIRED_INSTANCES.values()}

    for inst in instances_config:
        brand = inst.get("brand", "")
        if not brand or brand in seen_brands:
            continue
        seen_brands.add(brand)
        check_name = f"Integration: {brand}"

        if not api_ok:
            results.append({
                "check": check_name,
                "status": STATUS_WARN,
                "detail": "Core REST API unreachable — cannot verify.",
            })
            continue

        enabled = [
            x for x in all_instances
            if x.get("brand") == brand and x.get("enabled") == "true"
        ]
        if enabled:
            names = ", ".join(x.get("name", "?") for x in enabled)
            results.append({
                "check": check_name,
                "status": STATUS_OK,
                "detail": f"Enabled: {names}",
            })
        else:
            any_inst = [x for x in all_instances if x.get("brand") == brand]
            if any_inst:
                results.append({
                    "check": check_name,
                    "status": STATUS_WARN,
                    "detail": "Instance exists but is DISABLED — enable before demo.",
                })
            else:
                results.append({
                    "check": check_name,
                    "status": STATUS_FAIL,
                    "detail": "No instance found. Create and enable this integration.",
                })

    return results


def check_jobs_from_config(
        jobs_config: List[Dict],
        using: Optional[str],
) -> List[Dict[str, Any]]:
    """
    Verify each job defined in xsoar_config.json exists on the tenant.
    Job names in the config match exactly what appears in the XSIAM Jobs UI.
    Uses: core-api-post /jobs/search → response.data[].name
    """
    if not jobs_config:
        return []

    ok, response = _call_core_api(
        "post", "/jobs/search",
        body={"page": 0, "size": 500, "query": ""}, using=using
    )

    results = []

    if not ok:
        for job in jobs_config:
            name = job.get("name", "")
            if name:
                results.append({
                    "check": f"Job: {name}",
                    "status": STATUS_WARN,
                    "detail": "Core REST API unreachable — cannot verify.",
                })
        return results

    tenant_jobs = []
    if isinstance(response, dict):
        tenant_jobs = response.get("data", [])
    elif isinstance(response, list):
        tenant_jobs = response

    tenant_job_names = {j.get("name", "") for j in tenant_jobs}

    for job in jobs_config:
        name = job.get("name", "")
        if not name:
            continue
        check_name = f"Job: {name}"
        if name in tenant_job_names:
            results.append({
                "check": check_name,
                "status": STATUS_OK,
                "detail": f"Job '{name}' found.",
            })
        else:
            results.append({
                "check": check_name,
                "status": STATUS_WARN,
                "detail": (
                    f"Job '{name}' not found. "
                    "Run the Starter Configuration Setup playbook to create it."
                ),
            })

    return results


def check_datasets_from_config(
        datasets_config: List[Dict],
        using: Optional[str],
) -> List[Dict[str, Any]]:
    """
    Verify each lookup_dataset defined in xsoar_config.json exists.
    Uses: core-api-post /public_api/v1/xql/get_datasets
    Response: {reply: [{'Dataset Name': name}]}
    """
    if not datasets_config:
        return []

    ok, response = _call_core_api(
        "post", "/public_api/v1/xql/get_datasets",
        body={}, using=using
    )

    results = []

    if not ok:
        for ds in datasets_config:
            name = ds.get("dataset_name", "")
            if name:
                results.append({
                    "check": f"Dataset: {name}",
                    "status": STATUS_WARN,
                    "detail": "Core REST API unreachable — cannot verify.",
                })
        return results

    existing = []
    if isinstance(response, dict):
        existing = response.get("reply", [])
    elif isinstance(response, list):
        existing = response

    existing_names = {x.get("Dataset Name", "") for x in existing}

    for ds in datasets_config:
        name = ds.get("dataset_name", "")
        if not name:
            continue
        if name in existing_names:
            results.append({
                "check": f"Dataset: {name}",
                "status": STATUS_OK,
                "detail": f"Dataset '{name}' exists.",
            })
        else:
            results.append({
                "check": f"Dataset: {name}",
                "status": STATUS_WARN,
                "detail": (
                    f"Dataset '{name}' not found — created automatically "
                    "on first playbook execution."
                ),
            })

    return results


def check_packs_from_config(
        custom_packs: List[Dict],
        marketplace_packs: List[Dict],
        using: Optional[str],
) -> List[Dict[str, Any]]:
    """
    Verify packs defined in xsoar_config.json are installed.
    Uses core-api-get /contentpacks/metadata/installed.
    custom_packs:      [{id (filename like 'PackName.zip'), url, system}]
    marketplace_packs: [{id, name, version}]
    """
    all_packs = custom_packs + marketplace_packs
    if not all_packs:
        return []

    response = None
    for uri in ["/contentpacks/metadata/installed",
                "/xsoar/public/v1/contentpacks/metadata/installed"]:
        ok, resp = _call_core_api("get", uri, using=using)
        if ok:
            response = resp
            break

    results = []

    if response is None:
        for p in all_packs:
            pid = p.get("id", "")
            if pid:
                results.append({
                    "check": f"Pack: {pid}",
                    "status": STATUS_WARN,
                    "detail": "Could not query installed packs — verify manually.",
                })
        return results

    installed = response if isinstance(response, list) else []
    installed_ids = {p.get("id", "").lower() for p in installed}

    for p in all_packs:
        raw_id = p.get("id", "")
        if not raw_id:
            continue
        # custom_packs use filename e.g. "SOC_Framework.zip" — strip .zip
        pack_id = raw_id.replace(".zip", "").replace(".ZIP", "")
        check_name = f"Pack: {pack_id}"

        if pack_id.lower() in installed_ids:
            # Find version
            match = next((x for x in installed if x.get("id", "").lower() == pack_id.lower()), {})
            ver = match.get("currentVersion", "?")
            results.append({
                "check": check_name,
                "status": STATUS_OK,
                "detail": f"Installed v{ver}.",
            })
        else:
            results.append({
                "check": check_name,
                "status": STATUS_FAIL,
                "detail": (
                    f"Pack '{pack_id}' not installed. "
                    "Run Starter Configuration Setup to install."
                ),
            })

    return results


# ============================================================
# Fallback checks (no config_url)
# ============================================================

def check_integrations_summary(using: Optional[str]) -> Dict[str, Any]:
    """
    Fallback mode: show all enabled integration instances so the analyst
    can see what's connected without needing a config_url.
    """
    check_name = "Integration Instances"
    api_ok, all_instances = _get_all_instances(using)

    if not api_ok:
        return {"check": check_name, "status": STATUS_WARN,
                "detail": "Core REST API unreachable — cannot query instances."}

    enabled = [x for x in all_instances if x.get("enabled") == "true"]
    disabled = [x for x in all_instances if x.get("enabled") != "true"]

    if not enabled and not disabled:
        return {"check": check_name, "status": STATUS_WARN,
                "detail": "No integration instances found on tenant."}

    names = sorted({x.get("brand", x.get("name", "?")) for x in enabled})
    preview = ", ".join(names[:8])
    suffix  = f"  (+{len(names)-8} more)" if len(names) > 8 else ""
    detail  = f"{len(enabled)} enabled: {preview}{suffix}"
    if disabled:
        dis_names = sorted({x.get("brand", x.get("name", "?")) for x in disabled})[:4]
        detail += f"  |  {len(disabled)} disabled: {', '.join(dis_names)}"

    status = STATUS_OK if enabled else STATUS_WARN
    return {"check": check_name, "status": status, "detail": detail}


def check_correlation_rules(using: Optional[str], name_prefix: str = "SOC") -> Dict[str, Any]:
    """
    Check that SOC Framework correlation rules are present.
    Uses POST /public_api/v1/correlations/get.
    In fallback mode filters by name_prefix; config mode can pass "" to list all.
    """
    check_name = "Correlation Rules"
    ok, response = _call_core_api(
        "post", "/public_api/v1/correlations/get",
        body={"request_data": {}}, using=using
    )
    if not ok:
        return {"check": check_name, "status": STATUS_WARN,
                "detail": f"Could not query correlation rules: {response}"}

    rules: List[Dict] = []
    if isinstance(response, dict):
        # XSIAM wraps correlation results in {"reply": {"data": [...]}} or {"reply": [...]}
        # Handle both the wrapped and unwrapped forms.
        if "reply" in response:
            reply = response["reply"]
            if isinstance(reply, list):
                rules = reply
            elif isinstance(reply, dict):
                rules = reply.get("data", reply.get("objects", reply.get("rules", [])))
        else:
            rules = response.get("objects", response.get("rules", response.get("data", [])))
    elif isinstance(response, list):
        rules = response

    if not rules:
        return {"check": check_name, "status": STATUS_WARN,
                "detail": "No correlation rules returned — check Core REST API permissions."}

    def _rule_name(r: dict) -> str:
        return r.get("name", r.get("rule_name", r.get("id", "")))

    matched = sorted([_rule_name(r) for r in rules
                      if name_prefix == "" or _rule_name(r).startswith(name_prefix)])

    if matched:
        preview = ", ".join(matched[:6])
        suffix  = f"  (+{len(matched)-6} more)" if len(matched) > 6 else ""
        return {"check": check_name, "status": STATUS_OK,
                "detail": f"{len(matched)} found: {preview}{suffix}"}

    total = len(rules)
    sample = [_rule_name(r) for r in rules[:4]]
    return {"check": check_name, "status": STATUS_WARN,
            "detail": (f"0 rules match prefix '{name_prefix}' (total rules on tenant: {total}). "
                       f"Sample: {sample}")}


def check_dashboards(using: Optional[str], name_prefix: str = "SOC") -> Dict[str, Any]:
    """
    Verify SOC Framework dashboards are installed.
    XSIAM has no public dashboard-listing API, so we infer presence from the
    installed pack that ships them (soc-optimization-unified).  If that pack
    is confirmed installed we return OK; otherwise we fall back to WARN with
    a manual-verify instruction.
    """
    check_name = "Dashboards"
    expected = [
        "XSIAM SOC Value Driver Metrics",
        "XSIAM SOC Value Metrics V3",
    ]
    expected_str = ", ".join(f"'{d}'" for d in expected)

    # Try to confirm the containing pack is installed
    response = None
    for uri in ["/contentpacks/metadata/installed",
                "/xsoar/public/v1/contentpacks/metadata/installed"]:
        ok, resp = _call_core_api("get", uri, using=using)
        if ok:
            response = resp
            break

    if response is not None:
        packs = response if isinstance(response, list) else []
        dashboard_pack = next(
            (p for p in packs
             if any(kw in str(p.get("id", "")).lower()
                    for kw in ["soc-optim", "soc_optim", "soc-optimization-unified"])),
            None,
        )
        if dashboard_pack:
            ver = dashboard_pack.get("currentVersion", "?")
            return {
                "check": check_name,
                "status": STATUS_OK,
                "detail": (
                    f"soc-optimization-unified v{ver} installed — "
                    f"dashboards present: {expected_str} "
                    "(SOC Framework Unified | Public)."
                ),
            }
        # Pack query succeeded but the pack wasn't found
        return {
            "check": check_name,
            "status": STATUS_WARN,
            "detail": (
                "soc-optimization-unified not found in installed packs. "
                f"Expected dashboards: {expected_str}. "
                "Verify manually in XSIAM \u2192 Dashboards."
            ),
        }

    # Couldn't reach the pack API at all — fall back to manual verify
    return {
        "check": check_name,
        "status": STATUS_WARN,
        "detail": (
            f"Verify manually in XSIAM \u2192 Dashboards. "
            f"Expected: {expected_str} "
            "(SOC Framework Unified | Public)."
        ),
    }

def _extract_playbook_list(response: Any) -> List[Dict]:
    """
    Try every key shape XSIAM/XSOAR might use for playbook search results.
    Logs what it found so verbose mode can report it.
    """
    if isinstance(response, list):
        return response

    if isinstance(response, dict):
        # Try known keys in priority order
        for key in ("playbooks", "data", "result", "results", "items"):
            val = response.get(key)
            if isinstance(val, list) and val:
                demisto.debug(f"{SCRIPT_NAME}: playbook list found under key '{key}' ({len(val)} items)")
                return val

        # Last resort: return any list value in the dict
        for key, val in response.items():
            if isinstance(val, list) and val and isinstance(val[0], dict):
                demisto.debug(f"{SCRIPT_NAME}: playbook list found under unexpected key '{key}' ({len(val)} items)")
                return val

    return []


def check_entry_point_playbooks_fallback(
        prefixes: List[str],
        using: Optional[str],
        verbose: bool = False,
) -> Dict[str, Any]:
    """
    Search for playbooks by prefix using targeted per-prefix queries.

    A broad query="" returns all playbooks but may omit system=true pack
    playbooks (e.g. SOC Framework) depending on the XSIAM version.
    Querying each prefix explicitly (as the REST API playground does) is
    reliable: query="EP_IR_NIST" returns total=1 with the exact playbook.
    """
    check_name = "Entry-Point Playbooks"

    def _search_prefix(prefix: str) -> List[str]:
        """Return list of playbook names that match this prefix."""
        args: Dict[str, Any] = {
            "uri": "/xsoar/public/v1/playbook/search",
            "body": {"page": 0, "size": 100, "query": prefix},
        }
        if using:
            args["using"] = using

        status, raw_res = execute_command("core-api-post", args, fail_on_error=False)
        if not status:
            demisto.debug(f"{SCRIPT_NAME}: playbook search failed for prefix '{prefix}': {raw_res}")
            return []

        if isinstance(raw_res, list):
            raw_res = raw_res[0] if raw_res else {}

        contents = raw_res if isinstance(raw_res, dict) else {}
        inner    = contents.get("response", contents)
        playbooks = _extract_playbook_list(inner)

        if verbose:
            total = inner.get("total", "?") if isinstance(inner, dict) else "?"
            demisto.info(
                f"{SCRIPT_NAME} verbose | prefix='{prefix}' total={total} "
                f"returned={len(playbooks)}"
            )

        # name field confirmed from live API response (system=true playbooks)
        results = []
        for pb in playbooks:
            pb_name = pb.get("name", "")
            if pb_name and pb_name.startswith(prefix):
                results.append(pb_name)
        return results

    matched: List[str] = []
    missing: List[str] = []

    for prefix in prefixes:
        found = _search_prefix(prefix)
        if found:
            matched.extend(found)
        else:
            missing.append(prefix)

    if matched:
        preview = ", ".join(sorted(matched)[:6])
        suffix  = f"  (+{len(matched)-6} more)" if len(matched) > 6 else ""
        detail  = f"{len(matched)} found: {preview}{suffix}"
        if missing:
            detail += f"  |  No match for prefixes: {missing}"
        status = STATUS_OK if not missing else STATUS_WARN
        return {"check": check_name, "status": status, "detail": detail}

    return {"check": check_name, "status": STATUS_FAIL,
            "detail": f"No playbooks found for any prefix: {prefixes}"}


def check_jobs_fallback(job_pb_prefixes: List[str], using: Optional[str]) -> Dict[str, Any]:
    check_name = "SOCFramework Jobs"
    ok, response = _call_core_api(
        "post", "/jobs/search",
        body={"page": 0, "size": 500, "query": ""}, using=using
    )
    if not ok:
        return {"check": check_name, "status": STATUS_WARN,
                "detail": "Could not query jobs — verify manually."}

    jobs = []
    if isinstance(response, dict):
        jobs = response.get("data", [])
    elif isinstance(response, list):
        jobs = response

    matched = []
    for j in jobs:
        pb_name  = j.get("playbook", j.get("playbookId", ""))
        job_name = j.get("name", "")
        if any(str(pb_name).startswith(pfx) for pfx in job_pb_prefixes):
            matched.append(f"{job_name} → {pb_name}")
        elif any(str(job_name).startswith(pfx) for pfx in job_pb_prefixes):
            matched.append(job_name)

    if matched:
        return {"check": check_name, "status": STATUS_OK,
                "detail": f"{len(matched)} job(s): {', '.join(matched)}"}
    return {"check": check_name, "status": STATUS_WARN,
            "detail": "No SOC Framework jobs found. Jobs optional but capture PoV metrics."}


def check_installed_packs_fallback(using: Optional[str]) -> Dict[str, Any]:
    check_name = "SOC Framework Pack(s)"
    response = None
    for uri in ["/contentpacks/metadata/installed",
                "/xsoar/public/v1/contentpacks/metadata/installed"]:
        ok, resp = _call_core_api("get", uri, using=using)
        if ok:
            response = resp
            break
    if response is None:
        return {"check": check_name, "status": STATUS_WARN,
                "detail": "Could not query installed packs — verify manually."}

    packs = response if isinstance(response, list) else []
    soc_packs = [
        p for p in packs
        if any(kw in str(p.get("id", "")).lower()
               for kw in ["soc", "socfw", "nist_ir", "nistir", "soc-framework",
                          "soc_framework", "soc-optim"])
    ]
    if soc_packs:
        summary = ", ".join(f"{p.get('id')} v{p.get('currentVersion','?')}" for p in soc_packs)
        return {"check": check_name, "status": STATUS_OK, "detail": f"Installed: {summary}"}
    return {"check": check_name, "status": STATUS_WARN,
            "detail": "No SOC Framework pack detected by ID pattern."}


# ============================================================
# Dataset write
# ============================================================

def write_health_to_dataset(checks: List[Dict], using: Optional[str]) -> str:
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = [{
        "check_name": c.get("check", ""), "status": c.get("status", ""),
        "detail": c.get("detail", ""), "script_version": SCRIPT_VERSION, "timestamp": ts,
    } for c in checks]
    ok, _ = _call_core_api(
        "post", "/public_api/v1/xql/lookups/add_data",
        body={"request_data": {"dataset_name": HEALTH_DATASET, "data": rows}},
        using=using,
    )
    return (f"Results written to '{HEALTH_DATASET}'."
            if ok else f"Dataset write failed ('{HEALTH_DATASET}' may not exist yet).")


# ============================================================
# Markdown output
# ============================================================

def _icon(s: str) -> str:
    return {"OK": "✅", "WARN": "⚠️", "FAIL": "❌"}.get(s, "❓")


def _build_markdown(
        checks: List[Dict],
        config_url: str,
        dataset_note: str,
) -> str:
    source = f"`{config_url}`" if config_url else "default prefix matching (no config_url provided)"
    lines = [
        f"## 🔍 SOCFWHealthCheck v{SCRIPT_VERSION}",
        f"**Run at:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Config source:** {source}",
        "",
        "| # | Check | Status | Detail |",
        "|---|-------|--------|--------|",
    ]
    for i, c in enumerate(checks, 1):
        lines.append(
            f"| {i} | {c.get('check','')} | {_icon(c.get('status',''))} {c.get('status','')} | {c.get('detail','')} |"
        )

    ok_n   = sum(1 for c in checks if c["status"] == STATUS_OK)
    warn_n = sum(1 for c in checks if c["status"] == STATUS_WARN)
    fail_n = sum(1 for c in checks if c["status"] == STATUS_FAIL)

    lines += ["", f"**Summary:** ✅ {ok_n} OK  ⚠️ {warn_n} WARN  ❌ {fail_n} FAIL", ""]

    if fail_n == 0 and warn_n == 0:
        lines.append("🟢 **Tenant is fully configured for SOC Framework PoV.**")
    elif fail_n == 0:
        lines.append("🟡 **Tenant is ready for PoV — review warnings before demo.**")
    else:
        lines.append("🔴 **Tenant has gaps — resolve FAIL items before PoV.**")

    if dataset_note:
        lines += ["", f"*{dataset_note}*"]
    return "\n".join(lines)


# ============================================================
# Main
# ============================================================

def main():
    args = demisto.args()

    config_url    = (args.get("config_url") or "").strip()
    write_dataset = argToBoolean(args.get("write_dataset", "false"))
    using         = args.get("core_rest_instance") or None

    checks: List[Dict[str, Any]] = []

    # ── 1. Always: configuration, from SOCFWConfig status ────
    checks.extend(check_configuration())

    # ── 1b. Always: the instances the framework calls by exact name ──
    api_ok, all_instances = _get_all_instances(using)
    checks.extend(check_named_instances(all_instances, api_ok))

    # ── 2a. CONFIG-DRIVEN mode ────────────────────────────────
    if config_url:
        fetch_ok, config = fetch_xsoar_config(config_url)

        if not fetch_ok:
            checks.append({
                "check": "xsoar_config.json Fetch",
                "status": STATUS_FAIL,
                "detail": str(config),
            })
            # Fall through to fallback checks below
            config = {}
        else:
            checks.append({
                "check": "xsoar_config.json Fetch",
                "status": STATUS_OK,
                "detail": (
                    f"Loaded from {config_url} — "
                    f"{len(config.get('jobs',[]))} jobs, "
                    f"{len(config.get('integration_instances',[]))} instances, "
                    f"{len(config.get('lists',[]))} lists, "
                    f"{len(config.get('lookup_datasets',[]))} datasets, "
                    f"{len(config.get('custom_packs',[]))+len(config.get('marketplace_packs',[]))} packs"
                ),
            })

        if config:
            # Lists
            checks.extend(check_lists_from_config(config.get("lists", [])))

            # Integration instances
            checks.extend(check_integration_instances_from_config(
                config.get("integration_instances", []), all_instances, api_ok
            ))

            # Jobs (exact names from config)
            checks.extend(check_jobs_from_config(config.get("jobs", []), using))

            # Lookup datasets
            checks.extend(check_datasets_from_config(config.get("lookup_datasets", []), using))

            # Packs
            checks.extend(check_packs_from_config(
                config.get("custom_packs", []),
                config.get("marketplace_packs", []),
                using,
            ))

            # Correlation rules (from config names or SOC prefix fallback)
            config_corr = config.get("correlation_rules", [])
            if config_corr:
                config_corr_names = {r.get("name", "") for r in config_corr if r.get("name")}
                ok, corr_resp = _call_core_api("post", "/public_api/v1/correlations/get",
                                               body={"request_data": {}}, using=using)
                if ok and isinstance(corr_resp, dict):
                    # Unwrap XSIAM reply wrapper before extracting rule list
                    if "reply" in corr_resp:
                        _r = corr_resp["reply"]
                        all_rules = (_r if isinstance(_r, list)
                                     else _r.get("data", _r.get("objects", _r.get("rules", []))))
                    else:
                        all_rules = corr_resp.get("objects", corr_resp.get("rules",
                                                                           corr_resp.get("data", [])))
                    found_names = {r.get("name", "") for r in all_rules}
                    missing = sorted(config_corr_names - found_names)
                    present = sorted(config_corr_names & found_names)
                    if not missing:
                        checks.append({"check": "Correlation Rules", "status": STATUS_OK,
                                       "detail": f"{len(present)} configured rules present."})
                    else:
                        checks.append({"check": "Correlation Rules", "status": STATUS_WARN,
                                       "detail": f"{len(present)} present, missing: {missing[:5]}"})
                else:
                    checks.append(check_correlation_rules(using))
            else:
                checks.append(check_correlation_rules(using))

            # Dashboards
            checks.append(check_dashboards(using))

            # Done — skip fallback
            dataset_note = ""
            if write_dataset:
                dataset_note = write_health_to_dataset(checks, using)

            ok_n   = sum(1 for c in checks if c["status"] == STATUS_OK)
            warn_n = sum(1 for c in checks if c["status"] == STATUS_WARN)
            fail_n = sum(1 for c in checks if c["status"] == STATUS_FAIL)
            overall = (STATUS_OK if (fail_n == 0 and warn_n == 0) else
                       STATUS_WARN if fail_n == 0 else STATUS_FAIL)

            return_results(CommandResults(
                outputs_prefix="SOCFWHealthCheck",
                outputs_key_field="timestamp",
                outputs={
                    "version": SCRIPT_VERSION,
                    "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "config_url": config_url,
                    "overall_status": overall,
                    "ok_count": ok_n, "warn_count": warn_n, "fail_count": fail_n,
                    "checks": checks,
                },
                readable_output=_build_markdown(checks, config_url, dataset_note),
            ))
            return

    # ── 2b. FALLBACK mode (no config_url or fetch failed) ─────
    ep_prefixes     = argToList(args.get("entry_point_prefixes", "")) or DEFAULT_ENTRY_POINT_PREFIXES
    job_pb_prefixes = argToList(args.get("job_playbook_prefixes", "")) or DEFAULT_JOB_PLAYBOOK_PREFIXES
    verbose         = argToBoolean(args.get("verbose", "false"))

    checks.append(check_entry_point_playbooks_fallback(ep_prefixes, using, verbose=verbose))
    checks.append(check_jobs_fallback(job_pb_prefixes, using))
    checks.append(check_integrations_summary(using))
    checks.append(check_correlation_rules(using))
    checks.append(check_dashboards(using))
    checks.append(check_installed_packs_fallback(using))

    dataset_note = ""
    if write_dataset:
        dataset_note = write_health_to_dataset(checks, using)

    ok_n   = sum(1 for c in checks if c["status"] == STATUS_OK)
    warn_n = sum(1 for c in checks if c["status"] == STATUS_WARN)
    fail_n = sum(1 for c in checks if c["status"] == STATUS_FAIL)
    overall = (STATUS_OK if (fail_n == 0 and warn_n == 0) else
               STATUS_WARN if fail_n == 0 else STATUS_FAIL)

    return_results(CommandResults(
        outputs_prefix="SOCFWHealthCheck",
        outputs_key_field="timestamp",
        outputs={
            "version": SCRIPT_VERSION,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "config_url": "",
            "overall_status": overall,
            "ok_count": ok_n, "warn_count": warn_n, "fail_count": fail_n,
            "checks": checks,
        },
        readable_output=_build_markdown(checks, "", dataset_note),
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    try:
        main()
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"{SCRIPT_NAME} v{SCRIPT_VERSION} — Unhandled error:\n{e}")

register_module_line('SOCFWHealthCheck', 'end', __line__())
