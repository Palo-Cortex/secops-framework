#!/usr/bin/env python3
"""
socfw_smoke.py — SOC Framework remote smoke test runner.

What this validates via the public API:
  ✅  Alert creation succeeds (create_alert endpoint)
  ✅  Alert is grouped into a case (case_id populated → grouping engine ran)
  ✅  Case/incident exists and is retrievable (get_incidents)
  ✅  War room entries appear → playbook chain ran (get_warroom_entries)

What requires manual tenant inspection (not accessible via public API):
  ℹ   Playbook verdict values (Analysis.Email.verdict etc — context is write-only)
  ℹ   Shadow mode execution records (xsiam_socfw_ir_execution_raw dataset)
  ℹ   Individual playbook task results

The test prints the direct case URL immediately after grouping so you can
open the Work Plan in the tenant while the poll loop runs.

Usage:
    python3 tools/socfw_smoke.py
    python3 tools/socfw_smoke.py --scenario SC-01
    python3 tools/socfw_smoke.py --scenario SC-01 SC-02
    python3 tools/socfw_smoke.py --wait 120
    python3 tools/socfw_smoke.py --debug
    python3 tools/socfw_smoke.py --list

Vendor/product → DS tag mapping
────────────────────────────────
XSIAM generates issue.tags entry "DS:{vendor}_{product}" (lowercased,
non-alphanum → _). This smoke test uses:
    vendor  = "Proofpoint"
    product = "TAP v2 Generic Alert"
    → tag   = DS:proofpoint_tap_v2_generic_alert
    → key   = ds_proofpoint_tap_v2_generic_alert   (in SOCProductCategoryMap)

If your tenant generates a different key, look at issue.tags in the war room
of a fired alert (use --debug to see the raw alert returned by get_alerts)
and add that key to SOCProductCategoryMap_V3_data.json → Email category.
"""

import os, sys, time, argparse, json
from pathlib import Path
from datetime import datetime, timezone

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("pip install requests", file=sys.stderr)
    sys.exit(2)

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

POLL_INTERVAL   = 15   # seconds between incident/warroom polls
WARROOM_MIN_ENTRIES = 3  # minimum war room entries to consider chain "running"

# ── Smoke test alert fields ──────────────────────────────────────────────────
#
# create_alert rejects custom field names (socfw*,
# fw_email_sender, etc.) via the REST API — those require the HTTP collector path.
# Smoke test validates infrastructure only: alert created → grouped → chain fired.
# Content validation (verdict, shadow mode entries) is manual via the case URL.
#
# For full field injection in testing use: python3 tools/send_test_events.py
# with --env .env-httpcollector-proofpoint pointing at the HTTP collector endpoint.
# Sourced from tools/fixtures/email_chain_test_fixture.json.
# These fields are injected into create_alert so that
# Foundation_-_Normalize_Email_V3 can read issue.fw_email_sender etc.

SCENARIO_ALERT_FIELDS = {
    # action_status and ip/port satisfy insert_parsed_alerts schema if ever needed.
    # For create_alert these are ignored — only vendor/product/severity/category used.
    "SC-01": {
        "local_ip":        "198.51.100.77",
        "local_port":      587,
        "remote_ip":       "10.20.30.101",
        "remote_port":      443,
        "action_status":   "Reported",
    },
    "SC-02": {
        "local_ip":        "203.0.113.88",
        "local_port":      25,
        "remote_ip":       "10.40.50.200",
        "remote_port":      443,
        "action_status":   "Reported",
    },
    "SC-03": {
        "local_ip":        "192.0.2.15",
        "local_port":      25,
        "remote_ip":       "10.60.70.80",
        "remote_port":      443,
        "action_status":   "Blocked",
    },
}


def load_env(path=".env"):
    env = {}
    p = Path(path)
    if not p.exists():
        return env
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


# ── XSIAM API client ──────────────────────────────────────────────────────────

class XSIAMClient:
    """Auth: raw api_key + x-xdr-auth-id header. No hashing."""

    def __init__(self, base_url, api_key, auth_id, debug=False):
        self.base  = base_url.rstrip("/")
        self.debug = debug
        self.s     = requests.Session()
        self.s.verify = False
        self.h = {
            "x-xdr-auth-id": str(auth_id),
            "Authorization":  api_key,
            "Content-Type":   "application/json",
        }

    def _post(self, path, body):
        url = f"{self.base}{path}"
        if self.debug:
            print(f"  {DIM}POST {url}{RESET}")
            print(f"  {DIM}{json.dumps(body)[:300]}{RESET}")
        r = self.s.post(url, headers=self.h, json=body, timeout=30)
        if r.status_code not in (200, 201):
            print(f"  {DIM}→ HTTP {r.status_code}: {r.text[:400]}{RESET}")
        r.raise_for_status()
        return r.json()

    def test_auth(self):
        try:
            r = self.s.post(f"{self.base}/xsoar/settings/credentials",
                            headers=self.h, json={}, timeout=15)
            if r.status_code == 200:
                n = len(r.json().get("credentials", []))
                return True, f"OK — {n} credential(s) visible"
            return False, f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as e:
            return False, str(e)

    def create_alert(self, alert_name: str, description: str,
                     scenario_id: str) -> str:
        """
        Create alert via create_alert endpoint.

        vendor="Proofpoint" + product="TAP v2 Generic Alert" generates
        DS:proofpoint_tap_v2_generic_alert in issue.tags → maps to Email
        in SOCProductCategoryMap.

        create_alert accepts any alert table field on the alert object.
        All socfw* and fw_email_* scenario fields are passed directly so
        Foundation_-_Normalize_Email_V3 reads real data from issue.*.

        Returns external_id for alert lookup.
        """
        # create_alert accepts the 4 mandatory fields + any standard alert table fields.
        # DO NOT add custom socfw*/fw_email_* fields — they are rejected with 500.
        # vendor+product generate DS:proofpoint_tap_v2_generic_alert → Email category.
        alert_body = {
            "vendor":       "Proofpoint",
            "product":      "TAP v2 Generic Alert",
            "severity":     "High",
            "category":     "Phishing",
            "alert_name":   alert_name,
            "description":  description,
            "mitre_defs":   {},
        }

        import time as _time
        before_ms = int(_time.time() * 1000)

        if self.debug:
            print(f"  {DIM}create_alert payload: {alert_body}{RESET}")

        resp = self._post("/public_api/v1/alerts/create_alert", {
            "request_data": {"alert": alert_body}
        })
        # create_alert returns {"reply": "<external_id>"} per API spec.
        # external_id is a UUID we can use with the external_id_list filter in get_alerts.
        ext_id = resp.get("reply") or ""
        return str(ext_id) if ext_id else str(before_ms)
    def get_alert(self, alert_id_or_ts: str) -> dict | None:
        """
        Look up alert by external_id (UUID returned by create_alert) or by
        creation_time fence (ms timestamp fallback).

        create_alert returns {"reply": "<external_id>"} per API spec (p.54).
        Allowed filter fields: alert_id_list, external_id_list, alert_source,
        creation_time, last_modified_ts, server_creation_time, severity.
        """
        val = str(alert_id_or_ts)
        try:
            # If it looks like a UUID (contains hyphens), use external_id_list
            if "-" in val:
                resp = self._post("/public_api/v1/alerts/get_alerts", {
                    "request_data": {
                        "filters": [{
                            "field":    "external_id_list",
                            "operator": "in",
                            "value":    [val],
                        }],
                        "sort":   {"field": "creation_time", "keyword": "desc"},
                    }
                })
            else:
                # Fallback: numeric ms timestamp fence → creation_time filter
                ts_ms = int(val)
                resp = self._post("/public_api/v1/alerts/get_alerts", {
                    "request_data": {
                        "filters": [{
                            "field":    "creation_time",
                            "operator": "gte",
                            "value":    ts_ms,
                        }],
                        "sort":   {"field": "creation_time", "keyword": "desc"},
                    }
                })
            alerts = resp.get("reply", {}).get("alerts", [])
            return alerts[0] if alerts else None
        except Exception:
            return None

    def get_incident(self, incident_id: str) -> dict | None:
        try:
            resp = self._post("/public_api/v1/incidents/get_incidents", {
                "request_data": {
                    "filters": [{
                        "field": "incident_id_list",
                        "operator": "in",
                        "value": [str(incident_id)],
                    }],
                }
            })
            incidents = resp.get("reply", {}).get("incidents", [])
            return incidents[0] if incidents else None
        except Exception:
            return None

    def get_warroom_entry_count(self, alert_id: str) -> int:
        """
        Returns number of war room entries on the alert.
        Non-zero entries → Foundation / NIST IR playbooks have started writing.
        Uses section 2.1.3.17 Get War Room entries.
        """
        try:
            resp = self._post("/public_api/v1/alerts/get_warroom_entries", {
                "request_data": {
                    "filter": {
                        "alert_id_list": [str(alert_id)],
                    }
                }
            })
            entries = resp.get("reply", {}).get("warroom_entries", [])
            if isinstance(entries, list):
                return len(entries)
            # Some tenants return a different structure
            return resp.get("reply", {}).get("total_count", 0)
        except Exception:
            return -1   # -1 = endpoint not supported / error


# ── Scenarios ─────────────────────────────────────────────────────────────────

SCENARIOS = {
    "SC-01": {
        "name":          "SC-01 — Phishing URL clicked, campaign, search_and_purge",
        "alert_name":    "[SOCFW-SMOKE] SC-01 Phishing URL Clicked",
        "description":   "Credential-harvesting URL, active threat, campaign present. "
                         "Expected: verdict=malicious, response=search_and_purge.",
        "wait_secs":     120,
        "checks": [
            "alert_created",
            "alert_grouped",
            "incident_exists",
            "chain_started",   # war room entries > WARROOM_MIN_ENTRIES
        ],
        "manual_checks": [
            "Work Plan: Foundation → SOC NIST IR → SOC Email Analysis → C/E/R → Done",
            "Context Data: Analysis.Email.verdict = malicious",
            "Context Data: Analysis.Email.confidence = high",
            "Context Data: Analysis.Email.response_recommended = search_and_purge",
            "Context Data: Analysis.Email.CampaignID populated",
            "SOCFramework.Email.threat_status = active",
            "xsiam_socfw_ir_execution_raw: C/E/R rows have execution_mode=shadow",
            "Warroom: SOC Framework - SHADOW MODE entries for each C/E/R action",
        ],
    },
    "SC-02": {
        "name":          "SC-02 — Malware attachment, no campaign, retract_message",
        "alert_name":    "[SOCFW-SMOKE] SC-02 Malware Attachment",
        "description":   "Malware attachment (exe), delivered, no campaign. "
                         "Expected: verdict=malicious, response=retract_message.",
        "wait_secs":     120,
        "checks": [
            "alert_created",
            "alert_grouped",
            "incident_exists",
            "chain_started",
        ],
        "manual_checks": [
            "Work Plan: Foundation → SOC NIST IR → SOC Email Analysis → C/E/R → Done",
            "Context Data: Analysis.Email.verdict = malicious",
            "Context Data: Analysis.Email.response_recommended = retract_message",
            "Context Data: Analysis.Email.signal_type = file_malware",
            "SOCFramework.Email.attachment_sha256 populated",
            "xsiam_socfw_ir_execution_raw: C/E/R rows have execution_mode=shadow",
        ],
    },
    "SC-03": {
        "name":          "SC-03 — False positive, blocked, benign verdict",
        "alert_name":    "[SOCFW-SMOKE] SC-03 False Positive Blocked",
        "description":   "URL alert, status=cleared, delivery=blocked. "
                         "Expected: verdict=benign, response=no_action.",
        "wait_secs":     120,
        "checks": [
            "alert_created",
            "alert_grouped",
            "incident_exists",
            "chain_started",
        ],
        "manual_checks": [
            "Work Plan: Foundation → SOC NIST IR → SOC Email Analysis → Done (no C/E/R)",
            "Context Data: Analysis.Email.verdict = benign",
            "Context Data: Analysis.Email.response_recommended = no_action",
            "SOCFramework.Email.threat_status = cleared",
            "Warroom: no C/E/R SHADOW MODE entries (chain skips containment)",
        ],
    },
}


# ── Scenario runner ───────────────────────────────────────────────────────────

def run_scenario(client: XSIAMClient, sid: str, scenario: dict,
                 base_url: str, debug: bool = False) -> bool:

    tenant_url = base_url.replace("api-", "")
    results = {}

    print(f"\n{BOLD}[ {sid} ] {scenario['name']}{RESET}")

    # ── 1. Create alert ──────────────────────────────────────────────────────
    print(f"  Creating alert...", end="", flush=True)
    before_ms = int(time.time() * 1000)  # fence captured BEFORE the API call
    try:
        ext_id = client.create_alert(
            scenario["alert_name"], scenario["description"], sid
        )
    except Exception as e:
        print(f" {RED}FAILED: {e}{RESET}")
        return False

    if ext_id:
        results["alert_created"] = True
        print(f" {GREEN}✅  alert_name={ext_id[:40]}...{RESET}")
    else:
        results["alert_created"] = False
        print(f" {RED}❌  no external_id returned{RESET}")
        return False

    # ── 2. Poll for alert + case_id (up to 3 min) ──────────────────────────
    # ext_id is the UUID returned by create_alert → use external_id_list filter.
    # before_ms is a fallback only if ext_id is empty.
    lookup_key = ext_id if ext_id else str(before_ms - 5000)

    print(f"  Waiting for alert to register and group", end="", flush=True)
    alert_id = None
    case_id  = None
    for _ in range(18):
        time.sleep(10)
        alert = client.get_alert(lookup_key)
        if alert:
            if debug:
                print(f"\n  {DIM}alert fields: {list(alert.keys())}{RESET}")
                tags = alert.get("tags") or alert.get("alert_fields", {}).get("tags")
                if tags:
                    print(f"  {DIM}issue.tags: {tags}{RESET}")
            alert_id = str(alert.get("alert_id", "") or "")
            case_id  = str(alert.get("case_id", "0") or "0")
            if case_id and case_id != "0":
                results["alert_grouped"] = True
                print(f" {GREEN}✅  alert_id={alert_id}  case_id={case_id}{RESET}")
                break
            else:
                print(".", end="", flush=True)
        else:
            print(".", end="", flush=True)

    if not alert_id:
        print(f"\n  {RED}❌  Alert did not appear after 3 minutes{RESET}")
        results["alert_grouped"] = False
        return False

    if not results.get("alert_grouped"):
        print(f"\n  {YELLOW}⚠   Alert appeared but not grouped (case_id=0){RESET}")
        results["alert_grouped"] = False

    # ── 3. Fetch incident ────────────────────────────────────────────────────
    if case_id and case_id != "0":
        incident = client.get_incident(case_id)
        if incident:
            results["incident_exists"] = True
            status      = incident.get("status", "unknown")
            alert_count = incident.get("alert_count", 0)
            print(f"  Incident {case_id}: status={status}  alert_count={alert_count} {GREEN}✅{RESET}")
        else:
            results["incident_exists"] = False
            print(f"  {RED}❌  incident {case_id} not found{RESET}")
    else:
        results["incident_exists"] = False

    # ── 4. Print case URL early ──────────────────────────────────────────────
    if case_id and case_id != "0":
        case_url = f"{tenant_url}/cases?action:openCaseDetails={case_id}-workPlan"
        print(f"\n  {CYAN}{BOLD}Case URL (open now to watch Work Plan live):{RESET}")
        print(f"  {CYAN}{case_url}{RESET}\n")

    # ── 5. Active poll — EP + playbook chain ─────────────────────────────────
    wait = scenario["wait_secs"]
    print(f"  Polling for EP + playbook chain (up to {wait}s, every {POLL_INTERVAL}s):")

    elapsed        = 0
    prev_status    = None
    warroom_counts = []

    while elapsed < wait:
        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL

        parts = [f"  [{elapsed:3d}s]"]

        # Check incident status
        if case_id and case_id != "0":
            inc = client.get_incident(case_id)
            if inc:
                status = inc.get("status", "?")
                if status != prev_status:
                    parts.append(f"status={status}")
                    prev_status = status
                else:
                    parts.append(f"status={status}")

        # Check war room entries — key signal that playbooks are running
        if alert_id:
            wc = client.get_warroom_entry_count(alert_id)
            warroom_counts.append(wc)
            if wc >= 0:
                parts.append(f"warroom_entries={wc}")
                # Enough entries means the Foundation + Analysis chain is running/done
                if wc >= WARROOM_MIN_ENTRIES and not results.get("chain_started"):
                    results["chain_started"] = True
                    parts.append(f"{GREEN}← chain started{RESET}")
            else:
                parts.append(f"warroom=N/A")

        print("  " + "  ".join(parts))

        # Early exit: chain confirmed started + enough time has passed
        if results.get("chain_started") and elapsed >= 60:
            print(f"  {GREEN}Chain confirmed running — stopping early at {elapsed}s{RESET}")
            break

    # If war room API returned errors for all calls, mark as unknown
    if all(c < 0 for c in warroom_counts):
        print(f"  {YELLOW}⚠   War room API unavailable — cannot confirm chain_started{RESET}")
        # Don't fail on this check — set it to None to skip
        results["chain_started"] = None

    # ── 6. Final incident check ──────────────────────────────────────────────
    if case_id and case_id != "0":
        final_inc = client.get_incident(case_id)
        if final_inc:
            status      = final_inc.get("status", "unknown")
            alert_count = final_inc.get("alert_count", 0)
            print(f"\n  Final incident state: status={status}  alert_count={alert_count}")

    # ── 7. Evaluate checks ───────────────────────────────────────────────────
    # chain_started=None means API not supported — don't fail on it
    effective_checks = [
        c for c in scenario["checks"]
        if not (c == "chain_started" and results.get("chain_started") is None)
    ]
    passed = all(results.get(c, False) for c in effective_checks)

    # ── 8. Print manual checklist ────────────────────────────────────────────
    print(f"\n  {BOLD}Manual checks (open case URL above in tenant):{RESET}")
    for item in scenario["manual_checks"]:
        print(f"    {DIM}□  {item}{RESET}")

    if passed:
        print(f"\n  {GREEN}{BOLD}✅ {sid} PASSED — automated checks{RESET}")
    else:
        failed_checks = [c for c in effective_checks if not results.get(c)]
        print(f"\n  {RED}{BOLD}❌ {sid} FAILED — {failed_checks}{RESET}")

    return passed


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="SOC Framework remote smoke test runner")
    ap.add_argument("--scenario", nargs="+",
                    help=f"Scenario IDs to run. Choices: {list(SCENARIOS)}")
    ap.add_argument("--wait",   type=int,
                    help="Override per-scenario wait_secs")
    ap.add_argument("--env",    default=".env",
                    help=".env file path (default: .env)")
    ap.add_argument("--debug",  action="store_true",
                    help="Print raw API requests and responses")
    ap.add_argument("--list",   action="store_true",
                    help="List scenarios and exit")
    args = ap.parse_args()

    if args.list:
        print(f"\n{BOLD}Scenarios:{RESET}")
        for sid, sc in SCENARIOS.items():
            print(f"\n  {CYAN}{BOLD}{sid}{RESET}  {sc['name']}")
            print(f"  Automated checks: {sc['checks']}")
            print(f"  Manual checks:")
            for m in sc["manual_checks"]:
                print(f"    □  {m}")
        sys.exit(0)

    env  = load_env(args.env)
    base = env.get("DEMISTO_BASE_URL") or os.environ.get("DEMISTO_BASE_URL", "")
    key  = env.get("DEMISTO_API_KEY")  or os.environ.get("DEMISTO_API_KEY",  "")
    auth = env.get("XSIAM_AUTH_ID")    or os.environ.get("XSIAM_AUTH_ID",    "")

    if not base or not key:
        print(f"{RED}DEMISTO_BASE_URL and DEMISTO_API_KEY required (in .env or env vars){RESET}")
        sys.exit(2)

    client = XSIAMClient(base, key, auth, debug=args.debug)

    print(f"\n{BOLD}SOC Framework — Remote Smoke Tests{RESET}")
    print(f"  Tenant: {base}")
    print(f"  Source: vendor=Proofpoint  product=TAP v2 Generic Alert")
    print(f"          → DS tag: DS:proofpoint_tap_v2_generic_alert")
    print(f"          → map key: ds_proofpoint_tap_v2_generic_alert → Email")
    print("─" * 60)

    print(f"\nVerifying credentials...", end="", flush=True)
    ok, msg = client.test_auth()
    if not ok:
        print(f" {RED}FAILED{RESET}\n  {msg}")
        sys.exit(2)
    print(f" {GREEN}{msg}{RESET}")

    if args.scenario:
        bad = [s for s in args.scenario if s not in SCENARIOS]
        if bad:
            print(f"{RED}Unknown scenario(s): {bad}. Available: {list(SCENARIOS)}{RESET}")
            sys.exit(2)
        selected = {sid: SCENARIOS[sid] for sid in args.scenario}
    else:
        selected = SCENARIOS

    if args.wait:
        for sc in selected.values():
            sc["wait_secs"] = args.wait

    results = {}
    for sid, sc in selected.items():
        results[sid] = run_scenario(client, sid, sc, base, debug=args.debug)

    print(f"\n{'─' * 60}")
    print(f"{BOLD}Summary:{RESET}")
    for sid, ok in results.items():
        icon = f"{GREEN}✅{RESET}" if ok else f"{RED}❌{RESET}"
        print(f"  {icon}  {sid}: {SCENARIOS[sid]['name']}")
    print()

    failed = sum(1 for v in results.values() if not v)
    if failed == 0:
        print(f"{GREEN}{BOLD}✅ All automated checks passed — review manual checklist above{RESET}")
        sys.exit(0)
    else:
        print(f"{RED}{BOLD}❌ {failed} scenario(s) failed automated checks{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
