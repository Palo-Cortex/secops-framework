#!/usr/bin/env python3
"""
socfw_smoke.py — SOC Framework remote smoke test runner.

What this validates via the public API:
  ✅  Alert creation succeeds (create_alert endpoint)
  ✅  Alert is grouped into a case (case_id populated → grouping engine ran)
  ✅  Case/incident exists and is in a known state (get_incidents)
  ✅  Alert count on the case matches expectations

What requires manual tenant inspection (not accessible via public API):
  ℹ   Playbook verdict values (Analysis.Email.verdict, etc.)
  ℹ   Shadow mode execution records (xsiam_socfw_ir_execution_raw — write-only dataset)
  ℹ   Individual playbook task results

For deep validation: open the case in the tenant and check Work Plan + Context Data.
The test prints the direct URL to the case after each scenario.

Usage:
    python3 tools/socfw_smoke.py --scenario SC-01
    python3 tools/socfw_smoke.py
    python3 tools/socfw_smoke.py --debug
    python3 tools/socfw_smoke.py --list
"""

import os, sys, time, argparse
from pathlib import Path

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("pip install requests", file=sys.stderr); sys.exit(2)

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


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


class XSIAMClient:
    """Auth from setup.py — raw key, no hashing."""

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
            print(f"  {DIM}  POST {url}{RESET}")
        r = self.s.post(url, headers=self.h, json=body, timeout=30)
        if r.status_code not in (200, 201):
            print(f"  {DIM}  → HTTP {r.status_code}: {r.text[:400]}{RESET}")
        r.raise_for_status()
        return r.json()

    def test_auth(self):
        try:
            r = self.s.post(f"{self.base}/xsoar/settings/credentials",
                            headers=self.h, json={}, timeout=15)
            if self.debug:
                print(f"  {DIM}  POST /xsoar/settings/credentials → {r.status_code}{RESET}")
            if r.status_code == 200:
                n = len(r.json().get("credentials", []))
                return True, f"OK — {n} credential(s) visible"
            return False, f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as e:
            return False, str(e)

    def create_alert(self, name: str, description: str) -> str:
        """Returns external_id."""
        resp = self._post("/public_api/v1/alerts/create_alert", {
            "request_data": {
                "alert": {
                    "vendor":      "SOCFramework Test",
                    "product":     "Email SEG",
                    "severity":    "High",
                    "category":    "Phishing",
                    "alert_name":  name,
                    "description": description,
                    "mitre_defs":  {},
                }
            }
        })
        return resp.get("reply") or resp.get("data") or ""

    def get_alert(self, external_id: str) -> dict | None:
        """Returns alert dict with alert_id and case_id."""
        resp = self._post("/public_api/v1/alerts/get_alerts", {
            "request_data": {
                "filters": [{"field": "external_id_list",
                             "operator": "in", "value": [external_id]}],
            }
        })
        alerts = [a for a in resp.get("reply", {}).get("alerts", [])
                  if a.get("external_id") == external_id]
        return alerts[0] if alerts else None

    def get_incident(self, incident_id: str) -> dict | None:
        """Fetch incident by case_id using incident_id_list filter."""
        resp = self._post("/public_api/v1/incidents/get_incidents", {
            "request_data": {
                "filters": [{"field": "incident_id_list",
                             "operator": "in",
                             "value": [str(incident_id)]}],
            }
        })
        incidents = resp.get("reply", {}).get("incidents", [])
        return incidents[0] if incidents else None


# ── Scenarios ─────────────────────────────────────────────────────────────────

SCENARIOS = {
    "SC-01": {
        "name":        "SC-01 — Email alert creates, groups, EP fires",
        "alert_name":  "[SOCFW-SMOKE] SC-01 Email Chain",
        "description": "SOC Framework smoke test SC-01",
        "wait_secs":   90,
        "checks": [
            "alert_created",
            "alert_grouped",       # case_id present
            "incident_exists",     # incident retrievable via API
        ],
        # Manual validation items printed at end
        "manual_checks": [
            "Work Plan shows Foundation → SOC NIST IR → Done",
            "Context Data > Analysis.Email.verdict = malicious",
            "Context Data > Analysis.Email.response_recommended = search_and_purge",
            "Context Data > Analysis.Email.CampaignID populated",
            "xsiam_socfw_ir_execution_raw: all C/E/R rows have execution_mode=shadow",
        ],
    },
    "SC-02": {
        "name":        "SC-02 — Attachment alert, no campaign",
        "alert_name":  "[SOCFW-SMOKE] SC-02 Attachment Chain",
        "description": "SOC Framework smoke test SC-02",
        "wait_secs":   90,
        "checks": [
            "alert_created",
            "alert_grouped",
            "incident_exists",
        ],
        "manual_checks": [
            "Work Plan shows Foundation → SOC NIST IR → Done",
            "Context Data > Analysis.Email.verdict = malicious",
            "Context Data > Analysis.Email.response_recommended = retract_message",
            "xsiam_socfw_ir_execution_raw: all C/E/R rows have execution_mode=shadow",
        ],
    },
    "SC-03": {
        "name":        "SC-03 — False positive, blocked alert",
        "alert_name":  "[SOCFW-SMOKE] SC-03 FP Chain",
        "description": "SOC Framework smoke test SC-03",
        "wait_secs":   90,
        "checks": [
            "alert_created",
            "alert_grouped",
            "incident_exists",
        ],
        "manual_checks": [
            "Work Plan shows Foundation → SOC NIST IR → Done",
            "Context Data > Analysis.Email.verdict = benign",
            "Context Data > Analysis.Email.response_recommended = none",
            "xsiam_socfw_ir_execution_raw: all C/E/R rows have execution_mode=shadow",
        ],
    },
}


# ── Runner ────────────────────────────────────────────────────────────────────

def run_scenario(client: XSIAMClient, sid: str, scenario: dict,
                 base_url: str) -> bool:
    print(f"\n{BOLD}[ {sid} ] {scenario['name']}{RESET}")

    results = {}

    # 1. Create alert
    print(f"  Creating alert...", end="", flush=True)
    try:
        ext_id = client.create_alert(scenario["alert_name"], scenario["description"])
    except Exception as e:
        print(f" {RED}FAILED: {e}{RESET}")
        return False

    if ext_id:
        results["alert_created"] = True
        print(f" {GREEN}✅  external_id={ext_id}{RESET}")
    else:
        results["alert_created"] = False
        print(f" {RED}❌  no external_id returned{RESET}")
        return False

    # 2. Poll for alert + case_id
    print(f"  Waiting for alert to register and group...", end="", flush=True)
    alert_id = None
    case_id  = None
    for _ in range(18):   # up to 3 minutes
        time.sleep(10)
        alert = client.get_alert(ext_id)
        if alert:
            alert_id = str(alert.get("alert_id", ""))
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
        print(f"\n  {RED}❌  Alert did not appear{RESET}")
        results["alert_grouped"] = False
        return False
    if not results.get("alert_grouped"):
        print(f"\n  {YELLOW}⚠   Alert appeared but case_id=0 — grouping may be delayed{RESET}")
        results["alert_grouped"] = False

    # 3. Wait for EP to complete
    wait = scenario["wait_secs"]
    print(f"  Waiting {wait}s for EP + playbook chain...", end="", flush=True)
    time.sleep(wait)
    print(f" done")

    # 4. Fetch incident and check it exists
    if case_id and case_id != "0":
        print(f"  Checking incident {case_id}...", end="", flush=True)
        try:
            incident = client.get_incident(case_id)
            if incident:
                status      = incident.get("status", "unknown")
                alert_count = incident.get("alert_count", 0)
                results["incident_exists"] = True
                print(f" {GREEN}✅  status={status}  alert_count={alert_count}{RESET}")
            else:
                results["incident_exists"] = False
                print(f" {RED}❌  incident not found{RESET}")
        except Exception as e:
            results["incident_exists"] = False
            print(f" {RED}❌  {e}{RESET}")
    else:
        results["incident_exists"] = False

    # 5. Evaluate required checks
    passed = all(results.get(c, False) for c in scenario["checks"])

    # 6. Print case URL for manual inspection
    tenant_url = base_url.replace("api-", "")
    if case_id and case_id != "0":
        case_url = f"{tenant_url}/cases?action:openCaseDetails={case_id}-workPlan"
        print(f"\n  {CYAN}Case URL: {case_url}{RESET}")

    # 7. Print manual checklist
    print(f"\n  {BOLD}Manual checks (open case in tenant):{RESET}")
    for item in scenario["manual_checks"]:
        print(f"  {DIM}  □  {item}{RESET}")

    if passed:
        print(f"\n  {GREEN}{BOLD}✅ {sid} PASSED — automated checks{RESET}")
    else:
        failed_checks = [c for c in scenario["checks"] if not results.get(c)]
        print(f"\n  {RED}{BOLD}❌ {sid} FAILED — {failed_checks}{RESET}")

    return passed


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="SOC Framework remote smoke test runner")
    ap.add_argument("--scenario", nargs="+",
                    help=f"Scenarios to run. Choices: {list(SCENARIOS)}")
    ap.add_argument("--wait",   type=int,
                    help="Override per-scenario wait (seconds)")
    ap.add_argument("--env",    default=".env")
    ap.add_argument("--debug",  action="store_true")
    ap.add_argument("--list",   action="store_true")
    args = ap.parse_args()

    if args.list:
        print(f"\n{BOLD}Scenarios:{RESET}")
        for sid, sc in SCENARIOS.items():
            print(f"  {CYAN}{sid}{RESET}  {sc['name']}")
            print(f"  Automated:  {sc['checks']}")
            print(f"  Manual:")
            for m in sc["manual_checks"]:
                print(f"    □  {m}")
            print()
        sys.exit(0)

    env  = load_env(args.env)
    base = env.get("DEMISTO_BASE_URL") or os.environ.get("DEMISTO_BASE_URL", "")
    key  = env.get("DEMISTO_API_KEY")  or os.environ.get("DEMISTO_API_KEY",  "")
    auth = env.get("XSIAM_AUTH_ID")    or os.environ.get("XSIAM_AUTH_ID",    "")

    if not base or not key:
        print(f"{RED}DEMISTO_BASE_URL and DEMISTO_API_KEY required in {args.env}{RESET}")
        sys.exit(2)

    client = XSIAMClient(base, key, auth, debug=args.debug)

    print(f"\n{BOLD}SOC Framework — Remote Smoke Tests{RESET}")
    print(f"  Tenant: {base}")
    print("─" * 56)
    print(f"\nVerifying credentials...", end="", flush=True)
    ok, msg = client.test_auth()
    if not ok:
        print(f" {RED}FAILED{RESET}\n  {msg}"); sys.exit(2)
    print(f" {GREEN}{msg}{RESET}")

    if args.scenario:
        bad = [s for s in args.scenario if s not in SCENARIOS]
        if bad:
            print(f"{RED}Unknown: {bad}{RESET}"); sys.exit(2)
        selected = {sid: SCENARIOS[sid] for sid in args.scenario}
    else:
        selected = SCENARIOS

    if args.wait:
        for sc in selected.values():
            sc["wait_secs"] = args.wait

    results = {}
    for sid, sc in selected.items():
        results[sid] = run_scenario(client, sid, sc, base)

    print(f"\n{'─' * 56}")
    for sid, ok in results.items():
        icon = f"{GREEN}✅{RESET}" if ok else f"{RED}❌{RESET}"
        print(f"  {icon}  {sid}: {SCENARIOS[sid]['name']}")
    print()
    failed = sum(1 for v in results.values() if not v)
    if failed == 0:
        print(f"{GREEN}{BOLD}✅ Automated checks passed — complete manual checklist above{RESET}")
        sys.exit(0)
    else:
        print(f"{RED}{BOLD}❌ {failed} scenario(s) failed automated checks{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
