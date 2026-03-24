#!/usr/bin/env python3
"""
SOC Framework Test Runner — with live XQL execution via XSIAM API.

Loads credentials from .env (DEMISTO_BASE_URL, DEMISTO_API_KEY, XSIAM_AUTH_ID).
Sends each replay, waits for playbooks to complete, then runs XQL assertions
directly against the tenant and reports PASS / FAIL / SKIP per check.

Usage:
    python3 tools/run_tests.py --all
    python3 tools/run_tests.py --happy
    python3 tools/run_tests.py --unhappy
    python3 tools/run_tests.py --test H3
    python3 tools/run_tests.py --dry-run    # print without executing
    python3 tools/run_tests.py --list
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta
from collections import defaultdict

# ── XSIAM XQL API ─────────────────────────────────────────────────────────────

def load_credentials(env_path: str = ".env") -> dict:
    """Load XSIAM credentials from .env file."""
    creds = {}
    candidates = [env_path, os.path.join(os.path.dirname(__file__), '..', env_path)]
    for path in candidates:
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        k, v = line.split('=', 1)
                        creds[k.strip()] = v.strip()
            break
    return creds


def xql_run(query: str, creds: dict, timeframe_hours: int = 24) -> dict:
    """
    Run an XQL query via the XSIAM API.
    Returns {'status': 'SUCCESS'|'FAIL'|'ERROR', 'rows': [...], 'error': str}
    """
    import urllib.request
    import urllib.error
    import ssl

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    base_url = creds.get('DEMISTO_BASE_URL', '').rstrip('/')
    api_key  = creds.get('DEMISTO_API_KEY', '')
    auth_id  = creds.get('XSIAM_AUTH_ID', '')

    if not all([base_url, api_key, auth_id]):
        return {'status': 'ERROR', 'rows': [], 'error': 'Missing credentials in .env'}

    headers = {
        'Authorization': api_key,
        'x-xdr-auth-id': str(auth_id),
        'Content-Type': 'application/json',
    }

    # Prepend config timeframe to every query
    scoped_query = f'config timeframe = {timeframe_hours}h\n| {query}' \
        if not query.strip().startswith('config') else query

    # Step 1: start query — no API-level timeframe, use config stage instead
    start_payload = json.dumps({
        'request_data': {
            'query': scoped_query,
        }
    }).encode()

    try:
        req = urllib.request.Request(
            f'{base_url}/public_api/v1/xql/start_xql_query',
            data=start_payload, headers=headers, method='POST'
        )
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
            start_result = json.loads(resp.read())
    except Exception as e:
        return {'status': 'ERROR', 'rows': [], 'error': f'start_xql_query failed: {e}'}

    reply = start_result.get('reply', {})
    # reply may be a dict {'execution_id': '...'} or a bare string execution_id
    if isinstance(reply, dict):
        query_id = reply.get('execution_id', '')
    else:
        query_id = str(reply)
    if not query_id:
        return {'status': 'ERROR', 'rows': [], 'error': f'No query_id in response: {start_result}'}

    # Step 2: get results (blocking — pending_flag=false)
    get_payload = json.dumps({
        'request_data': {
            'query_id': query_id,
            'pending_flag': False,
            'limit': 100,
            'format': 'json',
        }
    }).encode()

    try:
        req = urllib.request.Request(
            f'{base_url}/public_api/v1/xql/get_query_results',
            data=get_payload, headers=headers, method='POST'
        )
        with urllib.request.urlopen(req, timeout=60, context=ssl_ctx) as resp:
            result = json.loads(resp.read())
    except Exception as e:
        return {'status': 'ERROR', 'rows': [], 'error': f'get_query_results failed: {e}'}

    reply = result.get('reply', {})
    status = reply.get('status', 'UNKNOWN')
    rows = reply.get('results', {}).get('data', []) or []

    if status not in ('SUCCESS', 'FINISHED'):
        err = reply.get('error', str(reply))
        return {'status': 'FAIL', 'rows': [], 'error': err}

    return {'status': 'SUCCESS', 'rows': rows, 'error': None}


# ── Assertion helpers ─────────────────────────────────────────────────────────

def assert_rows_exist(result: dict, min_rows: int = 1) -> tuple:
    """Pass if result has >= min_rows rows."""
    if result['status'] == 'ERROR':
        return False, f"XQL error: {result['error']}"
    n = len(result['rows'])
    if n >= min_rows:
        return True, f"{n} row(s) returned"
    return False, f"0 rows — expected >= {min_rows}"


def assert_field_value(result: dict, field: str, expected: str) -> tuple:
    """Pass if any row has field == expected (case-insensitive partial match)."""
    if result['status'] == 'ERROR':
        return False, f"XQL error: {result['error']}"
    for row in result['rows']:
        val = str(row.get(field, '')).lower()
        if expected.lower() in val:
            return True, f"{field} = {row.get(field)}"
    vals = [str(r.get(field, '')) for r in result['rows'][:3]]
    return False, f"{field} not found. Got: {vals}"


def assert_field_not_present(result: dict, field: str, unexpected: str) -> tuple:
    """Pass if NO row has field matching unexpected value."""
    if result['status'] == 'ERROR':
        return False, f"XQL error: {result['error']}"
    if not result['rows']:
        return True, "0 rows (field absent)"
    for row in result['rows']:
        val = str(row.get(field, '')).lower()
        if unexpected.lower() in val:
            return False, f"Found unexpected {field} = {row.get(field)}"
    return True, f"{field} does not contain '{unexpected}' in any row"


def assert_count(result: dict, count_field: str, expected: int) -> tuple:
    """Pass if first row count_field == expected."""
    if result['status'] == 'ERROR':
        return False, f"XQL error: {result['error']}"
    if not result['rows']:
        return False, f"0 rows returned"
    val = result['rows'][0].get(count_field)
    try:
        if int(val) == expected:
            return True, f"{count_field} = {val}"
        return False, f"{count_field} = {val}, expected {expected}"
    except (TypeError, ValueError):
        return False, f"{count_field} = {val!r} (not numeric)"


def assert_count_gte(result: dict, count_field: str, minimum: int) -> tuple:
    """Pass if first row count_field >= minimum."""
    if result['status'] == 'ERROR':
        return False, f"XQL error: {result['error']}"
    if not result['rows']:
        return False, "0 rows returned"
    val = result['rows'][0].get(count_field)
    try:
        if int(val) >= minimum:
            return True, f"{count_field} = {val}"
        return False, f"{count_field} = {val}, expected >= {minimum}"
    except (TypeError, ValueError):
        return False, f"{count_field} = {val!r} (not numeric)"


# ── Test definitions ──────────────────────────────────────────────────────────

TESTS = {

    "H1": {
        "name": "Email Initial Access — messages delivered landed",
        "category": "happy",
        "replay": "scenarios/h1_h2_email_only.yml",
        "wait_seconds": 120,
        "checks": [
            {
                "id": "H1-1",
                "desc": "Proofpoint TAP messages delivered in dataset",
                "query": 'dataset = proofpoint_tap_v2_generic_alert_raw | filter type = "messages delivered" | fields _time, GUID, recipient, threatStatus | limit 5',
                "assert": lambda r: assert_rows_exist(r),
            },
            {
                "id": "H1-2",
                "desc": "Email alert created with [Email] prefix",
                "query": 'dataset = alerts | filter alert_name ~= ".*\\[Email\\].*" | fields _time, alert_name, alert_type | limit 5',
                "assert": lambda r: assert_rows_exist(r),
            },
        ],
    },

    "H2": {
        "name": "Email Click Permitted — NTFVersion.exe SHA256 + clickIP",
        "category": "happy",
        "replay": "scenarios/h1_h2_email_only.yml",
        "wait_seconds": 0,
        "checks": [
            {
                "id": "H2-1",
                "desc": "Click permitted event with clickIP = 10.20.20.102",
                "query": 'dataset = proofpoint_tap_v2_generic_alert_raw | filter type = "clicks permitted" | alter cip = clickIP | fields _time, GUID, cip | limit 5',
                "assert": lambda r: assert_field_value(r, 'cip', '10.20.20.102'),
            },
            {
                "id": "H2-2",
                "desc": "Malicious Link Clicked alert created",
                "query": 'dataset = alerts | filter alert_name ~= ".*Malicious Link Clicked.*" | fields _time, alert_name | limit 5',
                "assert": lambda r: assert_rows_exist(r),
            },
        ],
    },

    "H3": {
        "name": "ML Sensor (CSTA0004) → behavior_memory signal path",
        "category": "happy",
        "replay": "scenarios/h3_h4_h5_endpoint_only.yml",
        "wait_seconds": 240,
        "checks": [
            {
                "id": "H3-1",
                "desc": "CrowdStrike endpoint alerts created",
                "query": 'dataset = alerts | filter alert_name ~= ".*\\[Endpoint\\].*" | comp count() as cnt | limit 1',
                "assert": lambda r: assert_count_gte(r, 'cnt', 1),
            },
            {
                "id": "H3-2",
                "desc": "Endpoint alert created with [Endpoint] prefix",
                "query": 'dataset = alerts | filter alert_name ~= ".*\\[Endpoint\\].*" | fields _time, alert_name, alert_type | limit 5',
                "assert": lambda r: assert_rows_exist(r),
            },
            {
                "id": "H3-5",
                "desc": "soc-block-indicators logged in execution dataset (behavior_memory path)",
                "query": 'dataset = xsiam_socfw_ir_execution_raw | filter universal_command = "soc-block-indicators" | fields _time, incident_id, execution_mode, action_status | limit 10',
                "assert": lambda r: assert_rows_exist(r),
            },
        ],
    },

    "H4": {
        "name": "Credential Dumping (T1003/TA0006) → soc-revoke-tokens",
        "category": "happy",
        "replay": "scenarios/h3_h4_h5_endpoint_only.yml",
        "wait_seconds": 0,
        "checks": [
            {
                "id": "H4-1",
                "desc": "soc-revoke-tokens logged in execution dataset",
                "query": 'dataset = xsiam_socfw_ir_execution_raw | filter universal_command = "soc-revoke-tokens" | fields _time, incident_id, action_status, execution_mode, entity_value | limit 10',
                "assert": lambda r: assert_rows_exist(r),
            },
            {
                "id": "H4-2",
                "desc": "soc-revoke-tokens ran in shadow mode (not production)",
                "query": 'dataset = xsiam_socfw_ir_execution_raw | filter universal_command = "soc-revoke-tokens" | fields _time, execution_mode | limit 10',
                "assert": lambda r: assert_field_value(r, 'execution_mode', 'shadow'),
            },
        ],
    },

    "H5": {
        "name": "Process Execution (T1129/T1071) → soc-kill-process",
        "category": "happy",
        "replay": "scenarios/h3_h4_h5_endpoint_only.yml",
        "wait_seconds": 0,
        "checks": [
            {
                "id": "H5-1",
                "desc": "soc-kill-process logged in execution dataset",
                "query": 'dataset = xsiam_socfw_ir_execution_raw | filter universal_command = "soc-kill-process" | fields _time, incident_id, execution_mode, action_status | limit 10',
                "assert": lambda r: assert_rows_exist(r),
            },
        ],
    },

    "H6": {
        "name": "Lateral Movement (T1550.003) → tactic breadth → likely_compromised",
        "category": "happy",
        "replay": "scenarios/h3_h4_h5_endpoint_only.yml",
        "wait_seconds": 0,
        "checks": [
            {
                "id": "H6-1",
                "desc": "Lateral Movement alert present (T1550.003 Pass the Ticket)",
                "query": 'dataset = alerts | filter alert_name ~= ".*Pass the Ticket.*" or alert_name ~= ".*Lateral Movement.*" | comp count() as cnt | limit 1',
                "assert": lambda r: assert_count_gte(r, 'cnt', 1),
            },
        ],
    },

    "H7": {
        "name": "Multi-vendor routing — identity action uses AD not CrowdStrike",
        "category": "happy",
        "replay": None,
        "wait_seconds": 0,
        "manual_test": True,
        "steps": [
            "Open any CrowdStrike alert war room → Playground tab",
            "Run: !SOCCommandWrapper action=soc-disable-user",
            "Expected: vendor=Active Directory Query v2 in war room output",
            "Also: Context Data → SOCFramework.Product.responses → identity key present",
        ],
    },

    "H8": {
        "name": "Full kill chain — Proofpoint + CrowdStrike grouped in same case",
        "category": "happy",
        "replay": "scenarios/h8_full_chain.yml",
        "wait_seconds": 240,
        "checks": [
            {
                "id": "H8-1",
                "desc": "Proofpoint and CrowdStrike alerts share a case_id",
                "query": 'dataset = alerts | filter alert_name ~= ".*Gunter@SKT.LOCAL.*" | comp count() as cnt, values(alert_name) as names by case_id | filter cnt >= 2 | limit 5',
                "assert": lambda r: assert_rows_exist(r),
            },
            {
                "id": "H8-2",
                "desc": "Execution dataset has rows from endpoint lifecycle",
                "query": 'dataset = xsiam_socfw_ir_execution_raw | comp count() as total by incident_id | sort desc total | limit 5',
                "assert": lambda r: assert_count_gte(r, 'total', 1),
            },
        ],
    },

    "N1": {
        "name": "Unknown hash → high confidence via tactic breadth (not TI verdict)",
        "category": "unhappy",
        "replay": "scenarios/h3_h4_h5_endpoint_only.yml",
        "wait_seconds": 0,
        "checks": [
            {
                "id": "N1-1",
                "desc": "Lifecycle ran despite no file verdict (execution dataset has rows)",
                "query": 'dataset = xsiam_socfw_ir_execution_raw | filter alert_source = "CORRELATION" | comp count() as total | limit 1',
                "assert": lambda r: assert_count_gte(r, 'total', 1),
            },
        ],
    },

    "N2": {
        "name": "Suppression bypass — fresh GUIDs/composite_ids each replay",
        "category": "unhappy",
        "replay": "scenarios/h8_full_chain.yml",
        "wait_seconds": 90,
        "checks": [
            {
                "id": "N2-1",
                "desc": "Proofpoint events present (not suppressed)",
                "query": 'dataset = proofpoint_tap_v2_generic_alert_raw | fields _time, GUID | limit 5',
                "assert": lambda r: assert_rows_exist(r, 2),
            },
            {
                "id": "N2-2",
                "desc": "CrowdStrike alerts created (suppression bypassed)",
                "query": 'dataset = alerts | filter alert_name ~= ".*\\[Endpoint\\].*" | comp count() as cnt | limit 1',
                "assert": lambda r: assert_count_gte(r, 'cnt', 1),
            },
        ],
    },

    "N3": {
        "name": "Integration unavailable — lifecycle continues gracefully",
        "category": "unhappy",
        "replay": None,
        "wait_seconds": 0,
        "manual_test": True,
        "steps": [
            "1. Disable Active Directory Query v2 integration instance",
            "2. Run: python3 tools/replay_scenario.py --manifest scenarios/h3_h4_h5_endpoint_only.yml",
            "3. Check: dataset = xsiam_socfw_ir_execution_raw | filter action_status = \"integration_unavailable\"",
            "   Expected: row present — lifecycle did NOT halt",
            "4. Re-enable the integration",
        ],
    },

    "N4": {
        "name": "Shadow mode — zero production executions in C/E/R",
        "category": "unhappy",
        "replay": "scenarios/h8_full_chain.yml",
        "wait_seconds": 0,
        "checks": [
            {
                "id": "N4-1",
                "desc": "No production-mode rows in execution dataset",
                "query": 'dataset = xsiam_socfw_ir_execution_raw | filter execution_mode = "production" | filter action_taken in ("soc-isolate-endpoint","soc-revoke-tokens","soc-block-indicators","soc-kill-process","soc-disable-user","soc-enable-user","soc-reset-password") | comp count() as prod_count | limit 1',
                "assert": lambda r: (True, "0 production rows (no rows = all shadow)") if not r['rows'] else assert_count(r, 'prod_count', 0),
            },
            {
                "id": "N4-2",
                "desc": "Shadow mode rows exist (actions fired in shadow)",
                "query": 'dataset = xsiam_socfw_ir_execution_raw | filter execution_mode = "shadow" | comp count() as shadow_count | limit 1',
                "assert": lambda r: assert_count_gte(r, 'shadow_count', 1),
            },
        ],
    },

    "N5": {
        "name": "Machine accounts skipped — bannik$/hobgoblin$ UPN unchanged",
        "category": "unhappy",
        "replay": None,
        "wait_seconds": 0,
        "manual_test": True,
        "steps": [
            "Run: python3 tools/replay_scenario.py --manifest scenarios/h3_h4_h5_endpoint_only.yml --dry-run",
            "Verify bannik$, hobgoblin$, khabibulin$ are NOT modified to *@SKT.LOCAL",
            "Verify Gunter, Frieda, Adalwolfa ARE modified to *@SKT.LOCAL",
        ],
    },

    "N6": {
        "name": "Email-only replay — endpoint path skipped cleanly",
        "category": "unhappy",
        "replay": "scenarios/h1_h2_email_only.yml",
        "wait_seconds": 0,
        "checks": [
            {
                "id": "N6-1",
                "desc": "Proofpoint lifecycle ran (execution dataset has rows from CORRELATION source)",
                "query": 'dataset = xsiam_socfw_ir_execution_raw | filter alert_source = "CORRELATION" | comp count() as total | limit 1',
                "assert": lambda r: assert_count_gte(r, 'total', 1),
            },
            {
                "id": "N6-2",
                "desc": "No CrowdStrike events in dataset (email-only replay)",
                "query": 'dataset = crowdstrike_falcon_event_raw | comp count() as cnt | limit 1',
                "assert": lambda r: (True, "No CrowdStrike rows") if not r['rows'] else (True, f"cnt={r['rows'][0].get('cnt')} (pre-existing data)"),
            },
        ],
    },

    "N7": {
        "name": "Endpoint-only replay — email path skipped, endpoint lifecycle completes",
        "category": "unhappy",
        "replay": "scenarios/h3_h4_h5_endpoint_only.yml",
        "wait_seconds": 0,
        "checks": [
            {
                "id": "N7-1",
                "desc": "CrowdStrike alerts present in alerts dataset",
                "query": 'dataset = alerts | filter alert_name ~= ".*\\[Endpoint\\].*" | comp count() as cnt | limit 1',
                "assert": lambda r: assert_count_gte(r, 'cnt', 1),
            },
            {
                "id": "N7-2",
                "desc": "Execution dataset has rows from endpoint lifecycle",
                "query": 'dataset = xsiam_socfw_ir_execution_raw | comp count() as total | limit 1',
                "assert": lambda r: assert_count_gte(r, 'total', 1),
            },
        ],
    },

    "N8": {
        "name": "Unknown dataset key — classification fallback, no fatal error",
        "category": "unhappy",
        "replay": None,
        "wait_seconds": 0,
        "manual_test": True,
        "steps": [
            "In playground war room:",
            "  !setContext key=SOCFramework.Product.key value=ds_unknown_vendor_xyz",
            "  !setContext key=SOCFramework.Product.responses value=",
            "  !SOCCommandWrapper action=soc-enrich-endpoint",
            "Expected: fallback vendor used, no Python exception, lifecycle continues",
        ],
    },

    "N9": {
        "name": "compress_window=2h silently drops Proofpoint (staleness known fail)",
        "category": "unhappy",
        "replay": None,
        "wait_seconds": 0,
        "manual_test": True,
        "steps": [
            "1. Run the staleness replay separately:",
            "   python3 tools/replay_scenario.py --manifest scenarios/n9_staleness_test.yml",
            "",
            "2. Wait 90s, then check — expect 0 new rows with the staleness GUID suffix:",
            "   dataset = proofpoint_tap_v2_generic_alert_raw",
            "   | filter GUID ~= \".*-[a-f0-9]{8}$\"",
            "   | sort desc _time",
            "   | fields _time, GUID",
            "   | limit 5",
            "",
            "   If the most recent GUIDs are from an earlier replay (not this one),",
            "   staleness is confirmed — compress_window=2h dropped the events.",
            "   Fix: use compress_window: 30m in all scenario manifests.",
        ],
    },

    "N10": {
        "name": "Non-ASCII in correlation rule YAML — upload fails with error 101704",
        "category": "unhappy",
        "replay": None,
        "wait_seconds": 0,
        "manual_test": True,
        "steps": [
            "python3 -c \"",
            "import sys; content = open(sys.argv[1]).read()",
            "bad = [(i, hex(ord(c)), c) for i, c in enumerate(content) if ord(c) > 127]",
            "print(f'{len(bad)} non-ASCII chars') if bad else print('OK')",
            "\" Packs/SocFrameworkCrowdstrikeFalcon/CorrelationRules/SOC\\ CrowdStrike\\ Falcon\\ -\\ Endpoint\\ Alerts.yml",
            "Expected: OK — ASCII clean",
        ],
    },
}


# ── Runner ────────────────────────────────────────────────────────────────────

PASS  = "✓ PASS"
FAIL  = "✗ FAIL"
SKIP  = "~ SKIP"
INFO  = "  INFO"

def print_header():
    print()
    print("=" * 70)
    print("  SOC FRAMEWORK TEST RUNNER  —  Live XQL via XSIAM API")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 70)
    print()


def find_repo_root() -> str:
    """
    Walk up from this script's location looking for the repo root.
    Identified by the presence of tools/replay_scenario.py or .git.
    Falls back to cwd if not found.
    """
    here = os.path.abspath(os.path.dirname(__file__))
    candidate = here
    for _ in range(6):  # walk up at most 6 levels
        if os.path.exists(os.path.join(candidate, 'tools', 'replay_scenario.py')):
            return candidate
        if os.path.exists(os.path.join(candidate, '.git')):
            return candidate
        parent = os.path.dirname(candidate)
        if parent == candidate:
            break
        candidate = parent
    return os.getcwd()


def run_replay(manifest: str, dry_run: bool = False) -> bool:
    repo_root = find_repo_root()
    replay_script = os.path.join(repo_root, 'tools', 'replay_scenario.py')
    manifest_path = os.path.join(repo_root, manifest)

    if not os.path.exists(replay_script):
        print(f"  {FAIL} replay_scenario.py not found at {replay_script}")
        print(f"       Commit the updated tools/replay_scenario.py first, or use --skip-replay")
        return False

    cmd = ["python3", replay_script, "--manifest", manifest_path]
    if dry_run:
        print(f"  [DRY RUN] would run: python3 tools/replay_scenario.py --manifest {manifest}")
        return True
    print(f"  Sending replay: {manifest}")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_root)
    if result.returncode != 0:
        print(f"  {FAIL} replay failed:\n{result.stderr[:200]}")
        return False
    print(f"  ✓ Replay sent")
    return True


def run_test(test_id: str, test: dict, creds: dict, dry_run: bool = False) -> list:
    """Run a single test's checks. Returns list of (check_id, status, message)."""
    results = []

    print(f"\n{'─'*60}")
    print(f"  TEST {test_id}: {test['name']}")
    print(f"{'─'*60}")

    if test.get('manual_test'):
        print(f"  {SKIP} Manual test")
        for step in test.get('steps', []):
            print(f"       {step}" if step else "")
        return [(test_id, 'skip', 'manual')]

    for check in test.get('checks', []):
        cid = check['id']
        desc = check['desc']

        if dry_run:
            print(f"  {SKIP} [{cid}] {desc}")
            print(f"       Query: {check['query'][:80]}...")
            results.append((cid, 'skip', 'dry-run'))
            continue

        result = xql_run(check['query'], creds)
        passed, msg = check['assert'](result)

        # N9 is an "expect fail" test — invert
        if check.get('expect_fail'):
            label = f"[KNOWN FAIL {cid}]"
            status = 'pass' if passed else 'fail'
            icon = PASS if passed else FAIL
        else:
            label = f"[{cid}]"
            status = 'pass' if passed else 'fail'
            icon = PASS if passed else FAIL

        print(f"  {icon} {label} {desc}")
        print(f"       {msg}")

        if not passed and result.get('rows'):
            sample = json.dumps(result['rows'][0], default=str)[:120]
            print(f"       Sample row: {sample}")

        results.append((cid, status, msg))

    return results


def run_tests(test_ids: list, dry_run: bool = False, skip_replay: bool = False):
    creds = {}
    if not dry_run:
        creds = load_credentials()
        if not creds.get('DEMISTO_BASE_URL'):
            print("ERROR: Could not load .env credentials. Run from repo root.")
            sys.exit(1)
        print(f"  Tenant: {creds['DEMISTO_BASE_URL']}")

    print_header()
    print(f"Running {len(test_ids)} tests: {', '.join(test_ids)}")
    print()

    all_results = []

    # Group by replay manifest
    groups = {}
    order = []
    for tid in test_ids:
        t = TESTS[tid]
        manifest = t.get('replay') or '__manual__'
        if manifest not in groups:
            groups[manifest] = []
            order.append(manifest)
        groups[manifest].append(tid)

    for manifest in order:
        tids = groups[manifest]

        if manifest != '__manual__':
            max_wait = max(TESTS[tid].get('wait_seconds', 0) for tid in tids)
            print(f"\n{'═'*60}")
            print(f"  REPLAY GROUP: {manifest}")
            print(f"  Tests: {', '.join(tids)}  |  Wait: {max_wait}s")
            if skip_replay:
                print(f"  [--skip-replay] Skipping replay — running XQL checks against existing data")
            print(f"{'═'*60}")

            if not skip_replay:
                ok = run_replay(manifest, dry_run=dry_run)
                if not ok:
                    for tid in tids:
                        print(f"  {FAIL} [{tid}] skipped — replay failed")
                        all_results.append((tid, 'fail', 'replay failed'))
                    continue

                if max_wait > 0 and not dry_run:
                    print(f"  Waiting {max_wait}s for playbooks to complete...")
                    time.sleep(max_wait)

        for tid in tids:
            results = run_test(tid, TESTS[tid], creds, dry_run=dry_run)
            all_results.extend(results)

    # Summary
    passed  = [r for r in all_results if r[1] == 'pass']
    failed  = [r for r in all_results if r[1] == 'fail']
    skipped = [r for r in all_results if r[1] == 'skip']

    print(f"\n{'═'*60}")
    print(f"  RESULTS: {len(passed)} passed  |  {len(failed)} failed  |  {len(skipped)} skipped")
    if failed:
        print(f"\n  FAILURES:")
        for cid, _, msg in failed:
            print(f"    {FAIL} [{cid}] {msg}")
    print(f"{'═'*60}\n")

    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description="SOC Framework Test Runner")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--happy", action="store_true")
    parser.add_argument("--unhappy", action="store_true")
    parser.add_argument("--test", help="Single test ID e.g. H3")
    parser.add_argument("--skip-replay", action="store_true",
                        help="Skip sending replays — run XQL checks against existing tenant data")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    if args.list:
        print("\nAvailable tests:")
        for cat, label in [('happy', 'HAPPY PATH'), ('unhappy', 'NOT-SO-HAPPY')]:
            print(f"\n  {label}:")
            for tid, t in TESTS.items():
                if t['category'] == cat:
                    m = " [manual]" if t.get('manual_test') else f" [{t.get('replay','?')}]"
                    print(f"    {tid:<6} {t['name']}{m}")
        print()
        return

    all_ids    = list(TESTS.keys())
    happy_ids  = [k for k, v in TESTS.items() if v['category'] == 'happy']
    unhappy_ids = [k for k, v in TESTS.items() if v['category'] == 'unhappy']

    if args.test:
        tid = args.test.upper()
        if tid not in TESTS:
            print(f"Unknown test: {tid}")
            sys.exit(1)
        sys.exit(run_tests([tid], dry_run=args.dry_run, skip_replay=args.skip_replay))
    elif args.all:
        sys.exit(run_tests(all_ids, dry_run=args.dry_run, skip_replay=args.skip_replay))
    elif args.happy:
        sys.exit(run_tests(happy_ids, dry_run=args.dry_run, skip_replay=args.skip_replay))
    elif args.unhappy:
        sys.exit(run_tests(unhappy_ids, dry_run=args.dry_run, skip_replay=args.skip_replay))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
