#!/usr/bin/env python3
"""
execution_baseline.py -- behavioural baseline from the framework's own telemetry.

The static checks (socfw_contract audit, normalize_regression) compare the
CONTRACT. This compares what the framework actually DID: xsiam_socfw_ir_execution_raw
records every phase execution with the entity it acted on, the command it ran,
and whether that succeeded.

Snapshot before a change, snapshot after, diff. A phase that produced entities
and stops, or a command whose success rate drops, is a regression the contract
diff cannot see.

  snapshot   pull current execution profile from a tenant -> JSON
  compare    diff two snapshots, exit non-zero on regression

Usage:
  python3 execution_baseline.py snapshot --env .env-brumxdr --out before.json
  # ... make contract changes, deploy ...
  python3 execution_baseline.py snapshot --env .env-brumxdr --out after.json
  python3 execution_baseline.py compare --before before.json --after after.json
"""
import argparse
import json
import os
import sys
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "tools"))

DATASET = "xsiam_socfw_ir_execution_raw"

# Dimensions worth tracking. Each answers a different "did we break it" question.
PROFILES = {
    "phase_volume": (
        "count of executions per lifecycle/category/phase",
        f"dataset = {DATASET} | comp count() as c by lifecycle, alert_category, phase"),
    "entity_types": (
        "which normalized entity types each category actually produces",
        f"dataset = {DATASET} | comp count() as c by alert_category, phase, entity_type"),
    "commands": (
        "which universal commands run, and against which vendor command",
        f"dataset = {DATASET} | comp count() as c by alert_category, universal_command, "
        f"vendor_command, action_status"),
    "errors": (
        "error profile per phase",
        f"dataset = {DATASET} | comp count() as c by alert_category, phase, has_error, error_type"),
    "playbooks": (
        "which playbooks execute",
        f"dataset = {DATASET} | comp count() as c by alert_category, phase, playbook_name"),
}


def snapshot(env, hours, out_path):
    from run_tests import load_credentials, xql_run
    creds = load_credentials(env)
    doc = {"_schema": "socfw execution baseline v1",
           "tenant": creds["DEMISTO_BASE_URL"],
           "timeframe_hours": hours, "profiles": {}}
    for name, (desc, query) in PROFILES.items():
        res = xql_run(query + " | limit 500", creds, timeframe_hours=hours)
        if res.get("status") != "SUCCESS":
            print(f"  {name:<14} FAILED: {str(res.get('error'))[:120]}")
            doc["profiles"][name] = {"error": str(res.get("error"))[:200]}
            continue
        rows = res.get("rows", [])
        doc["profiles"][name] = {"description": desc, "rows": rows}
        print(f"  {name:<14} {len(rows):>4} rows")
    parent = os.path.dirname(os.path.abspath(out_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
    print(f"\nwrote {out_path}")
    return 0


def keyed(rows, drop=("c",)):
    """row -> (tuple of dimension values, count)"""
    out = {}
    for row in rows or []:
        key = tuple(f"{k}={row.get(k)}" for k in sorted(row) if k not in drop)
        out[key] = out.get(key, 0) + (row.get("c") or 0)
    return out


def compare(before_path, after_path, tolerance):
    before = json.load(open(before_path, encoding="utf-8"))
    after = json.load(open(after_path, encoding="utf-8"))
    print(f"before : {before.get('tenant')}  {before.get('timeframe_hours')}h")
    print(f"after  : {after.get('tenant')}  {after.get('timeframe_hours')}h\n")

    regressions = []
    for name in PROFILES:
        b = keyed((before["profiles"].get(name) or {}).get("rows"))
        a = keyed((after["profiles"].get(name) or {}).get("rows"))
        gone = sorted(set(b) - set(a))
        new = sorted(set(a) - set(b))
        shrunk = []
        for key in sorted(set(b) & set(a)):
            if b[key] > 0 and a[key] < b[key] * (1 - tolerance):
                shrunk.append((key, b[key], a[key]))

        if not (gone or new or shrunk):
            print(f"=== {name}: unchanged")
            continue
        print(f"=== {name}")
        for key in gone:
            print(f"    DISAPPEARED  {' '.join(key)}  (was {b[key]})")
            regressions.append((name, key, b[key], 0))
        for key, bv, av in shrunk:
            print(f"    SHRANK       {' '.join(key)}  {bv} -> {av}")
            regressions.append((name, key, bv, av))
        for key in new[:10]:
            print(f"    new          {' '.join(key)}  ({a[key]})")
        print()

    if regressions:
        print(f"FAIL: {len(regressions)} behaviour(s) disappeared or shrank "
              f"beyond {tolerance:.0%}.")
        print("      A phase that stopped producing entities, or a command whose")
        print("      success rate dropped, will not show up in a contract diff.")
        return 1
    print("PASS: no execution behaviour disappeared or shrank.")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("snapshot")
    s.add_argument("--env", required=True)
    s.add_argument("--hours", type=int, default=8760)
    s.add_argument("--out", required=True)
    s.set_defaults(func=lambda a: snapshot(a.env, a.hours, a.out))

    c = sub.add_parser("compare")
    c.add_argument("--before", required=True)
    c.add_argument("--after", required=True)
    c.add_argument("--tolerance", type=float, default=0.20,
                   help="allowed shrink before it counts as a regression "
                        "(default 20%%, absorbs normal alert-volume variation)")
    c.set_defaults(func=lambda a: compare(a.before, a.after, a.tolerance))

    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
