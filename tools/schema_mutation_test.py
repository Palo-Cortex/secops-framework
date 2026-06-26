#!/usr/bin/env python3
"""
schema_mutation_test.py — Empirically test how an XSIAM dataset reacts to
schema changes, without touching any production dataset.

Point it at a DEDICATED test HTTP Collector (custom name -> custom dataset).
It sends a sequence of rows, each tagged with a unique `test_marker`, that
exercise every way data can change: add fields, drop fields, change types,
diverge field names, collide on id, and a volume/no-decay check. After each
step it prints the exact XQL to run so you can observe what happened to the
rows that already existed.

NOTHING here can harm crowdstrike_falcon_event_raw or any real dataset — it
only writes to whatever dataset the test collector in your .env routes to.

Usage:
    python3 schema_mutation_test.py --env .env-brumxdr-schematest
    python3 schema_mutation_test.py --env .env-brumxdr-schematest --test T3
    python3 schema_mutation_test.py --env .env-brumxdr-schematest --all
    python3 schema_mutation_test.py --env .env-prod-schematest  --all --dry-run

The .env file must contain:
    API_URL=<HTTP collector URL for the test dataset>
    API_KEY=<collector auth token>

Recommended: name the collector/dataset something obvious like
`schema_mutation_test_raw` so it's unmistakable and easy to delete after.
"""

import argparse
import json
import os
import ssl
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone


# ─────────────────────────────────────────────────────────────────────────────
# env loading
# ─────────────────────────────────────────────────────────────────────────────

def load_env(path):
    """Read KEY=VALUE lines from an env file. Returns (api_url, api_key)."""
    if not os.path.exists(path):
        sys.exit(f"env file not found: {path}")
    url = key = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k == "API_URL":
                url = v
            elif k == "API_KEY":
                key = v
    if not url:
        sys.exit(f"API_URL missing from {path}")
    if not key:
        sys.exit(f"API_KEY missing from {path}")
    return url, key


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ─────────────────────────────────────────────────────────────────────────────
# sending
# ─────────────────────────────────────────────────────────────────────────────

def send(url, key, rows, dry_run=False, ssl_ctx=None):
    """POST a JSON array of event dicts to the HTTP collector."""
    payload = json.dumps(rows).encode("utf-8")
    if dry_run:
        print(f"    [DRY RUN] would POST {len(rows)} row(s) to {url}")
        print(f"    sample: {json.dumps(rows[0])[:200]}")
        return True
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": key,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
            body = resp.read().decode("utf-8", "replace")
            print(f"    HTTP {resp.status}  sent {len(rows)} row(s)  resp: {body[:200]}")
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        print(f"    HTTP ERROR {e.code}: {e.read().decode('utf-8','replace')[:300]}")
        return False
    except urllib.error.URLError as e:
        print(f"    CONNECTION ERROR: {e.reason}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# test rows — one builder per phase. Each row carries test_marker + _time.
# A stable id field `event_uid` lets us probe collision behavior in T6.
# ─────────────────────────────────────────────────────────────────────────────

def base10(marker, uid):
    """The baseline 10-field shape every later test diverges from."""
    return {
        "test_marker": marker,
        "event_uid": uid,
        "_time": now_iso(),
        "f_string": "alpha",
        "f_int": 100,
        "f_bool": True,
        "f_user": "gunter@skt.local",
        "f_host": "host-01",
        "f_ip": "10.0.0.1",
        "f_score": 42,
    }


def build(test):
    """Return (description, list-of-rows, post_query_hint) for a given phase."""
    if test == "T0":
        rows = [base10("T0", "uid-T0-001")]
        return ("Baseline control: 10 fields, 1 row.", rows,
                'filter test_marker = "T0"  → expect exactly 1 row, 10 fields.')

    if test == "T1":
        r = base10("T1", "uid-T1-001")
        r["f_new_one"] = "added-field"          # 10 -> 11
        return ("Add ONE field (10→11).", [r],
                'filter test_marker in ("T0","T1") → T0 still present; '
                'f_new_one column exists and is null on T0.')

    if test == "T2":
        r = base10("T2", "uid-T2-001")
        for i in range(1, 10):                   # 11 -> 20
            r[f"f_bulk_{i}"] = f"v{i}"
        return ("Add NINE fields at once (11→20).", [r],
                'filter test_marker in ("T0","T1","T2") → all prior rows intact.')

    if test == "T3":
        # NARROWER row: only 5 of the original fields, rest omitted.
        r = {
            "test_marker": "T3",
            "event_uid": "uid-T3-001",
            "_time": now_iso(),
            "f_string": "narrow",
            "f_int": 5,
        }
        return ("Drop fields on NEW rows (send only 5).", [r],
                'filter test_marker in ("T0","T1","T2","T3") → CRITICAL: confirm '
                'T0/T1/T2 still hold their f_user/f_host/etc values (NOT nulled). '
                'T3 simply has nulls for omitted columns. '
                'This is the "does narrow data strip old columns" test.')

    if test == "T4":
        # TYPE COLLISION: f_int was integer; send it as a string now.
        r = base10("T4", "uid-T4-001")
        r["f_int"] = "not-a-number"
        r["f_score"] = "high"                    # was 42 (int)
        return ("Type change on existing fields (int→string).", [r],
                'filter test_marker in ("T0","T4") → both rows present. '
                'Then query f_int / f_score across all rows and watch for QUERY '
                'ERRORS or coercion. Row loss is the failure; query error is a caveat.')

    if test == "T5":
        # FIELD-NAME DIVERGENCE: near-miss name vs f_user.
        r = base10("T5", "uid-T5-001")
        del r["f_user"]
        r["fuser"] = "frieda@skt.local"          # typo'd / diverged name
        return ("Field-name divergence (f_user → fuser).", [r],
                'Confirm fuser is a NEW column; f_user on prior rows unchanged. '
                'Proves a renamed/typo field does not overwrite the original column.')

    if test == "T6":
        # ID COLLISION: reuse T0's event_uid with a changed payload.
        r = base10("T6", "uid-T0-001")           # SAME uid as T0
        r["f_string"] = "COLLISION-CHANGED"
        r["f_int"] = 999
        return ("ID collision: reuse T0 event_uid with changed payload.", [r],
                'filter event_uid = "uid-T0-001" → THE KEY TEST: '
                'append-only = TWO rows (original "alpha" + new "COLLISION-CHANGED"). '
                'Upsert/overwrite = ONE row with the changed payload. '
                'If you see overwrite, sending colliding ids is destructive.')

    if test == "T7":
        # VOLUME / NO-DECAY: a batch, then you wait and re-query.
        rows = [base10("T7", f"uid-T7-{i:03d}") for i in range(1, 21)]
        return ("Volume + no-decay: send 20 rows.", rows,
                'Query count() by test_marker → all markers T0..T7 present. '
                'Then WAIT 10-15 min, re-run → nothing decayed/disappeared.')

    sys.exit(f"unknown test: {test}")


ORDER = ["T0", "T1", "T2", "T3", "T4", "T5", "T6", "T7"]


# ─────────────────────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────────────────────

def run_phase(test, url, key, dry_run, ssl_ctx=None):
    desc, rows, hint = build(test)
    print(f"\n=== {test}: {desc} ===")
    ok = send(url, key, rows, dry_run=dry_run, ssl_ctx=ssl_ctx)
    print(f"    AFTER THIS STEP, run in XQL Search:")
    print(f"      dataset = <your_test_dataset>")
    print(f"      | {hint}")
    return ok


def main():
    ap = argparse.ArgumentParser(description="XSIAM dataset schema-mutation test harness")
    ap.add_argument("--env", required=True, help="path to .env file with API_URL + API_KEY")
    ap.add_argument("--test", help="run a single phase (T0..T7)")
    ap.add_argument("--all", action="store_true", help="run the full T0..T7 sequence")
    ap.add_argument("--dry-run", action="store_true", help="show what would be sent, send nothing")
    ap.add_argument("--pause", type=float, default=3.0, help="seconds between phases (default 3)")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (use on SSL-inspected/corporate networks)")
    ap.add_argument("--ca-bundle",
                    help="path to a CA bundle PEM to trust (preferred over --insecure)")
    args = ap.parse_args()

    url, key = load_env(args.env)

    ssl_ctx = None
    if args.ca_bundle:
        ssl_ctx = ssl.create_default_context(cafile=args.ca_bundle)
    elif args.insecure:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    print(f"[*] env: {args.env}")
    print(f"[*] collector: {url}")
    print(f"[*] mode: {'DRY RUN' if args.dry_run else 'LIVE'}"
          + ("  [TLS verify OFF]" if args.insecure else "")
          + (f"  [CA: {args.ca_bundle}]" if args.ca_bundle else ""))
    print(f"[!] This writes ONLY to the dataset the above collector routes to.")
    print(f"[!] It cannot affect crowdstrike_falcon_event_raw or any other dataset.")

    if args.test:
        run_phase(args.test, url, key, args.dry_run, ssl_ctx)
    elif args.all:
        for t in ORDER:
            run_phase(t, url, key, args.dry_run, ssl_ctx)
            if t != ORDER[-1]:
                time.sleep(args.pause)
        print("\n[*] Full matrix sent. Decision rule:")
        print("    Any phase where a PRIOR test_marker row vanished or its values")
        print("    changed = that operation is PROD-UNSAFE. Everything that left")
        print("    prior rows intact is proven safe on this platform version.")
    else:
        sys.exit("specify --test T0 (single phase) or --all (full sequence)")


if __name__ == "__main__":
    main()
