#!/usr/bin/env python3
"""
Install a pack's correlation rules onto a tenant via the XSIAM correlations API.

WHY THIS EXISTS
---------------
`demisto-sdk` does not deliver correlation rules to XSIAM. Verified 18 Sep 2026
on both 1.38.14 (container) and 1.39.3 (thor), with and without `-z`, against
soc-crowdstrike-idp and soc-crowdstrike-falcon: the pack zip it builds contains
no CorrelationRules/ directory and its metadata.json declares
`contentItems.correlationrule: []`. The pack installs, the version updates, the
upload reports success, and the rule is silently never created. deathstar had
zero pack-delivered correlation rules across 184 installed packs.

`POST /public_api/v1/correlations/insert` does work and is the only mechanism
observed to create a rule. This script drives it from the pack source so the
upload path actually delivers what the pack ships.

IDEMPOTENCY
-----------
The insert endpoint does NOT upsert by name — posting the same rule twice
creates two rules. So each rule is deleted by name first, then inserted.

USAGE
-----
    set -a; . ./.env; set +a
    python3 tools/install_correlation_rules.py Packs/soc-crowdstrike-idp
    python3 tools/install_correlation_rules.py Packs/<pack> --verify-only
"""
import argparse
import glob
import json
import os
import sys
import urllib.request

import yaml

# Fields the correlations API accepts. Taken verbatim from the working insert in
# tools/platform_health_check.sh and cross-checked against what /correlations/get
# returns for live rules. Repo/SDK-only keys (rule_id, fromversion,
# global_rule_id, system, action, lookup_mapping, id, ruleid) are NOT API fields
# and must be dropped or the insert is rejected.
API_FIELDS = [
    "name", "severity", "xql_query", "is_enabled", "description", "alert_name",
    "alert_category", "alert_description", "alert_domain", "alert_type",
    "alert_fields", "execution_mode", "search_window", "simple_schedule",
    "timezone", "crontab", "suppression_enabled", "suppression_duration",
    "suppression_fields", "dataset", "user_defined_severity",
    "user_defined_category", "mitre_defs", "investigation_query_link",
    "drilldown_query_timeframe", "mapping_strategy",
]


def creds():
    missing = [v for v in ("DEMISTO_BASE_URL", "DEMISTO_API_KEY", "XSIAM_AUTH_ID")
               if not os.environ.get(v)]
    if missing:
        sys.exit(f"Missing env var(s): {', '.join(missing)} — source the tenant .env first.")
    return (os.environ["DEMISTO_BASE_URL"].rstrip("/"),
            os.environ["DEMISTO_API_KEY"],
            os.environ["XSIAM_AUTH_ID"])


def api(path, payload, timeout=120):
    base, key, auth_id = creds()
    req = urllib.request.Request(
        f"{base}{path}",
        data=json.dumps(payload).encode(),
        headers={"Authorization": key, "x-xdr-auth-id": auth_id,
                 "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body}


def tenant_rules():
    code, body = api("/public_api/v1/correlations/get", {"request_data": {}})
    if code != 200:
        sys.exit(f"correlations/get failed HTTP {code}: {body}")
    return body.get("objects", [])


def pack_rules(pack):
    out = []
    for fn in sorted(glob.glob(f"{pack}/CorrelationRules/*.yml")):
        doc = yaml.safe_load(open(fn))
        if isinstance(doc, list):
            doc = doc[0]
        if not doc or "name" not in doc:
            continue
        out.append((fn, {k: doc[k] for k in API_FIELDS if k in doc}))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("packs", nargs="+")
    ap.add_argument("--verify-only", action="store_true",
                    help="Report presence on the tenant; do not install.")
    args = ap.parse_args()

    base, _, _ = creds()
    print(f"\n  Tenant : {base}")

    failures = 0
    total = 0
    for pack in args.packs:
        rules = pack_rules(pack)
        if not rules:
            continue
        print(f"  Pack   : {pack}  ({len(rules)} correlation rule(s))\n")
        on_tenant = {r.get("name"): r for r in tenant_rules()}

        for fn, rule in rules:
            total += 1
            name = rule["name"]
            if args.verify_only:
                hit = on_tenant.get(name)
                print(f"    {'PRESENT' if hit else 'MISSING'}  {name}"
                      + (f"  (rule_id={hit['rule_id']})" if hit else ""))
                if not hit:
                    failures += 1
                continue

            # delete-then-insert: the endpoint does not upsert by name
            existing = on_tenant.get(name)
            if existing:
                api("/public_api/v1/correlations/delete",
                    {"request_data": {"filters": [
                        {"field": "rule_id", "operator": "eq",
                         "value": existing["rule_id"]}]}})

            code, body = api("/public_api/v1/correlations/insert",
                             {"request_data": [rule]})
            errs = body.get("errors") or []
            added = body.get("added_objects") or []
            if code == 200 and added and not errs:
                print(f"    OK      {name}  -> rule_id={added[0].get('id')}")
            else:
                failures += 1
                detail = errs[0].get("status") if errs else body
                print(f"    FAILED  {name}\n              HTTP {code}: {detail}")

    if failures:
        print(f"\n  {failures}/{total} rule(s) failed.\n")
        return 1
    print(f"\n  All {total} correlation rule(s) "
          f"{'present' if args.verify_only else 'installed'} on the tenant.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
