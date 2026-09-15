#!/usr/bin/env python3
"""identity_census.py — which identifier FORMS does each source emit?

Answers the question that decides REAL_TIME vs SCHEDULED per vendor: does this
source carry a username, a domain, a SID/identifier, a UPN, an email — and do
they travel together? If a source emits a SID alongside a name, identities can
be bridged in `alter` with no join, and the rule stays REAL_TIME. If it emits
only an opaque identifier, that source needs CIE or getrole and pays the
SCHEDULED latency.

PRIVACY — the whole point of this tool:
  * It NEVER selects, returns, or prints a field VALUE. Only presence flags
    (1/0), counts, and distinct-counts.
  * Grouping is on presence flags, never on a field, so no bucket is labelled
    with a domain, hostname or account name.
  * Buckets smaller than MIN_BUCKET are dropped, so no row can describe a
    single person by their field pattern.
  * Emitted queries are checked against these rules before they are run, and
    the check refuses rather than warns.

Run it on the customer's tenant. Nothing leaves their environment except a
matrix of ones, zeros and counts. Keep the method in the repo; keep the numbers
wherever the engagement says customer data lives.
"""

import argparse
import json
import sys
import time
import urllib3

urllib3.disable_warnings()
import requests  # noqa: E402

MIN_BUCKET = 10

# Value-returning XQL stages. If a generated query contains one of these, the
# query is refused - it could put a username or a domain on screen.
FORBIDDEN_STAGES = ("fields ", "values(", "arraystring(", "| view", "sort ")

# Per-source field map. Only field NAMES live here, never values, and these are
# XDM / documented collector names rather than a customer's custom fields - a
# field called acme_contractor_id is customer information even with no value
# attached. Extend per engagement; do not commit customer-specific field names.
SOURCES = {
    "msft_graph_security_alerts_raw": {
        "username":   'json_extract_scalar(evidence, "$.accountName")',
        "domain":     'json_extract_scalar(evidence, "$.domainName")',
        "identifier": 'json_extract_scalar(evidence, "$.userSid")',
        "upn":        'json_extract_scalar(evidence, "$.userPrincipalName")',
        "email":      "null",
    },
    "abnormal_security_email_protection_raw": {
        "username":   "null",
        "domain":     "senderDomain",
        "identifier": "null",
        "upn":        "null",
        "email":      "recipientAddress",
    },
}

FORMS = ("username", "domain", "identifier", "upn", "email")


def presence_query(dataset, fields, min_bucket=MIN_BUCKET):
    """Presence matrix: which identifier forms co-occur, and how often.

    Every selected column is a 1/0 flag or a count. No field value is ever
    projected, and the `by` clause groups on flags, so no bucket carries a
    domain or account name as its label.
    """
    alters = ",\n        ".join(
        f'has_{f} = if({fields.get(f) or "null"} != null '
        f'and to_string({fields.get(f) or "null"}) != "", 1, 0)'
        for f in FORMS
    )
    by = ", ".join(f"has_{f}" for f in FORMS)
    return (
        f"dataset = {dataset}\n"
        f"| alter {alters}\n"
        f"| comp count() as n by {by}\n"
        f"| filter n >= {min_bucket}"
    )


def cardinality_query(dataset, fields, min_bucket=MIN_BUCKET):
    """Do identifiers and names travel together, at what ratio?

    dcount returns cardinality, never the values counted. Grouped on a presence
    flag rather than on the domain itself, so the ratio survives and the domain
    names do not.
    """
    ident = fields.get("identifier") or "null"
    user = fields.get("username") or "null"
    upn = fields.get("upn") or "null"
    return (
        f"dataset = {dataset}\n"
        f'| alter dom_present = if({fields.get("domain") or "null"} != null, 1, 0)\n'
        f"| comp count() as n, dcount({ident}) as distinct_identifiers,\n"
        f"       dcount({user}) as distinct_usernames,\n"
        f"       dcount({upn}) as distinct_upns by dom_present\n"
        f"| filter n >= {min_bucket}"
    )


def assert_non_identifying(query):
    """Refuse to run a query that could project a value. Refuse, not warn.

    A warning gets ignored at 2am on a customer tenant. The failure mode this
    guards against - a username or domain appearing in output that then lands
    in a ticket, a deck or a repo - is not recoverable once it has happened.
    """
    lowered = query.lower()
    for stage in FORBIDDEN_STAGES:
        if stage in lowered:
            raise SystemExit(
                f"REFUSED: generated query contains {stage!r}, which can project "
                f"field values. This tool only emits presence flags and counts.\n\n{query}"
            )
    if "filter n >=" not in lowered:
        raise SystemExit(
            "REFUSED: query has no minimum-bucket filter. A bucket of one "
            "describes a single person by their field pattern.\n\n" + query
        )
    return query


def discover_fields(creds, dataset, days):
    """Field NAMES present on a dataset.

    Reads one row to learn its keys. The values in that row are held in memory
    and discarded — never printed, returned or aggregated. A field NAME is not
    customer data; a field VALUE is. This is the only place the tool touches a
    value at all, and it is the minimum needed to find fields nobody mapped.
    """
    rows = run_xql(creds, f"dataset = {dataset} | limit 1", days)
    if not isinstance(rows, list) or not rows:
        return []
    keys = sorted(k for k in rows[0] if not k.startswith("_"))
    del rows
    return keys


def email_scan_query(dataset, candidates, min_bucket=MIN_BUCKET):
    """Which fields carry email-shaped values, and in how many events?

    The whole design rests on this. If an email is present at ALERT time it can
    be lowercased in `alter` and used as the grouping key with no join — the
    asset inventory then resolves the rest of the identity afterwards, at case
    scope, without paying the SCHEDULED 10-minute cost. If it is absent, that
    source needs a resolver in-rule and pays that cost.

    Tests for "@" rather than a full RFC pattern: `contains` is proven syntax in
    the shipped vendor rules, an unverified regex operator is not. It
    over-counts (a URL or message-id matches too), so read the result as "worth
    mapping", not "is an email", and eyeball the winner on the tenant before it
    becomes a grouping key.

    Emits counts per field. No value is ever projected.
    """
    alters = ",\n        ".join(
        f'at_{i} = if(to_string({f}) contains "@", 1, 0)'
        for i, f in enumerate(candidates))
    sums = ",\n       ".join(
        f"sum(at_{i}) as with_at_{i}" for i, f in enumerate(candidates))
    return (f"dataset = {dataset}\n| alter {alters}\n"
            f"| comp count() as n,\n       {sums}\n"
            f"| filter n >= {min_bucket}")


def load_creds(env_path):
    creds = {}
    for line in open(env_path):
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            creds[k.strip()] = v.strip().strip('"')
    return creds


def run_xql(creds, query, days):
    base = creds["DEMISTO_BASE_URL"].rstrip("/")
    h = {"Authorization": creds["DEMISTO_API_KEY"],
         "x-xdr-auth-id": creds["XSIAM_AUTH_ID"],
         "Content-Type": "application/json"}
    s = requests.post(f"{base}/public_api/v1/xql/start_xql_query/", headers=h,
                      json={"request_data": {"query": query,
                                             "timeframe": {"relativeTime": days * 86400000}}},
                      verify=False, timeout=120)
    if s.status_code != 200:
        return f"HTTP {s.status_code}: {s.text[:200]}"
    qid = s.json().get("reply")
    for _ in range(45):
        time.sleep(2)
        g = requests.post(f"{base}/public_api/v1/xql/get_query_results/", headers=h,
                          json={"request_data": {"query_id": qid, "pending_flag": True,
                                                 "limit": 200, "format": "json"}},
                          verify=False, timeout=120).json()
        rep = g.get("reply", {})
        if rep.get("status") == "SUCCESS":
            return rep.get("results", {}).get("data", [])
        if rep.get("status") not in ("PENDING", "IN_PROGRESS"):
            return f"status={rep.get('status')}: {str(rep)[:200]}"
    return "timed out"


def verdict(rows):
    """Translate the presence matrix into the execution-mode call per source."""
    if not isinstance(rows, list) or not rows:
        return "no data in window — cannot judge"
    named = sum(r.get("n", 0) for r in rows
                if r.get("has_username") or r.get("has_upn") or r.get("has_email"))
    ident_only = sum(r.get("n", 0) for r in rows
                     if r.get("has_identifier")
                     and not (r.get("has_username") or r.get("has_upn")
                              or r.get("has_email")))
    total = named + ident_only
    if not total:
        return "no identity-bearing events — source carries no identity"
    pct = 100.0 * ident_only / total
    if pct == 0:
        return ("every identity-bearing event carries a NAME → bridge in `alter`, "
                "REAL_TIME eligible, no CIE join needed")
    if pct < 5:
        return (f"{pct:.1f}% opaque-identifier-only → REAL_TIME for the bulk; "
                f"a SCHEDULED path is only needed for the residue")
    return (f"{pct:.1f}% of events carry an identifier with no name → this source "
            f"needs resolution (CIE / getrole) and pays SCHEDULED latency")


def main():
    p = argparse.ArgumentParser(
        description="Identifier-form census. Emits presence flags and counts only — "
                    "never usernames, domains, SIDs or any other field value.")
    p.add_argument("--env", default="/home/scott/secops-framework/.env",
                   help="tenant credentials file, e.g. .env-fedex, "
                        ".env-deathstar-defender. Selects which tenant is queried.")
    p.add_argument("--source", action="append",
                   help="dataset name from SOURCES; repeatable. Default: all.")
    p.add_argument("--dataset", action="append",
                   help="any dataset, mapped or not — use with --find-email to "
                        "discover identity fields nobody has mapped yet.")
    p.add_argument("--find-email", action="store_true",
                   help="discover which fields carry email-shaped values. This is "
                        "the go/no-go for email-as-grouping-key: present at alert "
                        "time means REAL_TIME with no CIE join.")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--min-bucket", type=int, default=MIN_BUCKET)
    p.add_argument("--dry-run", action="store_true",
                   help="print the queries and the safety check, run nothing")
    args = p.parse_args()

    creds = None if args.dry_run else load_creds(args.env)
    if creds:
        print(f"tenant: {creds.get('DEMISTO_BASE_URL', '?')}")

    if args.find_email:
        for ds in (args.dataset or args.source or list(SOURCES)):
            print(f"\n{'=' * 68}\n### {ds} — email-bearing field scan\n{'=' * 68}")
            if args.dry_run:
                print("  (needs a tenant to discover field names; omit --dry-run)")
                continue
            names = discover_fields(creds, ds, args.days)
            if not names:
                print("  no rows in window — nothing to scan")
                continue
            print(f"  {len(names)} fields on this dataset")
            q = assert_non_identifying(email_scan_query(ds, names, args.min_bucket))
            rows = run_xql(creds, q, args.days)
            if not isinstance(rows, list) or not rows:
                print("  ", rows or "no rows")
                continue
            r, total = rows[0], rows[0].get("n", 0)
            hits = sorted(((names[int(k.rsplit('_', 1)[1])], v)
                           for k, v in r.items()
                           if k.startswith("with_at_") and v),
                          key=lambda x: -x[1])
            print(f"  {total} events in window\n")
            for name, cnt in hits[:15]:
                print(f"    {name:<44} {cnt:>8}  ({100.0 * cnt / total:5.1f}%)")
            if not hits:
                print("    NO email-shaped field — this source cannot bridge on "
                      "email at alert time; it needs a resolver or a second key")
        return

    targets = args.source or args.dataset or list(SOURCES)
    for ds in targets:
        fields = SOURCES.get(ds)
        if not fields:
            print(f"\n### {ds}: not in SOURCES — add its field NAMES first, "
                  f"or use --find-email to scan it blind")
            continue
        print(f"\n{'=' * 68}\n### {ds}\n{'=' * 68}")
        for label, builder in (("presence matrix", presence_query),
                               ("cardinality", cardinality_query)):
            q = assert_non_identifying(builder(ds, fields, args.min_bucket))
            print(f"\n--- {label} ---\n{q}\n")
            if args.dry_run:
                continue
            rows = run_xql(creds, q, args.days)
            if not isinstance(rows, list):
                print("  ", rows)
                continue
            for r in rows:
                print("   ", json.dumps(r, sort_keys=True))
            if label == "presence matrix":
                print(f"\n  VERDICT: {verdict(rows)}")


if __name__ == "__main__":
    sys.exit(main())
