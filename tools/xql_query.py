#!/usr/bin/env python3
"""Run one read-only XQL query against a lab tenant and print the rows.

The tenant and its key come from the environment, so run it through povkit:

    povkit exec deathstar -- python3 tools/xql_query.py --hours 24 \\
        'dataset = playbook_runs | comp count() as n by playbook_name'

    povkit exec deathstar -- python3 tools/xql_query.py --file query.xql --json

The query gets `config timeframe = <hours>h` in front of it (time filters on
`_time`). Rows print one per line, as JSON with --json. A query whose stages
could change something is refused: only reads run here.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_tests import xql_run  # noqa: E402
from tenant_env import tenant_credentials  # noqa: E402

# XQL that writes rather than reads. The query API runs reads only, but a
# refusal here says so plainly instead of returning an engine error.
WRITING = re.compile(r"\|\s*(target|join\s+.*\btarget\b)", re.IGNORECASE)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("query", nargs="?", help="the XQL query (or use --file)")
    ap.add_argument("--file", help="read the query from this file")
    ap.add_argument("--hours", type=int, default=24, help="timeframe in hours (default 24)")
    ap.add_argument("--json", action="store_true", help="one JSON object per row")
    ap.add_argument("--limit", type=int, default=200, help="most rows to print (default 200)")
    a = ap.parse_args()
    if bool(a.query) == bool(a.file):
        ap.error("give the query or --file, not both")
    query = open(a.file).read() if a.file else a.query
    if WRITING.search(query):
        sys.exit("refused: this tool runs read-only queries; the query has a `target` stage")

    creds = tenant_credentials()
    print("tenant: {}".format(creds["DEMISTO_BASE_URL"]), file=sys.stderr)
    r = xql_run(query, creds, timeframe_hours=a.hours)
    if r.get("status") != "SUCCESS":
        sys.exit("XQL {}: {}".format(r.get("status"), r.get("error")))
    rows = r.get("rows") or []
    for row in rows[:a.limit]:
        print(json.dumps(row, default=str) if a.json else row)
    print("{} row(s){}".format(len(rows), " (first {} shown)".format(a.limit) if len(rows) > a.limit else ""),
          file=sys.stderr)


if __name__ == "__main__":
    main()
