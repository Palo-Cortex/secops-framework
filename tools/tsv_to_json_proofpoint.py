#!/usr/bin/env python3
"""
Convert a Proofpoint TAP TSV export into a JSON array suitable for
XSIAM HTTP Collector ingest via send_test_events.py.

Handles both event types:
  - messages delivered
  - clicks permitted

Fixes:
  1. _time / _insert_time stamped to NOW (UTC) so events always arrive
     current — no --time-field replay needed, no stale November dates.
  2b. messageTime, clickTime, threatTime also stamped to now (XSIAM uses
      messageTime for Observation Time display in the Issues view).
  2. threatsInfoMap / messageParts re-serialized as JSON strings so
     XQL json_extract_scalar() works (native arrays return null silently).
  3. Fresh GUID every run; orig_GUID preserves the original for tracing.
  4. alert_category and alert_domain defaulted in _alert_data so XSIAM
     alert creation doesn't fail on null user_defined_category.

Usage:
  python3 tsv_to_json_proofpoint.py --input scenario.tsv --output scenario.json
  python3 tsv_to_json_proofpoint.py --input scenario.tsv --output scenario.json --limit 5

Send (no --time-field needed — _time is already now):
  python3 send_test_events.py --file scenario.json --env .env-brumxdr-proofpoint
"""

import csv
import json
import argparse
import uuid
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime, timezone

# ── Column type sets ───────────────────────────────────────────────────────────

JSON_COLUMNS = {
    "threatsInfoMap",
    "messageParts",
    "fromAddress",
    "toAddresses",
    "ccAddresses",
    "replyToAddress",
    "recipient",
    "policyRoutes",
    "modulesRun",
    "_alert_data",
}

INT_COLUMNS = {
    "impostorScore", "malwareScore", "phishScore", "spamScore", "messageSize",
}

# These columns are overwritten with the current UTC time regardless of source value.
# Keeps test events current so the correlation rule real-time window catches them.
NOW_COLUMNS = {"_time", "_insert_time", "messageTime", "clickTime", "threatTime"}


def smart_value(v: Optional[str]) -> Any:
    if v is None:
        return None
    s = v.strip()
    if s == "" or s.lower() == "null":
        return None
    return s


def parse_json_col(val: str) -> Any:
    try:
        return json.loads(val)
    except Exception:
        return val


def convert_row(row: Dict[str, str]) -> Dict[str, Any]:
    now_iso = datetime.now(timezone.utc).isoformat()
    out: Dict[str, Any] = {}

    for k, v in row.items():
        # Always stamp NOW columns to current time
        if k in NOW_COLUMNS:
            out[k] = now_iso
            continue

        cleaned = smart_value(v)
        if cleaned is None:
            out[k] = None
            continue

        if k in JSON_COLUMNS:
            out[k] = parse_json_col(cleaned)
        elif k in INT_COLUMNS:
            try:
                out[k] = int(cleaned)
            except ValueError:
                out[k] = cleaned
        else:
            out[k] = cleaned

    # Required XSIAM ingest fields
    out.setdefault("_vendor", "Proofpoint TAP v2")
    out.setdefault("_product", "generic_alert")
    out.setdefault("_collector_name", "XSIAM")

    # Fresh GUID every run — 24h suppression blocks re-tests if GUID is reused.
    if out.get("GUID"):
        out["orig_GUID"] = out["GUID"]
    out["GUID"] = str(uuid.uuid4()).replace("-", "")[:34]

    if not out.get("id"):
        out["id"] = str(uuid.uuid4())

    # threatsInfoMap must stay a JSON string — XQL json_extract_scalar() returns
    # null silently on native arrays, so the threatStatus filter never fires.
    tim = out.get("threatsInfoMap")
    if isinstance(tim, list):
        out["threatsInfoMap"] = json.dumps(tim)

    mp = out.get("messageParts")
    if isinstance(mp, list):
        out["messageParts"] = json.dumps(mp)

    # Patch _alert_data
    ad = out.get("_alert_data")
    if isinstance(ad, dict):
        event_type = out.get("type", "")
        if "click" in event_type.lower():
            ad["alert_name"] = f"Proofpoint TAP - Click Permitted - {out['GUID']}"
            ad["alert_type"] = "Proofpoint TAP - Click Permitted"
            ad["sourceInstance"] = "Proofpoint TAP v2_Clicks_Permitted"
        else:
            ad["alert_name"] = f"Proofpoint TAP - Message Delivered - {out['GUID']}"
            ad["alert_type"] = "Proofpoint TAP - Message Delivered"
            ad["sourceInstance"] = "Proofpoint TAP v2_Messages_Delivered"
        ad["alert_source"] = "Proofpoint TAP v2"
        ad["alert_sub_type"] = "XDR"
        ad["alert_action_status"] = "DETECTED"
        ad["isactive"] = True
        ad["resolution_status"] = "STATUS_010_NEW"
        ad["alert_domain"] = "DOMAIN_SECURITY"
        if not ad.get("alert_category"):
            ad["alert_category"] = "Email Security"

        # Sync raw_json.threatsInfoMap
        tim_str = out.get("threatsInfoMap")
        if tim_str:
            rj = ad.get("raw_json")
            if isinstance(rj, str):
                try:
                    rj_obj = json.loads(rj)
                    rj_obj["threatsInfoMap"] = json.loads(tim_str) if isinstance(tim_str, str) else tim_str
                    ad["raw_json"] = json.dumps(rj_obj)
                except Exception:
                    pass

    return out


def main():
    parser = argparse.ArgumentParser(
        description="Convert Proofpoint TAP TSV export to JSON for XSIAM HTTP Collector"
    )
    parser.add_argument("--input",  required=True, help="Input TSV file path")
    parser.add_argument("--output", required=True, help="Output JSON file path")
    parser.add_argument("--limit",  type=int, default=None,
                        help="Max rows to convert (default: all)")
    args = parser.parse_args()

    input_path  = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"[!] Input file not found: {input_path}")
        raise SystemExit(1)

    events = []
    with open(input_path, encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for i, row in enumerate(reader):
            if args.limit and i >= args.limit:
                break
            events.append(convert_row(row))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2, default=str)

    print(f"[+] Converted {len(events)} row(s) → {output_path}")
    print(f"    _time stamped to now (UTC) — no --time-field needed")
    print(f"    Send with:")
    print(f"    python3 send_test_events.py --file {output_path} --env .env-brumxdr-proofpoint")


if __name__ == "__main__":
    main()
