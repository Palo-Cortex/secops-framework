#!/usr/bin/env python3
"""
Convert a Proofpoint TAP TSV export into a JSON array suitable for
XSIAM HTTP Collector ingest via send_test_events.py.

Handles both event types:
  - messages delivered
  - clicks permitted

JSON-encoded columns (threatsInfoMap, messageParts, _alert_data, etc.)
are parsed into real objects so XSIAM receives structured data.

Usage:
  python3 tsv_to_json_proofpoint.py --input scenario_phish_retract.tsv --output scenario_phish_retract.json
  python3 tsv_to_json_proofpoint.py --input scenario_phish_retract.tsv --output scenario_phish_retract.json --limit 5

Then send:
  python3 send_test_events.py --file scenario_phish_retract.json --env .env-brumxdr-proofpoint --time-field _time
"""

import csv
import json
import argparse
import uuid
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime, timezone

# Columns that contain embedded JSON strings — parse them to real objects
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

# Columns to cast to int if they look numeric
INT_COLUMNS = {
    "impostorScore", "malwareScore", "phishScore", "spamScore", "messageSize",
}


def smart_value(v: Optional[str]) -> Any:
    """Clean and type-cast a raw TSV cell value."""
    if v is None:
        return None
    s = v.strip()
    if s == "" or s.lower() == "null":
        return None
    return s


def parse_json_col(key: str, val: str) -> Any:
    """Try to parse a JSON-encoded column. Return raw string on failure."""
    try:
        return json.loads(val)
    except Exception:
        return val


def convert_row(row: Dict[str, str], cluster: str = "") -> Dict[str, Any]:
    """Convert a single TSV row to a structured JSON event."""
    out: Dict[str, Any] = {}

    for k, v in row.items():
        cleaned = smart_value(v)
        if cleaned is None:
            out[k] = None
            continue

        if k in JSON_COLUMNS:
            out[k] = parse_json_col(k, cleaned)
        elif k in INT_COLUMNS:
            try:
                out[k] = int(cleaned)
            except ValueError:
                out[k] = cleaned
        else:
            out[k] = cleaned

    # Ensure required XSIAM ingest fields are present
    out.setdefault("_vendor", "Proofpoint TAP v2")
    out.setdefault("_product", "generic_alert")
    out.setdefault("_collector_name", "XSIAM")

    # Generate a fresh GUID if missing
    if not out.get("GUID"):
        out["GUID"] = str(uuid.uuid4()).replace("-", "")[:34]

    # Generate a fresh id if missing
    if not out.get("id"):
        out["id"] = str(uuid.uuid4())

    # Sync _alert_data.alert_name to match GUID
    ad = out.get("_alert_data")
    if isinstance(ad, dict):
        event_type = out.get("type", "")
        if "click" in event_type.lower():
            ad["alert_name"] = f"Proofpoint - Click Permitted - {out['GUID']}"
            ad["alert_type"] = "Proofpoint TAP - Click Permitted"
            ad["sourceInstance"] = "Proofpoint TAP v2_Clicks_Permitted"
        else:
            ad["alert_name"] = f"Proofpoint - Message Delivered - {out['GUID']}"
            ad["alert_type"] = "Proofpoint TAP - Message Delivered"
            ad["sourceInstance"] = "Proofpoint TAP v2_Messages_Delivered"
        ad["alert_source"] = "Proofpoint TAP v2"
        ad["alert_sub_type"] = "XDR"
        ad["alert_action_status"] = "DETECTED"
        ad["isactive"] = True
        ad["resolution_status"] = "STATUS_010_NEW"

        # Update raw_json inside _alert_data to reflect threatsInfoMap changes
        tim = out.get("threatsInfoMap")
        if tim and isinstance(tim, list):
            rj = ad.get("raw_json")
            if isinstance(rj, str):
                try:
                    rj_obj = json.loads(rj)
                    rj_obj["threatsInfoMap"] = tim
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

    print(f"[+] Converted {len(events)} row(s) from {input_path.name} → {output_path}")
    print(f"    Send with:")
    print(f"    python3 send_test_events.py --file {output_path} --env .env-brumxdr-proofpoint --time-field _time")


if __name__ == "__main__":
    main()
