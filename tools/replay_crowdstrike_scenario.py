#!/usr/bin/env python3
"""
Replay a CrowdStrike JSON scenario (e.g. MITRE Turla Carbon) into XSIAM,
preserving relative timing and endpoint behavior, while anonymizing ONLY
CrowdStrike cloud tenant identifiers.

Workflow:

  1) Convert TSV -> JSON array with existing script (unchanged):
       python tools/tsv_to_json.py \
         --input turla_carbon_falcon.tsv \
         --output tools/turla_carbon_falcon.json

  2) Replay the JSON into XSIAM with rebased timestamps:
       python tools/replay_crowdstrike_scenario.py \
         --file tools/turla_carbon_falcon.json \
         --time-field "event_creation_time" \
         --env ".env-brumxdr-crowdstrike"

What this script does:

  - Reads JSON array of events (output from tsv_to_json.py).
  - Uses `time-field` to compute the earliest event time.
  - If --start is provided, earliest event -> that time.
    Otherwise, earliest event -> now() in UTC.
  - Rewrites:
      - ev[time_field]
      - ev["@timestamp"], ev["timestamp"], ev["event_creation_time"],
        ev["EventTimestamp"], ev["observation_time"], etc. if present
      - ev["_time"]
      - ev["_insert_time"]
    while preserving the original time in `cs_original_time`.
  - Leaves ALL endpoint behavior as-is (aid, host, IPs, hashes, etc.).
  - Anonymizes ONLY CrowdStrike cloud tenant fields + Falcon console URLs.
  - Reuses send_test_events.py for env loading and HTTP sending.
"""

import os
import sys
import json
import argparse
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urlunparse

# Make sure we can import send_test_events from the same tools/ directory
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import send_test_events  # uses load_env, read_events, send_events


# ---------- Stable anonymizer for CrowdStrike cloud tenant identifiers ----------

class StableAnonymizer:
    """
    Stable mapping for CrowdStrike cloud tenant identifiers only.

    We intentionally DO NOT touch:
      - aid / AgentId / sensorId
      - endpoint hostnames, IPs
      - hashes, domains, URLs, processes, usernames

    We ONLY anonymize fields that identify the Falcon CLOUD tenant
    (who the customer/org is), e.g.:

      - cid
      - customerId / CustomerId
      - orgId / OrgId
      - tenantId / TenantId
      - falcon_customer_name
      - cs_cloud_org
      - etc.
    """

    def __init__(self, prefix: str = "cscloud") -> None:
        self.prefix = prefix
        self._cache: Dict[str, str] = {}

    def _hash(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]

    def anon(self, value: Optional[str], kind: str) -> Optional[str]:
        if value is None:
            return None
        key = f"{kind}:{value}"
        if key not in self._cache:
            self._cache[key] = f"{self.prefix}-{kind}-{self._hash(value)}"
        return self._cache[key]


TENANT_FIELDS: List[str] = [
    "cid",
    "customerId",
    "CustomerId",
    "orgId",
    "OrgId",
    "tenantId",
    "TenantId",
    "cs_cloud_org",
    "falcon_customer_name",
    "falcon_cloud_tenant",
    "cloud_tenant",
]


def _scrub_falcon_url(value: str) -> str:
    """
    Replace the real Falcon console hostname with a generic one,
    keeping the path so the link still looks real but doesn't leak
    the original tenant/region.
    """
    try:
        parsed = urlparse(value)
    except Exception:
        return value  # not a valid URL; leave unchanged

    if not parsed.scheme or not parsed.netloc:
        return value

    # Pick any fake console host you like
    fake_netloc = "falcon.socframework.local"

    return urlunparse((
        parsed.scheme or "https",
        fake_netloc,
        parsed.path or "",
        "",  # params
        "",  # query
        "",  # fragment
    ))


def anonymize_crowdstrike_cloud(ev: Dict[str, Any], anon: StableAnonymizer) -> None:
    """
    Mutate a single event, anonymizing only cloud-tenant-level identifiers.
    """

    # 1) ID-like tenant fields
    for field in TENANT_FIELDS:
        if field in ev and ev[field]:
            ev[field] = anon.anon(str(ev[field]), kind=field.lower())

    # 2) Falcon console URLs (e.g. Falcon_Host_Link)
    for key, val in list(ev.items()):
        if not isinstance(val, str):
            continue

        lk = key.lower()
        # Match both specific field names and generic "falcon + link"
        if lk == "falcon_host_link" or ("falcon" in lk and "link" in lk):
            ev[key] = _scrub_falcon_url(val)


# ---------- Time parsing / rebasing ----------

def parse_event_time(raw: str, time_format: Optional[str]) -> datetime:
    """
    Parse an event time string into an aware datetime in UTC.

    If time_format is provided, use datetime.strptime.
    Otherwise, assume ISO8601; handle trailing 'Z' if present.
    """
    s = raw.strip()
    if time_format:
        dt = datetime.strptime(s, time_format)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    else:
        # Best-effort ISO8601 parse
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt


def compute_offset(
        events: List[Dict[str, Any]],
        time_field: str,
        time_format: Optional[str],
        start: datetime
) -> timedelta:
    """
    Compute the timedelta such that the earliest event time becomes `start`.
    """
    times: List[datetime] = []
    for ev in events:
        raw = ev.get(time_field)
        if not isinstance(raw, str) or not raw.strip():
            continue
        try:
            times.append(parse_event_time(raw, time_format))
        except Exception as e:
            print(f"[!] Skipping unparsable time '{raw}' ({e})")

    if not times:
        print("[!] No valid timestamps found; using zero offset.")
        return timedelta(0)

    first = min(times)
    return start - first


def apply_rebased_times(
        events: List[Dict[str, Any]],
        time_field: str,
        time_format: Optional[str],
        offset: timedelta,
) -> None:
    """
    For each event, compute:

        new_time = parse(original[time_field]) + offset

    Then write rebased time into:

        - ev[time_field]
        - ev["@timestamp"], ev["timestamp"], ev["event_creation_time"],
          ev["eventCreationTime"], ev["EventTimestamp"], ev["observation_time"],
          ev["observationTime"] (if present)
        - ev["_time"]
        - ev["_insert_time"]

    Preserve original in `cs_original_time`.
    """

    # Common timestamp field names that might exist
    # and influence how XSIAM sets its internal _time.
    candidate_fields = {
        time_field,
        "@timestamp",
        "timestamp",
        "event_creation_time",
        "eventCreationTime",
        "EventTimestamp",
        "observation_time",
        "observationTime",
    }

    for ev in events:
        raw = ev.get(time_field)
        if not isinstance(raw, str) or not raw.strip():
            continue

        try:
            original_dt = parse_event_time(raw, time_format)
        except Exception as e:
            print(f"[!] Skipping event with unparsable time '{raw}' ({e})")
            continue

        new_dt = original_dt + offset
        new_iso = new_dt.isoformat()

        # Keep the original around for debugging
        ev.setdefault("cs_original_time", raw)

        # Overwrite all candidate timestamp fields that exist in this event
        for fld in candidate_fields:
            if fld in ev:
                ev[fld] = new_iso

        # Also set these explicit helpers
        ev["_time"] = new_iso
        ev["_insert_time"] = new_iso


# ---------- CLI / env helpers ----------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Replay CrowdStrike JSON scenario into XSIAM, preserving behavior and "
            "anonymizing only cloud tenant identifiers."
        )
    )

    p.add_argument(
        "--file",
        required=True,
        help="JSON file produced by tsv_to_json.py (array of events).",
    )
    p.add_argument(
        "--time-field",
        required=True,
        help=(
            "Field in the JSON that holds the original event timestamp "
            "(e.g. 'event_creation_time', 'timestamp', etc.)."
        ),
    )
    p.add_argument(
        "--time-format",
        default=None,
        help=(
            "Optional Python strptime format for time-field. "
            "If omitted, assumes ISO8601 and uses fromisoformat()."
        ),
    )
    p.add_argument(
        "--start",
        default=None,
        help=(
            "Replay start time in ISO8601 "
            "(e.g. 2025-12-06T14:00:00+00:00). "
            "If omitted, uses now() in UTC."
        ),
    )
    p.add_argument(
        "--env",
        default=".env-brumxdr-crowdstrike",
        help="Path to .env file (same style as send_test_events.py).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't send to XSIAM; just show what would happen.",
    )

    return p.parse_args()


def resolve_env_path(env_rel: str) -> str:
    """
    Mirror send_test_events behavior:
      - If relative, treat it as repo_root/<env_rel>, where repo_root = parent of tools/.
    """
    if os.path.isabs(env_rel):
        return env_rel
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    return os.path.join(repo_root, env_rel)


def main() -> None:
    args = parse_args()

    # 1) Determine replay start time
    if args.start:
        start_dt = datetime.fromisoformat(args.start)
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=timezone.utc)
    else:
        start_dt = datetime.now(timezone.utc)
    print(f"[*] Replay start time: {start_dt.isoformat()}")

    # 2) Load events (reuse send_test_events.read_events)
    events = send_test_events.read_events(args.file)
    print(f"[*] Loaded {len(events)} event(s) from {args.file}")

    if not events:
        print("[!] No events to replay; exiting.")
        return

    # 3) Compute offset so earliest event -> start_dt
    offset = compute_offset(events, args.time_field, args.time_format, start_dt)
    print(f"[*] Applying time offset: {offset}")

    apply_rebased_times(events, args.time_field, args.time_format, offset)
    print("[*] Updated timestamp fields + _time/_insert_time with rebased values")

    # 4) Anonymize ONLY CrowdStrike cloud tenant info (IDs + console URLs)
    anon = StableAnonymizer(prefix="falcon")
    for ev in events:
        anonymize_crowdstrike_cloud(ev, anon)

    # 5) Load env + send
    env_path = resolve_env_path(args.env)
    print(f"[*] Loading env from {env_path}")
    send_test_events.load_env(env_path)
    api_url = os.getenv("API_URL")
    api_key = os.getenv("API_KEY")

    if not api_url or not api_key:
        raise EnvironmentError("API_URL or API_KEY missing after loading env")

    if args.dry_run:
        print(f"[DRY RUN] Would send {len(events)} events to {api_url}")
        # Show a sample event for sanity
        print(json.dumps(events[0], indent=2)[:2000])
        return

    send_test_events.send_events(events, api_url=api_url, api_key=api_key)
    print("[+] Replay complete.")


if __name__ == "__main__":
    main()
