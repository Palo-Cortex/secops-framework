#!/usr/bin/env python3
"""
Replay a CrowdStrike Falcon scenario (e.g., MITRE Turla Carbon) into XSIAM
via HTTP Collector, with:

- Time rebasing:
  - Anchor the LATEST event to "now" (or an explicit --start time)
  - Optionally compress the whole scenario into a shorter demo window
    (e.g. --compress-window 60m, 2h, 1h30m)
- Tenant anonymization:
  - Rewrite CrowdStrike cloud tenant IPs and *.crowdstrike.com hosts
    (e.g., https://api.crowdstrike.com -> https://falcon.socframework.local)
  - Do NOT touch endpoint agent IDs, hostnames, etc.

This script expects a JSON array exported via your existing tsv_to_json.py,
and uses send_test_events.py for env loading + HTTP send.
"""

import os
import json
import argparse
import re
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple

import send_test_events  # reuse load_env, read_events, send_events


# ---------- Time parsing helpers ----------

def parse_event_time(raw: str, time_format: Optional[str]) -> datetime:
    """
    Parse an event time string into an aware datetime in UTC.

    - If time_format is provided, use datetime.strptime().
    - Else assume ISO8601-like (possibly with 'Z' and >6 fractional digits)
      and normalize to something datetime.fromisoformat() accepts.
    """
    s = raw.strip()

    if time_format:
        dt = datetime.strptime(s, time_format)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    # Handle 'Z' (UTC) or explicit offsets
    tz_suffix = ""
    if s.endswith("Z"):
        s = s[:-1]
        tz_suffix = "+00:00"
    else:
        plus = s.rfind("+")
        minus = s.rfind("-")
        idx = max(plus, minus)
        if idx > 10:
            tz_suffix = s[idx:]
            s = s[:idx]

    # Truncate fractional seconds to 6 digits (Python fromisoformat limit)
    if "." in s:
        main, frac = s.split(".", 1)
        frac_digits = "".join(ch for ch in frac if ch.isdigit())
        frac_trim = frac_digits[:6].ljust(6, "0")
        s = f"{main}.{frac_trim}"

    iso = s + (tz_suffix or "")
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def compute_time_range(
        events: List[Dict[str, Any]],
        time_field: str,
        time_format: Optional[str],
) -> Tuple[Optional[datetime], Optional[datetime]]:
    """
    Return (min_dt, max_dt) over all events that have a parseable time_field.
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
        return None, None
    return min(times), max(times)


def parse_duration(spec: str) -> timedelta:
    """
    Parse a simple duration like:
      - "60m", "15m"
      - "2h", "1h30m"
      - "90m"
      - "1d", "1d2h"

    Units: d (days), h (hours), m (minutes), s (seconds).
    If unit is omitted, assume minutes.
    """
    s = spec.strip().lower()
    if not s:
        raise ValueError("Empty duration spec")

    pattern = re.compile(r"(\d+)\s*([dhms]?)")
    total_seconds = 0
    pos = 0
    for m in pattern.finditer(s):
        val = int(m.group(1))
        unit = m.group(2) or "m"  # default to minutes
        pos = m.end()

        if unit == "d":
            total_seconds += val * 86400
        elif unit == "h":
            total_seconds += val * 3600
        elif unit == "m":
            total_seconds += val * 60
        elif unit == "s":
            total_seconds += val
        else:
            raise ValueError(f"Unknown duration unit: {unit}")

    if total_seconds == 0:
        raise ValueError(f"Could not parse duration spec: {spec}")

    return timedelta(seconds=total_seconds)


# ---------- CrowdStrike cloud anonymization ----------

def _looks_like_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _map_ip(original: str, state: Dict[str, Any]) -> str:
    """
    Map each real IPv4 to a stable fake IPv4 in a documentation range.
    Example outputs: 203.0.113.10, 203.0.113.11, ...

    We keep a mapping so the same original IP always gets the same fake IP.
    """
    ip_map: Dict[str, str] = state.setdefault("ip_map", {})
    if original in ip_map:
        return ip_map[original]

    counter = state.get("ip_counter", 10)
    state["ip_counter"] = counter + 1

    last_octet = counter % 254 or 1
    fake_ip = f"203.0.113.{last_octet}"
    ip_map[original] = fake_ip
    return fake_ip


_CROWDSTRIKE_HOST_PATTERN = re.compile(
    r"https://[A-Za-z0-9.\-]*crowdstrike\.com", re.IGNORECASE
)
_FAKE_FALCON_HOST = "https://falcon.socframework.local"


def _anonymize_string_for_cloud(key: str, value: str, state: Dict[str, Any]) -> str:
    """
    Only anonymize CrowdStrike CLOUD tenant info:
      - IPs in reporting_device fields
      - *.crowdstrike.com hosts in URLs

    Endpoint agent IDs, hostnames, etc., are left untouched.
    """
    lk = key.lower()

    # IPs for the cloud tenant
    if lk in (
            "_reporting_device_ip",
            "_final_reporting_device_ip",
            "reporting_device_ip",
            "final_reporting_device_ip",
    ):
        if _looks_like_ipv4(value):
            return _map_ip(value, state)

    # URLs pointing at CrowdStrike cloud
    if "url" in lk or "link" in lk or "endpoint" in lk or "host" in lk:
        # Replace any https://*.crowdstrike.com host with fake host
        def repl(_m):
            return _FAKE_FALCON_HOST

        new_val = _CROWDSTRIKE_HOST_PATTERN.sub(repl, value)
        return new_val

    # Also catch raw URL strings without key hints
    if _CROWDSTRIKE_HOST_PATTERN.search(value):
        return _CROWDSTRIKE_HOST_PATTERN.sub(_FAKE_FALCON_HOST, value)

    return value


def anonymize_crowdstrike_cloud(obj: Any, state: Dict[str, Any]) -> Any:
    """
    Recursively anonymize only the CrowdStrike CLOUD tenant info in the event.
    """
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            obj[k] = anonymize_crowdstrike_cloud(obj[k], state if isinstance(state, dict) else {})
        return obj

    if isinstance(obj, list):
        for i, v in enumerate(obj):
            obj[i] = anonymize_crowdstrike_cloud(v, state)
        return obj

    if isinstance(obj, str):
        # We don't know the key here, so just use a generic key name.
        # For URLs this is enough because we match the pattern.
        return _anonymize_string_for_cloud("", obj, state)

    return obj


def anonymize_crowdstrike_cloud_top(ev: Dict[str, Any], state: Dict[str, Any]) -> None:
    """
    Top-level helper that:
      - respects key names for reporting IP fields
      - still recurses to catch nested URLs
    """
    # First pass: key-aware transforms
    for k, v in list(ev.items()):
        if isinstance(v, str):
            ev[k] = _anonymize_string_for_cloud(k, v, state)

    # Second pass: recursive catch-all (e.g., nested structures)
    anonymize_crowdstrike_cloud(ev, state)


# ---------- Timestamp rebasing ----------

def rebase_timestamps(
        events: List[Dict[str, Any]],
        time_field: str,
        time_format: Optional[str],
        anchor: datetime,
        compress_window: Optional[timedelta],
) -> None:
    """
    Replay-style behavior:

    - Compute original min/max of time_field.
    - If compress_window is None:
        - Anchor the LATEST event to `anchor` (e.g., now).
          Earlier events land in the past, preserving real gaps.
    - If compress_window is set (demo mode):
        - Map the entire [min, max] range into [anchor - compress_window, anchor].
        - Order is preserved, but the scenario is "squashed" into a shorter window.
    - For each event, update:
        - time_field
        - common timestamp fields if present
        - _time
        - _insert_time
        - cs_original_time (preserved once)
    """
    first_dt, last_dt = compute_time_range(events, time_field, time_format)
    if first_dt is None or last_dt is None:
        print("[!] No valid timestamps found; leaving times as-is.")
        return

    print(f"[*] Original time range for {time_field}: {first_dt.isoformat()} → {last_dt.isoformat()}")

    candidate_fields = {
        time_field,
        "@timestamp",
        "timestamp",
        "event_creation_time",
        "eventCreationTime",
        "EventTimestamp",
        "observation_time",
        "observationTime",
        "context_timestamp",
        "created_timestamp",
        "crawled_timestamp",
    }

    updated = 0

    if compress_window is None:
        # Normal replay: latest event becomes anchor
        offset = anchor - last_dt
        print(f"[*] Mode: translate-only. Latest event → {anchor.isoformat()}, offset={offset}")
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

            ev.setdefault("cs_original_time", raw)

            for fld in candidate_fields:
                if fld in ev:
                    ev[fld] = new_iso

            ev["_time"] = new_iso
            ev["_insert_time"] = new_iso
            updated += 1
    else:
        # Demo mode: compress the whole scenario into a shorter window
        original_span = last_dt - first_dt
        if original_span.total_seconds() <= 0:
            print("[!] Original time range is zero or negative; falling back to translate-only.")
            offset = anchor - last_dt
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
                ev.setdefault("cs_original_time", raw)
                for fld in candidate_fields:
                    if fld in ev:
                        ev[fld] = new_iso
                ev["_time"] = new_iso
                ev["_insert_time"] = new_iso
                updated += 1
        else:
            print(f"[*] Mode: DEMO compress. Original span={original_span}, compress_window={compress_window}")
            start_new = anchor - compress_window
            total_secs = original_span.total_seconds()
            window_secs = compress_window.total_seconds()

            for ev in events:
                raw = ev.get(time_field)
                if not isinstance(raw, str) or not raw.strip():
                    continue
                try:
                    original_dt = parse_event_time(raw, time_format)
                except Exception as e:
                    print(f"[!] Skipping event with unparsable time '{raw}' ({e})")
                    continue

                frac = (original_dt - first_dt).total_seconds() / total_secs
                if frac < 0:
                    frac = 0.0
                elif frac > 1:
                    frac = 1.0

                new_dt = start_new + timedelta(seconds=frac * window_secs)
                new_iso = new_dt.isoformat()

                ev.setdefault("cs_original_time", raw)
                for fld in candidate_fields:
                    if fld in ev:
                        ev[fld] = new_iso
                ev["_time"] = new_iso
                ev["_insert_time"] = new_iso
                updated += 1

    print(f"[*] Rebased timestamps on {updated} event(s)")


# ---------- Main CLI ----------

def main():
    parser = argparse.ArgumentParser(
        description="Replay a CrowdStrike Falcon scenario into XSIAM via HTTP Collector"
    )
    parser.add_argument("--file", required=True, help="JSON file with event(s) to replay")
    parser.add_argument(
        "--env",
        default=".env-brumxdr-crowdstrike",
        help="Path to .env with API_URL and API_KEY (default: .env-brumxdr-crowdstrike)",
    )
    parser.add_argument(
        "--time-field",
        required=True,
        help=(
            "Field in the JSON that holds the original event timestamp "
            "(e.g. 'created_timestamp', 'event_creation_time', 'timestamp')."
        ),
    )
    parser.add_argument(
        "--time-format",
        default=None,
        help=(
            "Optional Python strptime format for --time-field. "
            "If omitted, assumes ISO8601-like and uses fromisoformat() with "
            "fraction truncation and Z handling."
        ),
    )
    parser.add_argument(
        "--start",
        default=None,
        help=(
            "Anchor time in ISO8601 (e.g. 2025-12-06T21:00:00+00:00). "
            "The LATEST event is mapped to this. If omitted, uses now() in UTC."
        ),
    )
    parser.add_argument(
        "--compress-window",
        default=None,
        help=(
            "DEMO MODE: compress the entire scenario into this window before the anchor. "
            "Examples: '60m', '2h', '1h30m'. If omitted, keep original span (multi-day)."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't actually send events; just show what would happen and print a sample.",
    )

    args = parser.parse_args()

    # Resolve env path from repo root (parent of tools/)
    env_path = args.env
    if not os.path.isabs(env_path):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(script_dir)
        env_path = os.path.join(repo_root, env_path)

    # Load env & events
    print(f"[*] Replay anchor time argument: {args.start or 'NOW (UTC)'}")
    if args.start:
        anchor = datetime.fromisoformat(args.start)
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=timezone.utc)
    else:
        anchor = datetime.now(timezone.utc)

    print(f"[*] Replay anchor (latest event → this): {anchor.isoformat()}")

    events = send_test_events.read_events(args.file)
    print(f"[*] Loaded {len(events)} event(s) from {args.file}")

    compress_window: Optional[timedelta] = None
    if args.compress_window:
        compress_window = parse_duration(args.compress_window)

    # Rebase timestamps
    rebase_timestamps(
        events,
        time_field=args.time_field,
        time_format=args.time_format,
        anchor=anchor,
        compress_window=compress_window,
    )

    # Anonymize CrowdStrike cloud tenant info
    anon_state: Dict[str, Any] = {}
    for ev in events:
        anonymize_crowdstrike_cloud_top(ev, anon_state)
        # Tag for easy XQL locating
        ev.setdefault("scenario_source", "replay_crowdstrike_scenario")
        ev.setdefault("scenario_name", "Turla Carbon Replay")

    # Load env and send / dry-run
    print(f"[*] Loading env from {env_path}")
    send_test_events.load_env(env_path)
    api_url = os.getenv("API_URL")
    api_key = os.getenv("API_KEY")

    if args.dry_run:
        print(f"[DRY RUN] Would send {len(events)} events to {api_url}")
        if events:
            print(json.dumps(events[0], indent=2, ensure_ascii=False))
    else:
        send_test_events.send_events(events, api_url=api_url, api_key=api_key)


if __name__ == "__main__":
    main()
