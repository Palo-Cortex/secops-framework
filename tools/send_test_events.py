#!/usr/bin/env python3

import os
import json
import argparse
import requests
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

"""
python3 tools/send_test_events.py \
  --file output/test_messages_delivered.json \
  --env .env-httpcollector-proofpoint
"""


# ---------- Env + file helpers (unchanged API) ----------

def load_env(env_path: str) -> None:
    if not os.path.isfile(env_path):
        raise FileNotFoundError(f".env file not found at: {env_path}")
    # override=True ensures that when replay_scenario.py iterates multiple
    # sources with different .env files, each source's API_URL and API_KEY
    # replace the previously loaded values rather than being silently ignored.
    load_dotenv(env_path, override=True)
    for var in ("API_URL", "API_KEY"):
        if os.getenv(var) is None:
            raise EnvironmentError(f"Missing {var} in {env_path}")


def read_events(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else [data]


# ---------- Timestamp helpers ----------

def simple_set_timestamps(events: List[Dict[str, Any]]) -> None:
    now_iso = datetime.now(timezone.utc).isoformat()

    # fields that often drive "observation time" or event time
    top_level_time_fields = [
        "alert_time",
        "created_date_time",
        "updated_date_time",
        "@timestamp",
        "timestamp",
        "event_creation_time",
        "eventCreationTime",
        "EventTimestamp",
        "observation_time",
        "observationTime",
        "source_insert_ts",
    ]

    for ev in events:
        ev["_time"] = now_iso
        ev["_insert_time"] = now_iso

        # update top-level fields if they exist
        for k in top_level_time_fields:
            if k in ev:
                ev[k] = now_iso

        # also update inside _alert_data.raw_json if present (dict or json string)
        ad = ev.get("_alert_data")
        if isinstance(ad, dict):
            rj = ad.get("raw_json")
            if isinstance(rj, str):
                try:
                    rj_obj = json.loads(rj)
                except Exception:
                    rj_obj = None
                if isinstance(rj_obj, dict):
                    rj_obj["created_date_time"] = now_iso
                    rj_obj["updated_date_time"] = now_iso
                    ad["raw_json"] = json.dumps(rj_obj)
            elif isinstance(rj, dict):
                rj["created_date_time"] = now_iso
                rj["updated_date_time"] = now_iso

    print(f"[*] (simple) Updated timestamps on {len(events)} event(s) → {now_iso}")



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
        start: datetime,
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


def rebase_timestamps(
        events: List[Dict[str, Any]],
        time_field: str,
        time_format: Optional[str],
        start: datetime,
) -> None:
    """
    Replay-style behavior:

    - Compute offset so earliest event[time_field] -> start
    - Apply offset to:
        - time_field
        - common timestamp fields if present
        - _time
        - _insert_time
    - Preserve original time_field in cs_original_time
    """
    offset = compute_offset(events, time_field, time_format, start)
    print(f"[*] (replay) Applying time offset: {offset}")

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

    updated = 0
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

    print(f"[*] (replay) Rebased timestamps on {updated} event(s)")


# ---------- Sender (unchanged API) ----------

def send_events(events, api_url: str, api_key: str,
                batch_size: int = 5, max_body_bytes: int = 512_000):
    """
    Pure sender: assumes events already have whatever timestamps you want.

    Batches the POST. A single large body (e.g. 138 CrowdStrike EPP events at
    ~17KB each = 2.3MB) returns HTTP 200 but is silently dropped by the HTTP
    collector — nothing lands in the dataset. Small sources (2-event Proofpoint)
    work because the body is trivial. To avoid that, send in chunks.

    Two ceilings are enforced per POST, whichever is hit first:
      - batch_size: max events per POST (default 5)
      - max_body_bytes: max serialized body size per POST (default ~512KB)

    Events are NDJSON (one JSON object per line), unchanged from before.
    """
    headers = {
        "Authorization": api_key,  # bare api_key as before
        "Content-Type": "application/json",
    }

    total = len(events)
    print(f"[*] Sending {total} events to {api_url} "
          f"(batch_size={batch_size}, max_body={max_body_bytes}B)")

    # Build batches honoring both the count cap and the byte cap.
    batches = []
    cur, cur_bytes = [], 0
    for ev in events:
        line = json.dumps(ev)
        ln = len(line) + 1  # +1 for the newline join
        # flush if adding this event would breach either ceiling
        if cur and (len(cur) >= batch_size or cur_bytes + ln > max_body_bytes):
            batches.append(cur)
            cur, cur_bytes = [], 0
        cur.append(ev)
        cur_bytes += ln
    if cur:
        batches.append(cur)

    sent = 0
    failures = 0
    for i, batch in enumerate(batches, 1):
        body = "\n".join(json.dumps(ev) for ev in batch)
        try:
            resp = requests.post(api_url, headers=headers, data=body, timeout=30)
            ok = 200 <= resp.status_code < 300
            sent += len(batch) if ok else 0
            failures += 0 if ok else 1
            print(f"    batch {i}/{len(batches)}: {len(batch)} events "
                  f"({len(body)}B) → HTTP {resp.status_code} {resp.text.strip()[:80]}")
            if not ok:
                print(f"    [!] batch {i} failed; stopping.")
                break
        except requests.RequestException as e:
            failures += 1
            print(f"    [!] batch {i} POST error: {e}")
            break

    print(f"[+] Done: {sent}/{total} events accepted across "
          f"{len(batches)} batch(es); {failures} failed batch(es).")
    return failures == 0


# ---------- CLI ----------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True, help="JSON file with event(s)")
    parser.add_argument("--env", default=".env-brumxdr-crowdstrike")

    # New options for replay-style behavior
    parser.add_argument(
        "--time-field",
        help=(
            "Field in the JSON that holds the original event timestamp "
            "(e.g. 'event_creation_time', 'timestamp', etc.). "
            "If omitted, we just set _time/_insert_time to now (old behavior)."
        ),
    )
    parser.add_argument(
        "--time-format",
        default=None,
        help=(
            "Optional Python strptime format for --time-field. "
            "If omitted, assumes ISO8601 and uses fromisoformat()."
        ),
    )
    parser.add_argument(
        "--start",
        default=None,
        help=(
            "Replay start time in ISO8601 (e.g. 2025-12-07T09:00:00+00:00). "
            "If omitted and --time-field is given, uses now() in UTC."
        ),
    )

    args = parser.parse_args()

    # resolve env path from tools/
    env_path = args.env
    if not os.path.isabs(env_path):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(script_dir)
        env_path = os.path.join(repo_root, env_path)

    load_env(env_path)
    api_url = os.getenv("API_URL")
    api_key = os.getenv("API_KEY")

    events = read_events(args.file)

    # Decide how to handle timestamps
    if args.time_field:
        # Replay-style mode
        if args.start:
            start_dt = datetime.fromisoformat(args.start)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        else:
            start_dt = datetime.now(timezone.utc)

        print(f"[*] (replay) Start time: {start_dt.isoformat()}")
        rebase_timestamps(events, args.time_field, args.time_format, start_dt)
    else:
        # Original simple behavior
        simple_set_timestamps(events)

    send_events(events, api_url, api_key)


if __name__ == "__main__":
    main()
