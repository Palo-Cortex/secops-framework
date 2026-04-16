import demistomock as demisto  # type: ignore
from CommonServerPython import *  # type: ignore

import json
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple


# ── Constants ─────────────────────────────────────────────────────────────────

_TIME_FIELD_CANDIDATES = [
    "_time", "created_timestamp", "event_creation_time", "eventCreationTime",
    "EventTimestamp", "messageTime", "clickTime", "threatTime", "timestamp",
    "@timestamp", "observation_time", "context_timestamp",
]

_REBASE_FIELDS = set(_TIME_FIELD_CANDIDATES) | {"crawled_timestamp", "_insert_time"}

_FALLBACK_FORMATS = [
    "%b %d %Y %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
]

_KEEP_FIELDS = {"_time", "_name"}


def _parse_timestamp(raw: str) -> Optional[datetime]:
    s = raw.strip()
    if not s:
        return None
    normalized = s
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    normalized = re.sub(
        r"(\d{2}:\d{2}:\d{2})\.(\d+)",
        lambda m: m.group(1) + "." + m.group(2)[:6].ljust(6, "0"),
        normalized,
    )
    try:
        dt = datetime.fromisoformat(normalized)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in _FALLBACK_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def detect_time_field(events: List[Dict[str, Any]]) -> Optional[str]:
    for field in _TIME_FIELD_CANDIDATES:
        for ev in events[:5]:
            raw = ev.get(field)
            if isinstance(raw, str) and _parse_timestamp(raw):
                return field
    return None


def parse_duration(spec: str) -> timedelta:
    s = spec.strip().lower()
    total = 0
    for val, unit in re.findall(r"(\d+)\s*([dhms]?)", s):
        v = int(val)
        u = unit or "m"
        if u == "d":   total += v * 86400
        elif u == "h": total += v * 3600
        elif u == "m": total += v * 60
        elif u == "s": total += v
    if total == 0:
        raise ValueError(f"Cannot parse duration: {spec!r}")
    return timedelta(seconds=total)


def time_range(events, field):
    times = []
    for ev in events:
        raw = ev.get(field)
        if isinstance(raw, str):
            dt = _parse_timestamp(raw)
            if dt:
                times.append(dt)
    return (min(times), max(times)) if times else (None, None)


def rebase(events, field, anchor, compress_window, global_min=None, global_max=None):
    first_dt, last_dt = time_range(events, field)
    if first_dt is None:
        return 0
    range_min = global_min or first_dt
    range_max = global_max or last_dt
    span = (range_max - range_min).total_seconds()
    updated = 0
    for ev in events:
        raw = ev.get(field)
        if not isinstance(raw, str):
            continue
        original_dt = _parse_timestamp(raw)
        if original_dt is None:
            continue
        if span > 0:
            frac = max(0.0, min(1.0, (original_dt - range_min).total_seconds() / span))
            new_dt = (anchor - compress_window) + timedelta(seconds=frac * compress_window.total_seconds())
        else:
            new_dt = anchor
        new_iso = new_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        ev.setdefault("_original_time", raw)
        ev[field]          = new_iso
        ev["_time"]        = new_iso
        ev["_insert_time"] = new_iso
        for fld in _REBASE_FIELDS:
            if fld == field or fld not in ev:
                continue
            other_raw = ev[fld]
            if not isinstance(other_raw, str):
                continue
            other_dt = _parse_timestamp(other_raw)
            if other_dt is None:
                continue
            if span > 0:
                frac2 = max(0.0, min(1.0, (other_dt - range_min).total_seconds() / span))
                new_other = (anchor - compress_window) + timedelta(seconds=frac2 * compress_window.total_seconds())
            else:
                new_other = anchor
            ev[fld] = new_other.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        updated += 1
    return updated


def normalize_events(events, source_name):
    run_id = uuid.uuid4().hex[:8]
    src = source_name.lower()
    for ev in events:
        if "proofpoint" in src or "tap" in src:
            recipient = ev.get("recipient")
            if isinstance(recipient, list):
                ev["recipient"] = recipient[0] if recipient else ""
            elif isinstance(recipient, str):
                stripped = recipient.strip()
                if stripped.startswith("["):
                    try:
                        parsed = json.loads(stripped)
                        ev["recipient"] = parsed[0] if parsed else ""
                    except Exception:
                        pass
            for guid_field in ("GUID", "id"):
                val = ev.get(guid_field, "")
                if val:
                    ev[guid_field] = f"{val}-{run_id}"
        if "crowdstrike" in src or "falcon" in src:
            user_name = ev.get("user_name", "")
            if (isinstance(user_name, str) and user_name
                    and "@" not in user_name
                    and not user_name.endswith("$")
                    and user_name.upper() != "SYSTEM"):
                device = ev.get("device", {})
                domain = ""
                if isinstance(device, dict):
                    domain = device.get("machine_domain", "") or device.get("domain", "")
                if not domain:
                    domain = ev.get("domain", "")
                if not domain:
                    up = ev.get("user_principal", "")
                    if up and "@" in up:
                        domain = up.split("@")[1]
                if domain:
                    ev["user_name"] = f"{user_name}@{domain.upper()}"
            val = ev.get("composite_id", "")
            if val:
                ev["composite_id"] = f"{val}-{run_id}"
        if "defender" in src or "microsoft" in src or "mde" in src:
            for id_field in ("providerAlertId", "id"):
                val = ev.get(id_field, "")
                if val:
                    ev[id_field] = f"{val}-{run_id}"
    return events


def load_list(list_name):
    res = demisto.executeCommand("getList", {"listName": list_name})
    if isError(res):
        raise ValueError(f"List '{list_name}' not found. Error: {get_error(res)}")
    content = res[0].get("Contents", "")
    if not content or content == "Item not found (8)":
        raise ValueError(f"List '{list_name}' does not exist.")
    if isinstance(content, list):
        return content
    if isinstance(content, str):
        return json.loads(content)
    raise ValueError(f"Unexpected list content type: {type(content)}")



def main():
    args = demisto.args()

    list_name      = args.get("list_name", "")
    source_name    = args.get("source_name", "")
    seed_mode      = argToBoolean(args.get("seed", "false"))
    compress_str   = args.get("compress_window", "2h")
    global_min_str = args.get("global_min", "")
    global_max_str = args.get("global_max", "")

    if not list_name:
        return_error("list_name is required.")
    if not source_name:
        return_error("source_name is required (e.g. crowdstrike or proofpoint).")

    # Instance name follows convention: socfw_pov_{source_name}_sender
    # Enforced by xsoar_config.json — adding a new source = adding the instance there.
    instance_name = f"socfw_pov_{source_name.lower()}_sender"

    try:
        # Load event data from list
        events = load_list(list_name)
        if not events:
            return_results(f"List '{list_name}' is empty — nothing sent.")
            return

        # Strip XSIAM system fields that collide with HTTP Collector metadata.
        # Keep _time (needed for rebase) and _name (CrowdStrike detection name).
        stripped_count = 0
        for ev in events:
            sys_keys = [k for k in ev if k.startswith("_") and k not in _KEEP_FIELDS]
            for k in sys_keys:
                del ev[k]
            if sys_keys:
                stripped_count += 1

        # Strip non-vendor fields that shouldn't be in the dataset.
        # These survive the _ prefix check but aren't real vendor fields.
        _STRIP_EXTRA = {"scenario_name", "scenario_source"}
        for ev in events:
            for k in _STRIP_EXTRA:
                ev.pop(k, None)

        # ── SEED MODE ──
        # Sends a single event with an old timestamp to create the dataset
        # and populate its schema. Does NOT trigger correlation rules.
        # Run this BEFORE installing vendor correlation rule packs.
        if seed_mode:
            seed_event = dict(events[0])  # copy first event for schema
            seed_event["_time"] = "2020-01-01T00:00:00.000Z"
            # Zero out scores so it never looks like a real detection
            for score_field in ("confidence", "severity", "phishScore",
                                "spamScore", "malwareScore", "impostorScore"):
                if score_field in seed_event:
                    seed_event[score_field] = 0

            execute_args = {
                "JSON": json.dumps([seed_event]),
                "using": instance_name,
            }
            result = demisto.executeCommand("socfw-pov-send-data", execute_args)
            if isError(result):
                return_error(f"Seed failed: {get_error(result)}")

            return_results(
                f"**SOCFWPoVSend** — seed complete\n\n"
                f"| Field | Value |\n|---|---|\n"
                f"| Source | `{source_name}` |\n"
                f"| Instance | `{instance_name}` |\n"
                f"| Schema fields | {len(seed_event)} |\n"
                f"| Timestamp | `2020-01-01` (will not trigger rules) |\n\n"
                f"Wait 60 seconds, then install the vendor correlation rule pack."
            )
            return

        # ── FULL REPLAY MODE ──
        compress_window = parse_duration(compress_str)
        global_min = _parse_timestamp(global_min_str) if global_min_str else None
        global_max = _parse_timestamp(global_max_str) if global_max_str else None

        # Normalize and rebase
        events = normalize_events(events, source_name)
        time_field = detect_time_field(events) or "_time"
        anchor = datetime.now(timezone.utc)
        rebased = rebase(events, time_field, anchor, compress_window,
                         global_min=global_min, global_max=global_max)

        # Send in batches via SOCFWPoVSender integration.
        # Instance name derived from source_name convention, locked by xsoar_config.json.
        _BATCH_SIZE = 5
        total = len(events)
        sent = 0

        for i in range(0, total, _BATCH_SIZE):
            batch = events[i:i + _BATCH_SIZE]
            execute_args = {
                "JSON": json.dumps(batch),
                "using": instance_name,
            }

            result = demisto.executeCommand("socfw-pov-send-data", execute_args)

            failed = isError(result)
            if not failed and result:
                entry = result[0] if isinstance(result, list) else result
                contents = entry.get("Contents", "") if isinstance(entry, dict) else ""
                if "Unsupported Command" in str(contents):
                    return_error(
                        f"socfw-pov-send-data not found on instance '{instance_name}'. "
                        f"Verify: Settings → Integrations → search SOCFWPoVSender → "
                        f"instance '{instance_name}' exists and is enabled."
                    )
            if failed:
                return_error(f"Batch {i // _BATCH_SIZE + 1} failed: {get_error(result)}")

            sent += len(batch)
            demisto.debug(f"SOCFWPoVSend: batch {i // _BATCH_SIZE + 1} — {sent}/{total}")

        summary = (
            f"**SOCFWPoVSend** — complete\n\n"
            f"| Field | Value |\n|---|---|\n"
            f"| List | `{list_name}` |\n"
            f"| Source | `{source_name}` |\n"
            f"| Instance | `{instance_name}` |\n"
            f"| Events sent | {sent} |\n"
            f"| System fields stripped | {stripped_count} |\n"
            f"| Timestamps rebased | {rebased} |\n"
            f"| Compress window | {compress_str} |\n"
            f"| Anchor | {anchor.strftime('%Y-%m-%dT%H:%M:%SZ')} |\n"
            f"| Global min | {global_min_str or 'auto'} |\n"
            f"| Global max | {global_max_str or 'auto'} |"
        )
        return_results(summary)

    except Exception as e:
        return_error(f"SOCFWPoVSend error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
