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


# ── Timestamp helpers — identical logic to replay_scenario.py ─────────────────

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


def time_range(events: List[Dict[str, Any]], field: str) -> Tuple[Optional[datetime], Optional[datetime]]:
    times = []
    for ev in events:
        raw = ev.get(field)
        if isinstance(raw, str):
            dt = _parse_timestamp(raw)
            if dt:
                times.append(dt)
    return (min(times), max(times)) if times else (None, None)


def rebase(
        events: List[Dict[str, Any]],
        field: str,
        anchor: datetime,
        compress_window: timedelta,
        global_min: Optional[datetime] = None,
        global_max: Optional[datetime] = None,
) -> int:
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


# ── Normalization — identical logic to replay_scenario.py ────────────────────

def normalize_events(events: List[Dict[str, Any]], source_name: str) -> List[Dict[str, Any]]:
    run_id = uuid.uuid4().hex[:8]
    src = source_name.lower()

    for ev in events:
        # Proofpoint TAP: normalize recipient list, rotate GUID/id
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

        # CrowdStrike: reconstruct UPN, rotate composite_id
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

        # Microsoft Defender: rotate providerAlertId/id
        if "defender" in src or "microsoft" in src or "mde" in src:
            for id_field in ("providerAlertId", "id"):
                val = ev.get(id_field, "")
                if val:
                    ev[id_field] = f"{val}-{run_id}"

    return events


# ── List loading — scripts have executeCommand ────────────────────────────────

def load_list(list_name: str) -> List[Dict[str, Any]]:
    res = demisto.executeCommand("getList", {"listName": list_name})
    if isError(res):
        raise ValueError(
            f"List '{list_name}' not found or could not be read. "
            f"Check the list name matches exactly. Error: {get_error(res)}"
        )
    content = res[0].get("Contents", "")
    if not content or content == "Item not found (8)":
        raise ValueError(
            f"List '{list_name}' does not exist. "
            f"Verify the list is installed and the name is correct."
        )
    if isinstance(content, list):
        return content
    if isinstance(content, str):
        return json.loads(content)
    raise ValueError(f"Unexpected list content type: {type(content)}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = demisto.args()

    list_name     = args.get("list_name", "")
    instance_name = args.get("instance_name", "")
    source_name   = args.get("source_name", "")
    compress_str  = args.get("compress_window", "2h")
    global_min_str = args.get("global_min", "")
    global_max_str = args.get("global_max", "")

    if not list_name:
        return_error("list_name is required.")
    if not instance_name:
        return_error("instance_name is required (e.g. socfw_pov_crowdstrike_sender).")
    if not source_name:
        return_error("source_name is required (e.g. crowdstrike or proofpoint).")

    try:
        compress_window = parse_duration(compress_str)

        global_min: Optional[datetime] = _parse_timestamp(global_min_str) if global_min_str else None
        global_max: Optional[datetime] = _parse_timestamp(global_max_str) if global_max_str else None

        # Load from list (executeCommand available in scripts)
        events = load_list(list_name)
        if not events:
            return_results(f"List '{list_name}' contains no events — nothing sent.")
            return

        # Normalize and rebase
        events = normalize_events(events, source_name)
        time_field = detect_time_field(events) or "_time"
        anchor = datetime.now(timezone.utc)
        rebased = rebase(events, time_field, anchor, compress_window,
                         global_min=global_min, global_max=global_max)

        # Batch the executeCommand calls — CrowdStrike events are ~18KB each,
        # 138 events = 2.3MB which exceeds the executeCommand argument size limit.
        # Send in batches of 5 events (~100KB per call) to stay well under the limit.
        _BATCH_SIZE = 5
        total = len(events)
        sent = 0

        for i in range(0, total, _BATCH_SIZE):
            batch = events[i:i + _BATCH_SIZE]
            execute_args = {"JSON": json.dumps(batch)}
            if instance_name:
                execute_args["using"] = instance_name

            result = demisto.executeCommand("socfw-pov-send-data", execute_args)

            failed = isError(result)
            if not failed and result:
                entry = result[0] if isinstance(result, list) else result
                contents = entry.get("Contents", "") if isinstance(entry, dict) else ""
                if "Unsupported Command" in str(contents):
                    return_error(
                        f"SOCFWPoVSender failed — check instance name '{instance_name}' "
                        f"is correct and the integration is enabled. Detail: {contents}"
                    )
            if failed:
                return_error(f"SOCFWPoVSender failed on batch {i // _BATCH_SIZE + 1}: {get_error(result)}")

            sent += len(batch)
            demisto.debug(f"SOCFWPoVSend: batch {i // _BATCH_SIZE + 1} — {sent}/{total} events sent")

        summary = (
            f"**SOCFWPoVSend** — complete\n\n"
            f"| Field | Value |\n|---|---|\n"
            f"| List | `{list_name}` |\n"
            f"| Source | `{source_name}` |\n"
            f"| Instance | `{instance_name}` |\n"
            f"| Events sent | {len(events)} |\n"
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
