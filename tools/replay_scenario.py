#!/usr/bin/env python3
"""
replay_scenario.py — XSIAM Attack Scenario Replay Tool

Replays one or multiple data sources into XSIAM via HTTP Collector.
Supports single-vendor replays and multi-vendor grouping demos.

Usage:
    python3 tools/replay_scenario.py --manifest scenarios/turla_carbon_full_chain.yml
    python3 tools/replay_scenario.py --manifest scenarios/turla_carbon_full_chain.yml --compress-window 30m
    python3 tools/replay_scenario.py --manifest scenarios/turla_carbon_cs_only.yml --dry-run

Manifest format (YAML):
    scenario: Turla Carbon - Full Chain
    compress_window: 2h          # optional: compress timeline into demo window
    sources:
      - name: CrowdStrike
        file: output/turla_csfalcon_events.tsv   # TSV or JSON
        env: .env-brumxdr-crowdstrike
      - name: ProofPoint TAP
        file: output/turla_tap_events.tsv
        env: .env-brumxdr-proofpoint

Each source is sent to its own HTTP Collector endpoint (from its env file).
All sources share the same time anchor so the attack chain lands in proper order.
"""

import os
import csv
import json
import re
import argparse
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None

import send_test_events  # reuse load_env, send_events


# ── Timestamp auto-detection ──────────────────────────────────────────────────

# Fields tried in order when auto-detecting which field holds the event time.
# First one found with a parseable value wins.
_TIME_FIELD_CANDIDATES = [
    "_time",
    "created_timestamp",
    "event_creation_time",
    "eventCreationTime",
    "EventTimestamp",
    "messageTime",
    "clickTime",
    "threatTime",
    "timestamp",
    "@timestamp",
    "observation_time",
    "context_timestamp",
]

# Additional timestamp fields to rebase alongside the primary time field.
_REBASE_FIELDS = set(_TIME_FIELD_CANDIDATES) | {
    "crawled_timestamp",
    "_insert_time",
}

# Timestamp formats tried when ISO8601 auto-parse fails.
_FALLBACK_FORMATS = [
    "%b %d %Y %H:%M:%S",   # Dec 04 2025 11:07:50
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
]


def _parse_timestamp(raw: str) -> Optional[datetime]:
    """Try every known format to parse raw into an aware UTC datetime."""
    s = raw.strip()
    if not s:
        return None

    # ISO8601 with Z or offset
    normalized = s
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    # Truncate fractional seconds beyond 6 digits (Python fromisoformat limit)
    normalized = re.sub(
        r"(\d{2}:\d{2}:\d{2})\.(\d+)",
        lambda m: m.group(1) + "." + m.group(2)[:6].ljust(6, "0"),
        normalized,
    )

    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass

    for fmt in _FALLBACK_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    return None


def detect_time_field(events: List[Dict[str, Any]]) -> Optional[str]:
    """
    Return the first candidate field that has a parseable timestamp
    in the first few events. Returns None if nothing is found.
    """
    sample = events[:5]
    for field in _TIME_FIELD_CANDIDATES:
        for ev in sample:
            raw = ev.get(field)
            if isinstance(raw, str) and _parse_timestamp(raw):
                return field
    return None



# ── Source-specific normalization ─────────────────────────────────────────────

def normalize_events(events: List[Dict[str, Any]], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Normalize shared grouping fields across sources so XSIAM's grouping engine
    can correlate alerts from different vendors into a single case.

    Proofpoint TAP:
      recipient arrives as a list (TSV JSON-parsed). Extract first element.
      ["Gunter@SKT.LOCAL"] → "Gunter@SKT.LOCAL"

    CrowdStrike Falcon:
      user_name has no domain ("Gunter"). Reconstruct UPN using
      device.machine_domain → "Gunter@SKT.LOCAL".
      Machine accounts ending in $ are left unchanged.
    """
    import uuid as _uuid
    source_name = cfg.get("name", "").lower()
    _run_id = _uuid.uuid4().hex[:8]  # unique per normalize_events call = per source per run

    for ev in events:

        # Proofpoint: normalize recipient list → scalar
        # Also randomize GUID/id so suppression never blocks replay runs.
        # In production, Proofpoint generates a unique GUID per message event.
        # The TSV has fixed GUIDs — append a run-unique suffix to match real behavior.
        if "proofpoint" in source_name or "tap" in source_name:
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
            # Randomize GUID and id to bypass 24h suppression on repeated replays
            for guid_field in ("GUID", "id"):
                val = ev.get(guid_field, "")
                if val:
                    ev[guid_field] = f"{val}-{_run_id}"

        # CrowdStrike: reconstruct full UPN for human accounts only.
        # user_principal is unreliable (empty on many events, wrong for SYSTEM).
        # Rule: skip machine accounts ($) and SYSTEM; reconstruct from
        # user_name + device.machine_domain for all other accounts.
        if "crowdstrike" in source_name or "falcon" in source_name:
            user_name = ev.get("user_name", "")
            if (isinstance(user_name, str)
                    and user_name
                    and "@" not in user_name
                    and not user_name.endswith("$")
                    and user_name.upper() != "SYSTEM"):
                device = ev.get("device", {})
                domain = ""
                if isinstance(device, dict):
                    domain = (device.get("machine_domain", "")
                              or device.get("domain", ""))
                if not domain:
                    domain = ev.get("domain", "")
                # Fallback: extract domain from user_principal if available
                if not domain:
                    up = ev.get("user_principal", "")
                    if up and "@" in up:
                        domain = up.split("@")[1]
                if domain:
                    ev["user_name"] = f"{user_name}@{domain.upper()}"

        # Microsoft Defender for Endpoint (via Graph API):
        # Randomize providerAlertId and id to bypass suppression on repeated
        # replays. The rule suppresses on providerAlertId for 1 hour — appending
        # a run-unique suffix ensures each replay run fires fresh alerts.
        # incidentId is deliberately preserved: all events in the same replay
        # run share the same incidentId so XSIAM groups them into one incident.
        if "defender" in source_name or "microsoft" in source_name or "mde" in source_name:
            for id_field in ("providerAlertId", "id"):
                val = ev.get(id_field, "")
                if val:
                    ev[id_field] = f"{val}-{_run_id}"

    return events


# ── File loading ──────────────────────────────────────────────────────────────

def load_tsv(path: str) -> List[Dict[str, Any]]:
    """Load a TSV file into a list of dicts. Values that look like JSON are parsed."""
    events = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            ev: Dict[str, Any] = {}
            for k, v in row.items():
                if v is None:
                    ev[k] = ""
                    continue
                v = v.strip()
                # Attempt JSON parse for array/object values
                if v and v[0] in ("[", "{"):
                    try:
                        ev[k] = json.loads(v)
                        continue
                    except (json.JSONDecodeError, ValueError):
                        pass
                ev[k] = v
            events.append(ev)
    return events


def load_events(path: str) -> List[Dict[str, Any]]:
    """Load TSV or JSON file. Format detected by extension."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".tsv", ".txt", ".csv"):
        return load_tsv(path)
    else:
        return send_test_events.read_events(path)


# ── Duration parsing ──────────────────────────────────────────────────────────

def parse_duration(spec: str) -> timedelta:
    """Parse '2h', '30m', '1h30m', '1d' etc into a timedelta."""
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
        raise ValueError(f"Could not parse duration: {spec!r}")
    return timedelta(seconds=total)


# ── Time rebasing ─────────────────────────────────────────────────────────────

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
        compress_window: Optional[timedelta],
        global_min: Optional[datetime] = None,
        global_max: Optional[datetime] = None,
) -> int:
    """
    Rebase all timestamps in events.

    If compress_window is set, map [global_min, global_max] → [anchor - window, anchor].
    Otherwise shift so latest event lands at anchor, preserving original gaps.

    global_min/global_max allow multi-source scenarios to share a single time axis.
    """
    first_dt, last_dt = time_range(events, field)
    if first_dt is None:
        print(f"  [!] No parseable timestamps in '{field}' — leaving as-is")
        return 0

    # Use global range if provided (multi-source mode)
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

        if compress_window is not None and span > 0:
            frac = max(0.0, min(1.0, (original_dt - range_min).total_seconds() / span))
            new_dt = (anchor - compress_window) + timedelta(seconds=frac * compress_window.total_seconds())
        else:
            offset = anchor - range_max
            new_dt = original_dt + offset

        new_iso = new_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        ev.setdefault("_original_time", raw)
        ev[field] = new_iso
        ev["_time"] = new_iso
        ev["_insert_time"] = new_iso

        # Rebase other known time fields if present
        for fld in _REBASE_FIELDS:
            if fld == field or fld not in ev:
                continue
            other_raw = ev[fld]
            if not isinstance(other_raw, str):
                continue
            other_dt = _parse_timestamp(other_raw)
            if other_dt is None:
                continue
            if compress_window is not None and span > 0:
                frac2 = max(0.0, min(1.0, (other_dt - range_min).total_seconds() / span))
                new_other = (anchor - compress_window) + timedelta(seconds=frac2 * compress_window.total_seconds())
            else:
                new_other = other_dt + (anchor - range_max)
            ev[fld] = new_other.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        updated += 1

    return updated


# ── Env loading ───────────────────────────────────────────────────────────────

def resolve_env_path(env_path: str, script_dir: str) -> str:
    if os.path.isabs(env_path):
        return env_path
    # Try relative to repo root (parent of tools/)
    repo_root = os.path.dirname(script_dir)
    candidate = os.path.join(repo_root, env_path)
    if os.path.exists(candidate):
        return candidate
    # Try relative to cwd
    return os.path.join(os.getcwd(), env_path)


def load_env_file(env_path: str) -> Tuple[str, str]:
    """Load API_URL and API_KEY from an env file. Returns (url, key)."""
    send_test_events.load_env(env_path)
    url = os.environ.get("API_URL", "")
    key = os.environ.get("API_KEY", "")
    if not url:
        raise ValueError(f"API_URL not set in {env_path}")
    if not key:
        raise ValueError(f"API_KEY not set in {env_path}")
    return url, key


# ── Manifest loading ──────────────────────────────────────────────────────────

def load_manifest(path: str) -> Dict[str, Any]:
    if yaml is None:
        raise ImportError("PyYAML required: pip install pyyaml --break-system-packages")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Replay one or multiple attack scenario sources into XSIAM"
    )
    parser.add_argument(
        "--manifest", required=True,
        help="Path to scenario manifest YAML file"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be sent without actually sending"
    )
    parser.add_argument(
        "--compress-window", default=None,
        help="Override compress window from manifest (e.g. '2h', '30m')"
    )
    parser.add_argument(
        "--tenant-tz", default=None,
        metavar="HOURS",
        type=float,
        help=(
            "Tenant UTC offset in hours (e.g. -5 for EST, 1 for CET). "
            "Defaults to UTC (0). Events are anchored to tenant local time "
            "so the correlation rule sees them as 'now' regardless of timezone."
        )
    )
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    manifest_dir = os.path.dirname(os.path.abspath(args.manifest))

    # ── Load manifest ──
    manifest = load_manifest(args.manifest)
    scenario_name = manifest.get("scenario", "Unknown Scenario")
    sources_cfg = manifest.get("sources", [])

    compress_str = args.compress_window or manifest.get("compress_window")
    compress_window: Optional[timedelta] = parse_duration(compress_str) if compress_str else None

    print(f"\n{'='*60}")
    print(f"  Scenario : {scenario_name}")
    print(f"  Sources  : {len(sources_cfg)}")
    print(f"  Window   : {compress_str or 'preserve original gaps'}")
    print(f"  Mode     : {'DRY RUN' if args.dry_run else 'LIVE SEND'}")
    print(f"{'='*60}\n")

    tenant_tz_offset = args.tenant_tz if args.tenant_tz is not None else 0.0
    tenant_tz = timezone(timedelta(hours=tenant_tz_offset))
    anchor = datetime.now(tenant_tz)
    if tenant_tz_offset != 0:
        print(f"[*] Tenant timezone: UTC{tenant_tz_offset:+.1f}")
    print(f"[*] Anchor (latest event → now): {anchor.isoformat()}\n")

    # ── Load all sources ──
    sources = []
    global_min: Optional[datetime] = None
    global_max: Optional[datetime] = None

    for cfg in sources_cfg:
        name = cfg.get("name", "unnamed")
        raw_path = cfg.get("file", "")
        env_str = cfg.get("env", "")

        # Resolve file path relative to manifest location
        file_path = raw_path if os.path.isabs(raw_path) else os.path.join(manifest_dir, raw_path)
        if not os.path.exists(file_path):
            # Try relative to cwd as fallback
            file_path = os.path.join(os.getcwd(), raw_path)

        print(f"[*] Loading source: {name}")
        print(f"    File: {file_path}")

        events = load_events(file_path)
        print(f"    Events loaded: {len(events)}")
        events = normalize_events(events, cfg)

        time_field = cfg.get("time_field") or detect_time_field(events)
        if not time_field:
            print(f"  [!] WARNING: Could not detect timestamp field for {name} — skipping rebase")
            time_field = "_time"
        else:
            print(f"    Time field: {time_field} (auto-detected)" if not cfg.get("time_field") else f"    Time field: {time_field}")

        s_min, s_max = time_range(events, time_field)
        if s_min and s_max:
            print(f"    Time range: {s_min.strftime('%Y-%m-%d %H:%M')} → {s_max.strftime('%Y-%m-%d %H:%M')} UTC")
            if global_min is None or s_min < global_min:
                global_min = s_min
            if global_max is None or s_max > global_max:
                global_max = s_max

        env_path = resolve_env_path(env_str, script_dir)

        # Tag events with source metadata
        for ev in events:
            ev.setdefault("scenario_name", scenario_name)
            ev.setdefault("scenario_source", name)

        sources.append({
            "name": name,
            "events": events,
            "time_field": time_field,
            "env_path": env_path,
            "env_str": env_str,
        })
        print()

    if global_min and global_max:
        print(f"[*] Global time range: {global_min.strftime('%Y-%m-%d %H:%M')} → {global_max.strftime('%Y-%m-%d %H:%M')} UTC")

    # ── Rebase all sources against shared anchor and time range ──
    print()
    for src in sources:
        n = rebase(
            src["events"],
            src["time_field"],
            anchor,
            compress_window,
            global_min=global_min,
            global_max=global_max,
        )
        print(f"[*] {src['name']}: rebased {n}/{len(src['events'])} events")

    # ── Send each source to its own endpoint ──
    print()
    for src in sources:
        name = src["name"]
        events = src["events"]
        env_path = src["env_path"]

        if args.dry_run:
            print(f"[DRY RUN] {name}: would send {len(events)} events")
            print(f"          Env: {env_path}")
            if events:
                sample = {k: v for k, v in list(events[0].items())[:8]}
                print(f"          Sample: {json.dumps(sample, ensure_ascii=False)}")
            print()
            continue

        try:
            url, key = load_env_file(env_path)
        except (ValueError, FileNotFoundError) as e:
            print(f"[!] {name}: env load failed — {e}")
            print(f"    Skipping send for this source.\n")
            continue

        print(f"[*] {name}: sending {len(events)} events → {url}")
        send_test_events.send_events(events, api_url=url, api_key=key)
        print()

    print("[*] Replay complete.")


if __name__ == "__main__":
    main()
