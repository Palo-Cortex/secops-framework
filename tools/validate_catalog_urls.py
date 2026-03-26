#!/usr/bin/env python3
"""
validate_catalog_urls.py

Validates that every pack in pack_catalog.json has:
  1. A reachable xsoar_config.json URL (HTTP 200 + valid JSON)
  2. Every custom_packs[].url in that config resolves to a real
     GitHub Release asset (HTTP 200 or 302)

Behavior:
  --skip-packs PACK1,PACK2   Skip URL checks for these pack IDs.
                              Use for packs being bumped in the current PR
                              whose release does not exist yet.

  --warn-only                 Print failures as warnings, always exit 0.
                              Used in PR gate for cross-pack staleness —
                              the fix requires a separate PR so blocking
                              the current one is wrong.

  (default)                   Hard fail on any error. Used in release job
                              to confirm the release asset just published
                              is actually reachable.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, List, Tuple
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

CATALOG_PATH = Path("pack_catalog.json")
TIMEOUT = 20


def _head(url: str) -> Tuple[int, str]:
    try:
        req = Request(url, method="HEAD")
        with urlopen(req, timeout=TIMEOUT) as r:
            return r.status, ""
    except HTTPError as e:
        return e.code, str(e)
    except URLError as e:
        return 0, str(e)
    except Exception as e:
        return 0, str(e)


def _get_json(url: str) -> Tuple[Any, str]:
    try:
        req = Request(url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=TIMEOUT) as r:
            raw = r.read().decode("utf-8")
        return json.loads(raw), ""
    except HTTPError as e:
        return None, f"HTTP {e.code}: {e}"
    except URLError as e:
        return None, f"URLError: {e}"
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e}"
    except Exception as e:
        return None, str(e)


def validate_catalog(catalog_path: Path, skip_packs: List[str], warn_only: bool) -> int:
    errors: List[str] = []
    warnings: List[str] = []

    def record(msg: str):
        if warn_only:
            warnings.append(msg)
        else:
            errors.append(msg)

    if not catalog_path.exists():
        print(f"FATAL: {catalog_path} not found", file=sys.stderr)
        return 1

    try:
        catalog = json.loads(catalog_path.read_text())
    except json.JSONDecodeError as e:
        print(f"FATAL: {catalog_path} is not valid JSON: {e}", file=sys.stderr)
        return 1

    packs = catalog.get("packs") or []
    if not packs:
        print("FATAL: pack_catalog.json has no 'packs' list", file=sys.stderr)
        return 1

    skip_set = set(skip_packs)
    if skip_set:
        print(f"Skipping URL checks for bumped packs: {sorted(skip_set)}")

    print(f"Checking {len(packs)} pack(s) "
          f"({'warn-only' if warn_only else 'hard-fail'} mode)...\n")

    for pack in packs:
        pack_id = pack.get("id", "(unknown)")
        version = pack.get("version", "")
        cfg_url = pack.get("xsoar_config") or pack.get("xsoar_config_url") or ""

        if pack_id in skip_set:
            print(f"  [{pack_id}] SKIPPED (version bumped in this PR)")
            continue

        if not cfg_url:
            record(f"[{pack_id}] missing xsoar_config URL in pack_catalog.json")
            continue

        print(f"  [{pack_id} v{version}] checking xsoar_config...")
        cfg_data, err = _get_json(cfg_url)
        if err:
            record(f"[{pack_id}] xsoar_config unreachable or invalid: {err}\n  → {cfg_url}")
            continue

        if not isinstance(cfg_data, dict):
            record(f"[{pack_id}] xsoar_config is not a JSON object → {cfg_url}")
            continue

        custom_packs = cfg_data.get("custom_packs") or []
        if not isinstance(custom_packs, list):
            record(f"[{pack_id}] xsoar_config custom_packs is not a list → {cfg_url}")
            continue

        for entry in custom_packs:
            if not isinstance(entry, dict):
                continue
            zip_url = (entry.get("url") or "").strip()
            zip_id  = (entry.get("id") or zip_url).strip()

            if not zip_url:
                record(f"[{pack_id}] custom_packs entry '{zip_id}' has no url")
                continue

            parsed = urlparse(zip_url)
            if parsed.scheme not in ("https", "http"):
                record(f"[{pack_id}] custom_packs '{zip_id}' url not http(s): {zip_url}")
                continue

            print(f"    [{zip_id}] HEAD {zip_url}")
            status, err = _head(zip_url)

            if status in (200, 302):
                print(f"    [{zip_id}] OK ({status})")
            elif status == 404:
                record(
                    f"[{pack_id}] '{zip_id}' release asset not found (404)\n"
                    f"  → {zip_url}\n"
                    f"  Fix: bump version + merge, or correct the URL."
                )
            elif status == 0:
                record(f"[{pack_id}] '{zip_id}' unreachable: {err}\n  → {zip_url}")
            else:
                record(f"[{pack_id}] '{zip_id}' HTTP {status}\n  → {zip_url}")

    print()
    if warnings:
        print("─" * 60)
        print(f"WARNING: {len(warnings)} stale catalog URL(s) found.")
        print("These require a separate PR to fix. Current PR is NOT blocked.\n")
        for i, w in enumerate(warnings, 1):
            print(f"  {i}. {w}\n")
        print("─" * 60)
        return 0

    if errors:
        print("─" * 60)
        print(f"FAILED: {len(errors)} catalog URL error(s):\n")
        for i, e in enumerate(errors, 1):
            print(f"  {i}. {e}\n")
        print("─" * 60)
        return 1

    print("OK: All catalog URLs and release assets are valid.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", default=str(CATALOG_PATH))
    parser.add_argument("--skip-packs", default="",
                        help="Comma-separated pack IDs to skip.")
    parser.add_argument("--warn-only", action="store_true",
                        help="Warn instead of fail. Used in PR gate.")
    args = parser.parse_args()
    skip_packs = [p.strip() for p in args.skip_packs.split(",") if p.strip()]
    sys.exit(validate_catalog(Path(args.catalog), skip_packs, args.warn_only))


if __name__ == "__main__":
    main()
