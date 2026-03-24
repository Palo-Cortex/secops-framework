#!/usr/bin/env python3
"""
fix_xsoar_config_ids.py — one-shot migration

Finds every xsoar_config.json under Packs/ and corrects any custom_packs
entry whose 'id' contains a version segment.

The id field is XSIAM's stable upgrade-in-place key.  The correct format is
{PackName}.zip — no version segment.  A versioned id causes XSIAM to install
a parallel copy on every release instead of upgrading the existing one.
Version belongs only in the url field.

What it does:
  - Strips the '-v{N}.{N}.{N}' version segment, preserving the .zip suffix
    e.g. 'SocFrameworkCrowdstrikeFalcon-v1.0.46.zip' → 'SocFrameworkCrowdstrikeFalcon.zip'
  - Leaves the url field untouched
  - Dry-runs by default — use --fix to write changes

Usage:
  # Preview all changes without writing anything
  python3 tools/fix_xsoar_config_ids.py

  # Apply fixes
  python3 tools/fix_xsoar_config_ids.py --fix

  # Limit to specific packs
  python3 tools/fix_xsoar_config_ids.py --fix --packs SocFrameworkCrowdstrikeFalcon,soc-optimization-unified
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

PACKS_DIR = Path(os.environ.get("PACKS_DIR", "Packs"))

_VERSIONED_ID_RE = re.compile(r"-v\d+\.\d+[.\d]*(?=\.zip$)", re.IGNORECASE)


def bare_pack_id(raw_id: str) -> str:
    """Strip the version segment from an id, preserving the .zip suffix.

    'SocFrameworkCrowdstrikeFalcon-v1.0.46.zip' → 'SocFrameworkCrowdstrikeFalcon.zip'
    'SocFrameworkCrowdstrikeFalcon.zip'          → 'SocFrameworkCrowdstrikeFalcon.zip' (unchanged)
    """
    return _VERSIONED_ID_RE.sub("", raw_id)


def fix_config(path: Path, dry_run: bool) -> bool:
    """
    Inspect and optionally fix one xsoar_config.json.
    Returns True if changes were made (or would be made in dry-run).
    """
    try:
        text = path.read_text(encoding="utf-8")
        cfg = json.loads(text)
    except (OSError, json.JSONDecodeError) as e:
        print(f"  ERROR reading {path}: {e}")
        return False

    custom_packs = cfg.get("custom_packs")
    if not isinstance(custom_packs, list):
        return False

    changed = False
    for i, entry in enumerate(custom_packs):
        if not isinstance(entry, dict):
            continue
        raw_id = entry.get("id", "")
        if not raw_id:
            continue
        if not _VERSIONED_ID_RE.search(raw_id):
            continue  # already a bare name

        clean_id = bare_pack_id(raw_id)
        tag = "[DRY RUN] " if dry_run else ""
        print(f"  {tag}custom_packs[{i}].id: '{raw_id}'  →  '{clean_id}'")
        if not dry_run:
            entry["id"] = clean_id
        changed = True

    if changed and not dry_run:
        path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        print(f"  Wrote: {path}")

    return changed


def collect_pack_dirs(packs_filter: list[str] | None) -> list[Path]:
    if not PACKS_DIR.is_dir():
        print(f"ERROR: packs directory '{PACKS_DIR}' not found.")
        sys.exit(1)
    if packs_filter:
        dirs = []
        for name in packs_filter:
            p = PACKS_DIR / name
            if p.is_dir():
                dirs.append(p)
            else:
                print(f"WARN: pack '{p}' not found, skipping.")
        return dirs
    return [p for p in sorted(PACKS_DIR.iterdir()) if p.is_dir()]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Strip versioned ids from xsoar_config.json custom_packs entries."
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Write changes to disk.  Without this flag the script is a dry run.",
    )
    parser.add_argument(
        "--packs",
        default="",
        help="Comma-separated pack names to limit the scan (default: all).",
    )
    args = parser.parse_args()

    dry_run = not args.fix
    packs_filter = [p.strip() for p in args.packs.split(",") if p.strip()] or None
    pack_dirs = collect_pack_dirs(packs_filter)

    if dry_run:
        print("DRY RUN — no files will be modified.  Pass --fix to apply changes.\n")

    total_checked = 0
    total_fixed = 0

    for pack_dir in pack_dirs:
        config_path = pack_dir / "xsoar_config.json"
        if not config_path.exists():
            continue
        total_checked += 1
        print(f"{pack_dir.name}:")
        if fix_config(config_path, dry_run):
            total_fixed += 1
        else:
            print(f"  OK (no versioned ids found)")

    print()
    if total_checked == 0:
        print("No xsoar_config.json files found.")
        return 0

    if dry_run:
        if total_fixed:
            print(f"Would fix {total_fixed} of {total_checked} file(s).  Run with --fix to apply.")
            return 1  # non-zero so CI can catch pre-existing violations
        else:
            print(f"All {total_checked} file(s) are already clean.")
            return 0
    else:
        print(f"Fixed {total_fixed} of {total_checked} file(s).")
        return 0


if __name__ == "__main__":
    sys.exit(main())
