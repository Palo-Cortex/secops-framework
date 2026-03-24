#!/usr/bin/env python3
"""
validate_xsoar_configs.py — CI gate for xsoar_config.json in every pack

Rules enforced:
  1. Every pack directory that contains an xsoar_config.json must be valid JSON.
  2. Optionally scope to a comma-separated list of pack names via --packs.
     When --packs is omitted, ALL packs under PACKS_DIR are checked.

Exit 0 on success, 1 if any file fails to parse.

Usage:
  # All packs
  python tools/validate_xsoar_configs.py

  # Specific packs (CI: pass changed packs from detect job)
  python tools/validate_xsoar_configs.py --packs soc-optimization-unified,soc-framework-nist-ir
"""

import argparse
import json
import os
import sys
from pathlib import Path

PACKS_DIR = Path(os.environ.get("PACKS_DIR", "Packs"))


import re

_VERSIONED_ID_RE = re.compile(r"-v\d+\.\d+", re.IGNORECASE)


def validate_file(path: Path) -> str | None:
    """
    Return an error string, or None if the file is valid JSON and structurally
    correct.

    Structural rules enforced:
      • custom_packs[*].id must be a bare pack name — no version suffix, no .zip.
        The id is XSIAM's upgrade-in-place key.  A versioned id causes a new pack
        to be installed on every release instead of upgrading the existing one.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return str(exc)
    except OSError as exc:
        return f"cannot read file — {exc}"

    # Structural: custom_packs id must be bare pack name
    for i, entry in enumerate(data.get("custom_packs", [])):
        pack_id = entry.get("id", "")
        if _VERSIONED_ID_RE.search(pack_id):
            return (
                f"custom_packs[{i}].id '{pack_id}' contains a version suffix. "
                f"The id must be the bare pack name with .zip (e.g. 'SocFrameworkCrowdstrikeFalcon.zip'). "
                f"Version belongs only in the url field."
            )

    return None


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
                # Warn but do not fail — pack may have been deleted
                print(f"WARN: pack directory '{p}' not found, skipping.")
        return dirs

    return [p for p in sorted(PACKS_DIR.iterdir()) if p.is_dir()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate xsoar_config.json files.")
    parser.add_argument(
        "--packs",
        default="",
        help="Comma-separated list of pack names to check (default: all).",
    )
    args = parser.parse_args()

    packs_filter = [p.strip() for p in args.packs.split(",") if p.strip()] or None
    pack_dirs = collect_pack_dirs(packs_filter)

    if not pack_dirs:
        print("No pack directories found — nothing to validate.")
        return 0

    checked = 0
    errors: list[tuple[Path, str]] = []

    for pack_dir in pack_dirs:
        config_path = pack_dir / "xsoar_config.json"
        if not config_path.exists():
            # Not every pack is required to have one; skip silently.
            continue

        err = validate_file(config_path)
        checked += 1
        if err:
            errors.append((config_path, err))
            print(f"FAIL  {config_path}: {err}")
        else:
            print(f"OK    {config_path}")

    if checked == 0:
        print("No xsoar_config.json files found — nothing to validate.")
        return 0

    print(f"\n{checked} file(s) checked.")

    if errors:
        print(f"\nFAIL  {len(errors)} invalid xsoar_config.json file(s):")
        for path, msg in errors:
            print(f"  {path}: {msg}")
        return 1

    print("PASS  all xsoar_config.json files are valid JSON.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
