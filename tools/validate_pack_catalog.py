#!/usr/bin/env python3
"""
validate_pack_catalog.py — CI gate for pack_catalog.json

Rules enforced:
  1. File is valid JSON.
  2. Top-level structure is {"packs": [...]}.
  3. Every pack entry contains all required fields.
  4. No required field value is null or empty string.
  5. Extra/unknown fields are silently allowed (additive-safe).

Required fields (from canonical schema):
  id, display_name, category, version, path, visible, xsoar_config

Exit 0 on success, 1 on any failure.
"""

import json
import sys
from pathlib import Path

CATALOG_PATH = Path("pack_catalog.json")

REQUIRED_FIELDS = [
    "id",
    "display_name",
    "category",
    "version",
    "path",
    "visible",
    "xsoar_config",
]

# Fields where an empty string is NOT acceptable (bool/str must be non-empty)
NON_EMPTY_FIELDS = {"id", "display_name", "category", "version", "path", "xsoar_config"}


def main() -> int:
    if not CATALOG_PATH.exists():
        print(f"ERROR: {CATALOG_PATH} not found.")
        return 1

    # ── Rule 1: valid JSON ───────────────────────────────────────────────────
    try:
        data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR: {CATALOG_PATH} is not valid JSON — {exc}")
        return 1

    print(f"OK  JSON is valid ({CATALOG_PATH})")

    # ── Rule 2: top-level shape ──────────────────────────────────────────────
    if not isinstance(data, dict) or "packs" not in data:
        print('ERROR: top-level structure must be {"packs": [...]}')
        return 1

    packs = data["packs"]
    if not isinstance(packs, list):
        print('ERROR: "packs" must be a JSON array.')
        return 1

    print(f"OK  packs array present ({len(packs)} entries)")

    # ── Rules 3 & 4: per-entry field checks ─────────────────────────────────
    errors: list[str] = []

    for idx, entry in enumerate(packs):
        if not isinstance(entry, dict):
            errors.append(f"  pack[{idx}]: entry is not an object")
            continue

        pack_id = entry.get("id", f"<index {idx}>")
        prefix = f"  pack '{pack_id}'"

        for field in REQUIRED_FIELDS:
            if field not in entry:
                errors.append(f"{prefix}: missing required field '{field}'")
                continue

            value = entry[field]

            if value is None:
                errors.append(f"{prefix}: field '{field}' is null")
                continue

            if field in NON_EMPTY_FIELDS and isinstance(value, str) and value.strip() == "":
                errors.append(f"{prefix}: field '{field}' is empty string")

    if errors:
        print(f"\nFAIL  {len(errors)} error(s) found in {CATALOG_PATH}:")
        for e in errors:
            print(e)
        return 1

    print(f"OK  all {len(packs)} pack entries pass required-field checks")
    print("\nPASS  pack_catalog.json is valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
