#!/usr/bin/env python3
"""Pack metadata and catalog integrity checks.

This file existed but was empty, so the PR gate's "Validate pack_catalog.json"
step passed trivially on every PR since it was added. The checks below are the
ones that would have caught defects that reached a tenant instead.

THE ID MISMATCH (why this file now exists)
------------------------------------------
``pack_metadata.json`` carries an ``id`` field, and CI copies that file to
``metadata.json`` inside the release zip. The platform's pack upload endpoint
installs the pack under the id it finds THERE, not under the directory name.

When the two disagree the upload still returns HTTP 200 and appears to succeed,
but the pack installs under the metadata id -- a phantom duplicate -- while the
real pack id keeps serving its old content. The tenant reports the old version,
``updateAvailable`` stays False, and reinstalling changes nothing.

Confirmed on deathstar 19 Sep 2026: SocFrameworkMicrosoftDefender declared
``id: soc-microsoft-defender``. Uploading its 1.2.16 zip returned 200 while the
tenant stayed at 1.2.13; the pack had installed as ``soc-microsoft-defender``.
Correcting the id to the directory name and re-uploading the same zip installed
it correctly first try. Five packs carried this mismatch.

Nothing else catches it: demisto-sdk validate does not compare id to the
directory, and the SDK upload path derives the id from the directory, so the
mismatch is invisible until a direct upload silently does the wrong thing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PACKS_DIR = Path("Packs")
CATALOG = Path("pack_catalog.json")


def check_pack_metadata_ids() -> list[str]:
    """``pack_metadata.json`` id must equal the pack directory name."""
    errors: list[str] = []
    for meta_path in sorted(PACKS_DIR.glob("*/pack_metadata.json")):
        pack_dir = meta_path.parent.name
        try:
            meta = json.loads(meta_path.read_text())
        except Exception as exc:
            errors.append(f"{meta_path}: unreadable ({exc})")
            continue

        pack_id = meta.get("id")
        if pack_id is None:
            # Absent is safe: the platform falls back to the directory name.
            continue
        if pack_id != pack_dir:
            errors.append(
                f"{meta_path}: id is {pack_id!r} but the pack directory is "
                f"{pack_dir!r}. A direct pack upload installs under the id from "
                f"metadata.json, so this installs a phantom duplicate as "
                f"{pack_id!r} and leaves {pack_dir!r} on its old version while "
                f"returning HTTP 200. Set id to {pack_dir!r}."
            )
    return errors


def check_pack_metadata_version_key() -> list[str]:
    """A string ``version`` alongside ``currentVersion`` breaks the upload.

    metadata.json is unmarshalled into a struct whose CommonFields.version is an
    int64, so a string there fails the upload with a 400 naming the field.
    Packs that install cleanly carry currentVersion only.
    """
    errors: list[str] = []
    for meta_path in sorted(PACKS_DIR.glob("*/pack_metadata.json")):
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            continue  # reported by the id check
        if isinstance(meta.get("version"), str):
            errors.append(
                f"{meta_path}: stray string \"version\": {meta['version']!r}. "
                f"CI copies this file to metadata.json, where the platform "
                f"parses version as an int64, so the upload fails with "
                f"400 'cannot unmarshal string ... of type int64'. "
                f"Remove the key; keep currentVersion."
            )
    return errors


def check_catalog() -> list[str]:
    """Every catalog entry points at a real pack, and versions agree."""
    errors: list[str] = []
    if not CATALOG.exists():
        return [f"{CATALOG}: missing"]
    try:
        catalog = json.loads(CATALOG.read_text())
    except Exception as exc:
        return [f"{CATALOG}: invalid JSON ({exc})"]

    entries = catalog.get("packs", catalog if isinstance(catalog, list) else [])
    seen: set[str] = set()
    for entry in entries:
        pid = entry.get("id")
        if not pid:
            errors.append(f"{CATALOG}: entry with no id: {entry!r}")
            continue
        if pid in seen:
            errors.append(f"{CATALOG}: duplicate entry for {pid!r}")
        seen.add(pid)

        meta_path = PACKS_DIR / pid / "pack_metadata.json"
        if not meta_path.exists():
            errors.append(
                f"{CATALOG}: {pid!r} has no Packs/{pid}/pack_metadata.json. "
                f"The catalog id must be the pack directory name."
            )
            continue

        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            continue
        cat_v, meta_v = entry.get("version"), meta.get("currentVersion")
        if cat_v and meta_v and cat_v != meta_v:
            errors.append(
                f"{CATALOG}: {pid!r} version {cat_v} does not match "
                f"pack_metadata currentVersion {meta_v}."
            )
    return errors


def main() -> int:
    checks = (
        ("pack_metadata id matches directory", check_pack_metadata_ids),
        ("no stray string version key", check_pack_metadata_version_key),
        ("pack_catalog integrity", check_catalog),
    )

    total = 0
    for label, fn in checks:
        errors = fn()
        if errors:
            total += len(errors)
            print(f"\n  ✗ {label} — {len(errors)} problem(s):")
            for e in errors:
                print(f"      {e}")
        else:
            print(f"  ✓ {label}")

    if total:
        print(f"\n  FAILED — {total} problem(s)\n")
        return 1
    print("\n  PASSED\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
