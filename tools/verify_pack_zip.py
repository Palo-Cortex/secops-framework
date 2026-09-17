#!/usr/bin/env python3
"""
verify_pack_zip.py -- release gate: prove a built pack zip actually contains
the pack's content before it is published.

WHY THIS EXISTS
---------------
`demisto-sdk zip-packs` silently drops XSIAM-only content types. Verified on
SDK 1.39.3: CorrelationRules, ModelingRules and XSIAMDashboards are omitted
from the produced zip while XSOAR types (Playbooks, Scripts, Lists,
IncidentFields) survive. A rules-only vendor pack therefore builds a zip
containing nothing but pack_metadata.json, README.md and ReleaseNotes -- and
the release succeeds, green, with an uninstallable artifact.

That shipped soc-crowdstrike-falcon v2.0.0, soc-crowdstrike-idp v1.1.0 and
soc-crowdstrike-saas v1.1.0 as empty packs. Nothing in the pipeline noticed,
because nothing opened the zip.

This gate opens the zip.

USAGE
-----
    python3 tools/verify_pack_zip.py --pack-root Packs/<pack> --zip dist/<pack>-vX.Y.Z.zip

Exit 0 when every content file in the pack source is present in the zip.
Exit 1 with a per-file report otherwise.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

# Directories whose contents must reach the tenant. Anything added here is
# enforced for every pack that ships it.
CONTENT_DIRS = [
    "CorrelationRules",
    "ModelingRules",
    "XSIAMDashboards",
    "XSIAMReports",
    "Playbooks",
    "Scripts",
    "Integrations",
    "Lists",
    "Lookups",
    "IncidentFields",
    "IncidentTypes",
    "Layouts",
    "Classifiers",
    "Wizards",
    "Triggers",
    "Jobs",
]

# Files that legitimately never ship inside the pack zip.
IGNORED_NAMES = {".gitkeep", ".DS_Store", ".pack-ignore", ".secrets-ignore"}
IGNORED_SUFFIXES = {".pyc"}

# Repo-only files: deliberately excluded from Marketplace packs.
REPO_ONLY_NAMES = {"xsoar_config.json", "preflight_overrides.json"}


def source_content_files(pack_root: Path) -> list[Path]:
    """Every file under the pack's content dirs that is expected in the zip."""
    found: list[Path] = []
    for d in CONTENT_DIRS:
        base = pack_root / d
        if not base.is_dir():
            continue
        for f in sorted(base.rglob("*")):
            if not f.is_file():
                continue
            if f.name in IGNORED_NAMES or f.suffix in IGNORED_SUFFIXES:
                continue
            found.append(f.relative_to(pack_root))
    return found


def zip_members(zip_path: Path) -> set[str]:
    with zipfile.ZipFile(zip_path) as z:
        return {n for n in z.namelist() if not n.endswith("/")}


def present(member_set: set[str], rel: Path) -> bool:
    """
    Match tolerantly on path suffix.

    The zip may carry a top-level pack directory (`<pack>/CorrelationRules/x.yml`)
    or place content at the root (`CorrelationRules/x.yml`). The SDK also
    renames some items on prepare (e.g. `x.yml` ->
    `correlationrule-x.yml`, `external-modelingrule-x.yml`), so fall back to a
    basename match within the right content directory.
    """
    rel_posix = rel.as_posix()
    for m in member_set:
        if m == rel_posix or m.endswith("/" + rel_posix):
            return True
    top = rel.parts[0]
    stem = rel.name
    for m in member_set:
        parts = m.split("/")
        if top in parts and (parts[-1] == stem or parts[-1].endswith(stem)):
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify a built pack zip contains the pack's content")
    ap.add_argument("--pack-root", required=True, help="Path to Packs/<pack>")
    ap.add_argument("--zip", required=True, dest="zip_path", help="Path to the built zip")
    ap.add_argument("--quiet", action="store_true", help="Only print on failure")
    args = ap.parse_args()

    pack_root = Path(args.pack_root)
    zip_path = Path(args.zip_path)

    if not pack_root.is_dir():
        print(f"FAIL  pack root not found: {pack_root}")
        return 1
    if not zip_path.is_file():
        print(f"FAIL  zip not found: {zip_path}")
        return 1

    pack = pack_root.name
    expected = source_content_files(pack_root)
    members = zip_members(zip_path)

    print(f"\n=== verify_pack_zip: {pack} ===")
    print(f"  zip          : {zip_path}  ({zip_path.stat().st_size} bytes, {len(members)} files)")
    print(f"  content files expected from source: {len(expected)}")

    if not expected:
        print(f"  NOTE  pack ships no content directories -- nothing to verify.")
        return 0

    missing = [rel for rel in expected if not present(members, rel)]

    by_dir: dict[str, list[str]] = {}
    for rel in expected:
        by_dir.setdefault(rel.parts[0], []).append(rel.as_posix())
    for d in sorted(by_dir):
        miss_in_d = [r for r in missing if r.parts[0] == d]
        mark = "MISSING" if miss_in_d else "ok"
        print(f"    {d:<20} {len(by_dir[d]) - len(miss_in_d)}/{len(by_dir[d])}  {mark}")

    problems: list[str] = []

    # --- metadata.json: Marketplace reads the pack version from this file ---
    # It is generated at build time by copying pack_metadata.json; it is not in
    # the repo. Absent metadata.json == no version reported in Marketplace.
    meta_member = next(
        (m for m in members if m == "metadata.json" or m.endswith("/metadata.json")), None
    )
    src_meta = pack_root / "pack_metadata.json"
    if meta_member is None:
        problems.append(
            "metadata.json missing from the zip -- Marketplace reads the pack "
            "version from it. The release job must copy pack_metadata.json to "
            "metadata.json at the pack root before zipping (see #1072)."
        )
    elif src_meta.is_file():
        import json as _json
        with zipfile.ZipFile(zip_path) as z:
            try:
                zipped_ver = _json.loads(z.read(meta_member)).get("currentVersion")
            except Exception:
                zipped_ver = None
        src_ver = _json.loads(src_meta.read_text()).get("currentVersion")
        if zipped_ver != src_ver:
            problems.append(
                f"metadata.json version mismatch: zip reports {zipped_ver!r}, "
                f"pack_metadata.json is {src_ver!r}. Marketplace would show the wrong version."
            )
        else:
            print(f"    {'metadata.json':<20} present, version {zipped_ver}  ok")

    # --- repo-only files must not ship inside the pack ---
    for repo_only in sorted(REPO_ONLY_NAMES):
        hit = next((m for m in members if m.split("/")[-1] == repo_only), None)
        if hit:
            problems.append(f"{repo_only} must not ship inside the pack zip (found at {hit}).")

    if problems:
        print(f"\n  FAIL  {len(problems)} packaging problem(s):")
        for p in problems:
            print(f"      - {p}")

    if missing:
        print(f"\n  FAIL  {len(missing)} content file(s) absent from the zip:")
        for rel in missing:
            print(f"      - {rel.as_posix()}")
        print(
            "\n  This is the demisto-sdk zip-packs XSIAM-drop failure mode.\n"
            "  A release built from this zip installs as an empty pack.\n"
            "  Build the zip with:  cd Packs && zip -r <out>/<pack>-v<ver>.zip <pack>\n"
        )

    if missing or problems:
        return 1

    if not args.quiet:
        print(f"\n  PASS  all {len(expected)} content file(s) present, "
              f"metadata.json correct, no repo-only files shipped.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
