#!/usr/bin/env python3
"""
check_dependency_versions.py — Verify cross-pack dependency versions in xsoar_config.json

For every custom_packs entry that references a different pack (a dependency, not the
pack itself), compare the pinned version in the entry against the current version in
that pack's pack_metadata.json.

When a mismatch is found:
  • Interactive (TTY):  prompt to auto-fix the id/url in-place
  • Non-interactive:    print a warning (default) or exit 1 (--strict)
  • --fix flag:         apply all updates non-interactively (no prompts)

Self-entries (where the entry pack name == the containing pack) are SKIPPED — those
are already enforced by preflight_xsoar_config.py.

Dependency entries whose id format is not parseable (e.g. legacy bare .zip names
without a version) are reported as SKIP warnings but do not cause failures.

Usage:
  # All packs
  python3 tools/check_dependency_versions.py

  # Specific packs (comma-separated)
  python3 tools/check_dependency_versions.py --packs soc-optimization-unified,SocFrameworkProofPointTap

  # Auto-fix stale entries
  python3 tools/check_dependency_versions.py --fix

  # CI hard-fail mode (warn becomes error)
  python3 tools/check_dependency_versions.py --strict

  # Combine: fix only specific packs
  python3 tools/check_dependency_versions.py --packs soc-optimization-unified --fix

Exit codes:
  0  All dependency versions match (or no cross-pack dependencies found)
  1  Stale versions found and --strict is set, or fix was requested but write failed
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

GITHUB_REPO = "Palo-Cortex/secops-framework"
PACKS_DIR = Path(os.environ.get("PACKS_DIR", "Packs"))


# ── Helpers ──────────────────────────────────────────────────────────────────

def parse_entry_id(entry_id: str) -> Optional[tuple[str, str]]:
    """
    Extract (pack_name, version) from a custom_packs id field.

    Expected format: {pack_name}-v{version}.zip
    e.g. 'soc-framework-nist-ir-v1.1.0.zip' → ('soc-framework-nist-ir', '1.1.0')

    Uses rfind('-v') so hyphenated names work regardless of depth.
    Returns None if the format is unrecognisable (e.g. bare 'pack-name.zip').
    """
    stem = entry_id.removesuffix(".zip")
    idx = stem.rfind("-v")
    if idx == -1:
        return None
    pack_name = stem[:idx]
    version = stem[idx + 2:]
    if not pack_name or not re.fullmatch(r"\d+\.\d+[\.\d]*", version):
        return None
    return pack_name, version


def build_version_index(packs_root: Path) -> dict[str, str]:
    """
    Walk all pack directories under packs_root and return a mapping of
    pack_name → current_version from pack_metadata.json.
    """
    index: dict[str, str] = {}
    if not packs_root.is_dir():
        return index
    for meta_path in packs_root.rglob("pack_metadata.json"):
        pack_name = meta_path.parent.name
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            version = data.get("version") or data.get("currentVersion") or ""
            if version:
                index[pack_name] = str(version)
        except (json.JSONDecodeError, OSError):
            pass
    return index


def build_updated_url(pack_name: str, version: str) -> str:
    """Build the canonical GitHub release download URL for a pack at a given version."""
    tag = f"{pack_name}-v{version}"
    asset = f"{tag}.zip"
    return f"https://github.com/{GITHUB_REPO}/releases/download/{tag}/{asset}"


def build_updated_id(pack_name: str, version: str) -> str:
    return f"{pack_name}-v{version}.zip"


# ── Per-pack check ────────────────────────────────────────────────────────────

class Finding:
    """Represents one stale dependency entry found in a pack's xsoar_config.json."""

    def __init__(self, config_path: Path, entry_index: int, entry_id: str,
                 dep_pack: str, pinned: str, actual: str):
        self.config_path = config_path
        self.entry_index = entry_index   # index into custom_packs list
        self.entry_id = entry_id
        self.dep_pack = dep_pack
        self.pinned = pinned
        self.actual = actual

    def __str__(self) -> str:
        return (
            f"  STALE  {self.config_path}\n"
            f"         dependency '{self.dep_pack}': "
            f"pinned=v{self.pinned}  →  actual=v{self.actual}"
        )


def check_pack(pack_dir: Path, version_index: dict[str, str]) -> list[Finding]:
    """
    Check one pack's xsoar_config.json for stale cross-pack dependency versions.
    Returns a list of Findings (empty = all OK).
    """
    findings: list[Finding] = []
    config_path = pack_dir / "xsoar_config.json"
    if not config_path.exists():
        return findings

    primary_pack = pack_dir.name

    try:
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  WARN  cannot read {config_path}: {exc}")
        return findings

    for idx, entry in enumerate(cfg.get("custom_packs", [])):
        entry_id = entry.get("id", "")
        parsed = parse_entry_id(entry_id)

        if parsed is None:
            # Unrecognisable format — can't check, skip silently unless verbose
            print(f"  SKIP  {config_path.relative_to(PACKS_DIR.parent)}")
            print(f"        entry '{entry_id}' — id format not parseable (no version), skipping")
            continue

        dep_pack, pinned_version = parsed

        if dep_pack == primary_pack:
            # Self-entry — handled by preflight_xsoar_config.py, not our job
            continue

        actual_version = version_index.get(dep_pack)
        if actual_version is None:
            # Dependency pack not present locally — can't compare, skip
            print(f"  SKIP  {config_path.relative_to(PACKS_DIR.parent)}")
            print(f"        dependency '{dep_pack}' not found in {PACKS_DIR} — cannot compare")
            continue

        if actual_version != pinned_version:
            findings.append(Finding(
                config_path=config_path,
                entry_index=idx,
                entry_id=entry_id,
                dep_pack=dep_pack,
                pinned=pinned_version,
                actual=actual_version,
            ))
        else:
            print(f"  OK    {config_path.relative_to(PACKS_DIR.parent)}")
            print(f"        dependency '{dep_pack}' @ v{pinned_version} ✓")

    return findings


# ── Fix ───────────────────────────────────────────────────────────────────────

def apply_fix(finding: Finding) -> bool:
    """
    Update the id and url fields in the xsoar_config.json entry to reflect the
    actual current version. Returns True on success, False on error.
    """
    try:
        cfg = json.loads(finding.config_path.read_text(encoding="utf-8"))
        entry = cfg["custom_packs"][finding.entry_index]

        new_id = build_updated_id(finding.dep_pack, finding.actual)
        new_url = build_updated_url(finding.dep_pack, finding.actual)

        old_id = entry.get("id", "")
        old_url = entry.get("url", "")

        entry["id"] = new_id
        entry["url"] = new_url

        finding.config_path.write_text(
            json.dumps(cfg, indent=2) + "\n", encoding="utf-8"
        )
        print(f"  FIXED {finding.config_path.relative_to(PACKS_DIR.parent)}")
        print(f"        id:  {old_id}")
        print(f"          →  {new_id}")
        print(f"        url: {old_url}")
        print(f"          →  {new_url}")
        return True

    except (KeyError, IndexError, OSError, json.JSONDecodeError) as exc:
        print(f"  ERROR  failed to fix {finding.config_path}: {exc}")
        return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check cross-pack dependency versions in xsoar_config.json files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--packs",
        default="",
        help="Comma-separated pack names to check (default: all packs under Packs/).",
    )
    parser.add_argument(
        "--packs-dir",
        default=str(PACKS_DIR),
        help=f"Root packs directory (default: {PACKS_DIR}).",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Automatically update stale dependency versions in xsoar_config.json. "
             "No prompts — applies all fixes. Use interactively without --fix to be prompted.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any stale dependency versions are found (default: warn only).",
    )
    args = parser.parse_args()

    packs_root = Path(args.packs_dir)
    if not packs_root.is_dir():
        print(f"ERROR: packs directory '{packs_root}' not found.")
        return 1

    # Resolve pack directories to check
    pack_names = [p.strip() for p in args.packs.split(",") if p.strip()]
    if pack_names:
        pack_dirs = []
        for name in pack_names:
            p = packs_root / name
            if p.is_dir():
                pack_dirs.append(p)
            else:
                print(f"WARN: pack '{name}' not found in {packs_root}, skipping.")
    else:
        pack_dirs = sorted(p for p in packs_root.iterdir() if p.is_dir())

    if not pack_dirs:
        print("No pack directories to check.")
        return 0

    # Build the version index once — map every known pack → its current version
    version_index = build_version_index(packs_root)
    if not version_index:
        print(f"WARN: No pack_metadata.json files found under {packs_root}. "
              "Cannot perform dependency version checks.")
        return 0

    # Collect findings across all packs
    all_findings: list[Finding] = []
    is_interactive = sys.stdin.isatty() and sys.stdout.isatty()

    for pack_dir in pack_dirs:
        findings = check_pack(pack_dir, version_index)
        all_findings.extend(findings)

    if not all_findings:
        print("\nAll cross-pack dependency versions are current.")
        return 0

    # Report findings
    print(f"\n{'─' * 60}")
    print(f"Found {len(all_findings)} stale dependency version(s):\n")
    for f in all_findings:
        print(str(f))
    print(f"{'─' * 60}\n")

    # Decide what to do: --fix → apply all; interactive TTY → prompt; else warn/fail
    if args.fix:
        print("Applying fixes (--fix)...")
        fix_errors = 0
        for f in all_findings:
            if not apply_fix(f):
                fix_errors += 1
        if fix_errors:
            print(f"\n{fix_errors} fix(es) failed.")
            return 1
        print("\nAll stale entries updated.")
        return 0

    if is_interactive and not args.strict:
        # Prompt for each finding
        fix_errors = 0
        for f in all_findings:
            prompt = (
                f"\nUpdate '{f.dep_pack}' from v{f.pinned} → v{f.actual} "
                f"in {f.config_path.relative_to(packs_root.parent)}? [y/N] "
            )
            answer = input(prompt).strip().lower()
            if answer in ("y", "yes"):
                if not apply_fix(f):
                    fix_errors += 1
            else:
                print(f"  Skipped '{f.dep_pack}'.")
        if fix_errors:
            return 1
        return 0

    # Non-interactive / --strict
    if args.strict:
        print(
            "FAIL: stale dependency versions found. "
            "Run with --fix to update, or update xsoar_config.json manually.\n"
            "Re-run without --strict to treat this as a warning."
        )
        return 1

    # Default: warn only
    print(
        "WARN: stale dependency versions found (non-blocking).\n"
        "Run with --fix to update automatically, or update xsoar_config.json manually."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
