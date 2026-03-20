#!/usr/bin/env python3
"""
preflight_xsoar_config.py

Validates xsoar_config.json for one or more packs before deployment.

Checks:
  1. custom_packs[*].url  — Format validation only (release doesn't exist
                             yet pre-merge). Each entry's pack name and version
                             are derived from its own 'id' field, so dependency
                             entries (e.g. soc-framework-nist-ir inside
                             soc-optimization-unified) are validated correctly.
                             If the entry matches the primary pack, its version
                             is also cross-checked against pack_metadata.json.
  2. pre_config_docs[*].url  — HTTP check (file must exist on main)
  3. post_config_docs[*].url — HTTP check (file must exist on main)

Usage:
  python3 tools/preflight_xsoar_config.py Packs/SocFrameworkProofPointTap
  python3 tools/preflight_xsoar_config.py Packs/SocFrameworkProofPointTap Packs/SocFrameworkCrowdstrikeFalcon

  # From CI — comma-separated pack names (as output by detect job)
  python3 tools/preflight_xsoar_config.py --packs "SocFrameworkProofPointTap,soc-optimization-unified"
"""

import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Optional, Tuple

GITHUB_REPO = "Palo-Cortex/secops-framework"

# ── Helpers ───────────────────────────────────────────────────────────────────

def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"ERROR: File not found: {path}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"ERROR: Failed to parse JSON {path}: {e}")


def check_url(url: str, label: str) -> Tuple[bool, str]:
    """
    HTTP check — HEAD first, falls back to GET.
    Used for doc URLs which must already exist on main.
    """
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(
                url, method=method,
                headers={"User-Agent": "soc-framework-preflight/1.0"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status == 200:
                    return True, f"  ✓ {label}: {url}"
                return False, f"  ✗ {label}: HTTP {resp.status} — {url}"
        except urllib.error.HTTPError as e:
            if method == "HEAD" and e.code in (405, 403):
                continue
            return False, f"  ✗ {label}: HTTP {e.code} — {url}"
        except urllib.error.URLError as e:
            return False, f"  ✗ {label}: Connection error — {url} ({e.reason})"
        except Exception as e:
            return False, f"  ✗ {label}: {e} — {url}"
    return False, f"  ✗ {label}: Unreachable — {url}"


def parse_entry_id(entry_id: str) -> Optional[Tuple[str, str]]:
    """
    Derive pack name and version from a custom_packs entry 'id' field.

    Expected format: {pack_name}-v{version}.zip
    e.g. 'soc-framework-nist-ir-v1.1.0.zip' → ('soc-framework-nist-ir', '1.1.0')

    Uses rfind('-v') so hyphenated pack names (soc-framework-nist-ir) are
    handled correctly regardless of depth.

    Returns None if the format is unrecognisable.
    """
    stem = entry_id.removesuffix(".zip")   # soc-framework-nist-ir-v1.1.0
    idx = stem.rfind("-v")
    if idx == -1:
        return None
    pack_name = stem[:idx]                 # soc-framework-nist-ir
    version = stem[idx + 2:]              # 1.1.0
    # Version must look like semver (digits and dots only, e.g. 1.1.0)
    if not pack_name or not re.fullmatch(r"\d+\.\d+[\.\d]*", version):
        return None
    return pack_name, version


def validate_zip_url_format(
        url: str, pack_id: str, version: str, label: str
) -> Tuple[bool, str]:
    """
    Format-only validation for custom_packs zip URLs.

    The release zip doesn't exist yet at PR time — we can't HTTP check it.
    Instead verify the URL is structurally correct:
      - References the right repo
      - Pack name in URL matches pack_id
      - Version in URL matches version

    Expected format:
      https://github.com/{repo}/releases/download/{pack_id}-v{version}/{pack_id}-v{version}.zip
    """
    expected = (
        f"https://github.com/{GITHUB_REPO}/releases/download/"
        f"{pack_id}-v{version}/{pack_id}-v{version}.zip"
    )

    if url == expected:
        return True, f"  ✓ {label} format: {url}"

    # Diagnose what's wrong
    if GITHUB_REPO not in url:
        detail = f"wrong repo (expected {GITHUB_REPO})"
    elif f"{pack_id}-v{version}" not in url:
        if pack_id not in url:
            detail = f"pack name mismatch (expected '{pack_id}', got something else)"
        else:
            detail = f"version mismatch (expected v{version})"
    else:
        detail = f"expected:\n      {expected}"

    return False, (
        f"  ✗ {label} format error — {detail}\n"
        f"    was:  {url}\n"
        f"    want: {expected}"
    )


# ── Per-pack validation ───────────────────────────────────────────────────────

def validate_pack(pack_dir: Path, no_http: bool = False) -> List[str]:
    """
    Validate xsoar_config.json for a single pack.
    Returns a list of error strings. Empty = all checks passed.
    """
    config_path = pack_dir / "xsoar_config.json"
    errors = []

    if not config_path.exists():
        print(f"  (no xsoar_config.json — skipping)")
        return errors

    cfg = load_json(config_path)

    # Read version from pack_metadata.json — source of truth for the primary pack
    meta_path = pack_dir / "pack_metadata.json"
    if not meta_path.exists():
        errors.append(f"  ✗ pack_metadata.json not found in {pack_dir}")
        return errors

    meta = load_json(meta_path)
    primary_version = meta.get("version") or meta.get("currentVersion") or ""
    if not primary_version:
        errors.append(f"  ✗ No version found in pack_metadata.json")
        return errors

    pack_id = pack_dir.name

    # ── 1. custom_packs zip URLs — format check only ──────────────────────────
    # Each entry validates against its OWN pack name + version derived from
    # its 'id' field. Dependency packs (e.g. soc-framework-nist-ir listed
    # inside soc-optimization-unified) are therefore checked correctly.
    # If the entry is the primary pack, its version is also cross-checked
    # against pack_metadata.json.
    custom_packs = cfg.get("custom_packs", [])
    if custom_packs:
        print(f"  Checking custom_packs zip URL format (pack={pack_id}, version={primary_version})...")

    for entry in custom_packs:
        entry_id = entry.get("id", "")
        url = entry.get("url", "")

        if not url:
            errors.append(f"  ✗ custom_packs entry missing 'url': {entry_id or '?'}")
            continue

        # Derive the expected pack name + version from the entry's own id.
        parsed = parse_entry_id(entry_id) if entry_id else None

        if parsed:
            entry_pack, entry_version = parsed

            # If this entry is the primary pack, version must match pack_metadata.json
            if entry_pack == pack_id and entry_version != primary_version:
                errors.append(
                    f"  ✗ zip [{entry_id}] version mismatch — "
                    f"id says v{entry_version} but pack_metadata.json says v{primary_version}"
                )
                continue
        else:
            # Unrecognisable id — fall back to primary pack context and warn
            print(f"  ! zip [{entry_id or '?'}] id format unrecognisable — falling back to primary pack context")
            entry_pack, entry_version = pack_id, primary_version

        ok, msg = validate_zip_url_format(url, entry_pack, entry_version, f"zip [{entry_id or '?'}]")
        print(msg)
        if not ok:
            errors.append(msg)

    # ── 2. pre_config_docs URLs — HTTP check ──────────────────────────────────
    pre_docs = cfg.get("pre_config_docs", [])
    if pre_docs:
        if no_http:
            print("  Skipping pre_config_docs URL checks (--no-http).")
        else:
            print("  Checking pre_config_docs URLs...")
    if not no_http:
        for entry in pre_docs:
            url = entry.get("url", "")
            if not url:
                continue
            ok, msg = check_url(url, f"pre_doc [{entry.get('name', '?')}]")
            print(msg)
            if not ok:
                errors.append(msg)

    # ── 3. post_config_docs URLs — HTTP check ─────────────────────────────────
    post_docs = cfg.get("post_config_docs", [])
    if post_docs:
        if no_http:
            print("  Skipping post_config_docs URL checks (--no-http).")
        else:
            print("  Checking post_config_docs URLs...")
    if not no_http:
        for entry in post_docs:
            url = entry.get("url", "")
            if not url:
                continue
            ok, msg = check_url(url, f"post_doc [{entry.get('name', '?')}]")
            print(msg)
            if not ok:
                errors.append(msg)

    return errors


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Preflight validation for xsoar_config.json before deployment."
    )
    parser.add_argument(
        "pack_paths",
        nargs="*",
        help="Pack directory paths (e.g. Packs/SocFrameworkProofPointTap)",
    )
    parser.add_argument(
        "--packs",
        help="Comma-separated pack names relative to Packs/ (for CI use)",
    )
    parser.add_argument(
        "--packs-dir",
        default="Packs",
        help="Root packs directory (default: Packs)",
    )
    parser.add_argument(
        "--no-http",
        action="store_true",
        help="Skip live HTTP checks for doc URLs. Only zip URL format is validated. "
             "Use locally to avoid network latency; CI always runs full checks.",
    )

    args = parser.parse_args()

    # Collect pack directories
    pack_dirs: List[Path] = []

    for p in args.pack_paths:
        pack_dirs.append(Path(p))

    if args.packs:
        packs_root = Path(args.packs_dir)
        for name in args.packs.split(","):
            name = name.strip()
            if name:
                pack_dirs.append(packs_root / name)

    if not pack_dirs:
        parser.error("Provide at least one pack path or --packs argument.")

    all_errors: List[str] = []

    for pack_dir in pack_dirs:
        print(f"\n── {pack_dir.name} ──")
        if not pack_dir.is_dir():
            msg = f"  ✗ Directory not found: {pack_dir}"
            print(msg)
            all_errors.append(msg)
            continue
        errors = validate_pack(pack_dir, no_http=args.no_http)
        all_errors.extend(errors)

    print()
    if all_errors:
        print(f"PREFLIGHT FAILED — {len(all_errors)} error(s):")
        for e in all_errors:
            print(e)
        sys.exit(1)
    else:
        print("PREFLIGHT PASSED — all xsoar_config.json checks passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
