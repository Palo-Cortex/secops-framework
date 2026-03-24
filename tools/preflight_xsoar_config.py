#!/usr/bin/env python3
"""
preflight_xsoar_config.py

Validates xsoar_config.json for one or more packs before deployment.

Checks:
  1. custom_packs[*].id   — Must be the BARE pack name (no version suffix, no .zip).
                             The id is XSIAM's stable upgrade-in-place key.
                             A versioned id causes a new pack to be installed alongside
                             the old one on every release instead of upgrading it.
                             Version belongs only in the url field.
  2. custom_packs[*].url  — Format validation only (release zip doesn't exist yet
                             pre-merge).  Version is sourced from pack_metadata.json,
                             not from the id field.  Dependency pack entries are
                             matched by pack name prefix in the url.
  3. pre_config_docs[*].url  — HTTP check (file must exist on main)
  4. post_config_docs[*].url — HTTP check (file must exist on main)

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
from typing import List, Tuple

GITHUB_REPO = "Palo-Cortex/secops-framework"

# Matches a versioned id — must NOT appear in custom_packs[*].id
_VERSIONED_ID_RE = re.compile(r"-v\d+\.\d+|\.zip$", re.IGNORECASE)

# Matches semver e.g. "1.2.3"
_SEMVER_RE = re.compile(r"^\d+\.\d+(\.\d+)*$")


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


def expected_zip_url(pack_id: str, version: str) -> str:
    """Build the canonical GitHub release zip URL for a pack at a given version."""
    tag = f"{pack_id}-v{version}"
    return f"https://github.com/{GITHUB_REPO}/releases/download/{tag}/{tag}.zip"


def validate_zip_url_format(
    url: str, pack_id: str, version: str, label: str
) -> Tuple[bool, str]:
    """
    Format-only validation for custom_packs zip URLs.

    The release zip doesn't exist yet at PR time — we can't HTTP-check it.
    Instead verify the URL is structurally correct against the expected pattern:
      https://github.com/{repo}/releases/download/{pack_id}-v{version}/{pack_id}-v{version}.zip
    """
    want = expected_zip_url(pack_id, version)

    if url == want:
        return True, f"  ✓ {label} url: {url}"

    if GITHUB_REPO not in url:
        detail = f"wrong repo (expected {GITHUB_REPO})"
    elif f"{pack_id}-v{version}" not in url:
        if pack_id not in url:
            detail = f"pack name mismatch (expected '{pack_id}')"
        else:
            detail = f"version mismatch (expected v{version})"
    else:
        detail = f"unexpected format"

    return False, (
        f"  ✗ {label} url format error — {detail}\n"
        f"    was:  {url}\n"
        f"    want: {want}"
    )


# ── Per-pack validation ───────────────────────────────────────────────────────

def validate_pack(pack_dir: Path, no_http: bool = False) -> List[str]:
    """
    Validate xsoar_config.json for a single pack.
    Returns a list of error strings.  Empty = all checks passed.
    """
    config_path = pack_dir / "xsoar_config.json"
    errors = []

    if not config_path.exists():
        print(f"  (no xsoar_config.json — skipping)")
        return errors

    cfg = load_json(config_path)

    # Version source-of-truth: pack_metadata.json
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

    # ── 1 + 2. custom_packs — id and url ─────────────────────────────────────
    custom_packs = cfg.get("custom_packs", [])
    if custom_packs:
        print(f"  Checking custom_packs (pack={pack_id}, version={primary_version})...")

    for i, entry in enumerate(custom_packs):
        if not isinstance(entry, dict):
            errors.append(f"  ✗ custom_packs[{i}] is not an object")
            continue

        entry_id = entry.get("id", "")
        url = entry.get("url", "")

        # Rule 1: id must be the bare pack name
        if not entry_id:
            errors.append(f"  ✗ custom_packs[{i}] missing 'id'")
        elif _VERSIONED_ID_RE.search(entry_id):
            errors.append(
                f"  ✗ custom_packs[{i}].id '{entry_id}' must be the bare pack name "
                f"(no version suffix, no .zip). "
                f"Run bump_pack_version.py to fix — it will set id='{entry_id.split('-v')[0].removesuffix('.zip')}'."
            )
        else:
            print(f"  ✓ custom_packs[{i}].id '{entry_id}' (bare name)")

        # Rule 2: url must match expected format
        # Version is always sourced from pack_metadata.json.
        # For dependency entries (id != primary pack), derive the pack name from
        # the id (which is now bare) and look up its version from the url itself
        # since we don't have its pack_metadata here.  We validate that the url
        # at minimum references the right repo and pack name.
        if not url:
            errors.append(f"  ✗ custom_packs[{i}] missing 'url'")
        else:
            # Determine which pack+version to validate against
            if entry_id and entry_id == pack_id:
                # Primary pack — version must match pack_metadata.json
                ok, msg = validate_zip_url_format(url, pack_id, primary_version, f"custom_packs[{i}]")
            elif entry_id and not _VERSIONED_ID_RE.search(entry_id):
                # Dependency pack — extract version from the url (we trust the url
                # for version since we don't have that pack's metadata here)
                m = re.search(r"-v(\d+\.\d+(?:\.\d+)*)\.zip$", url)
                if m:
                    dep_version = m.group(1)
                    ok, msg = validate_zip_url_format(url, entry_id, dep_version, f"custom_packs[{i}]")
                else:
                    ok, msg = False, (
                        f"  ✗ custom_packs[{i}] url '{url}' does not match the expected "
                        f"GitHub release zip format: "
                        f"https://github.com/ORG/REPO/releases/download/PACK-vVER/PACK-vVER.zip"
                    )
            else:
                # id is versioned/bad — skip url check, id error already recorded
                ok, msg = True, ""

            if msg:
                print(msg)
            if not ok:
                errors.append(msg)

    # ── 3. pre_config_docs URLs — HTTP check ─────────────────────────────────
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

    # ── 4. post_config_docs URLs — HTTP check ────────────────────────────────
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
        help="Skip live HTTP checks for doc URLs.  Only zip URL format is validated. "
             "Use locally to avoid network latency; CI always runs full checks.",
    )

    args = parser.parse_args()

    pack_dirs: List[Path] = [Path(p) for p in args.pack_paths]

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
