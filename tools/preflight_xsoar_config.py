#!/usr/bin/env python3
"""
preflight_xsoar_config.py

Validates xsoar_config.json for one or more packs before deployment.

Checks:
  1. custom_packs[*].url       — GitHub release zip URL returns HTTP 200
  2. pre_config_docs[*].url    — Doc URLs return HTTP 200
  3. post_config_docs[*].url   — Doc URLs return HTTP 200

Usage:
  python3 tools/preflight_xsoar_config.py Packs/SocFrameworkProofPointTap
  python3 tools/preflight_xsoar_config.py Packs/SocFrameworkProofPointTap Packs/SocFrameworkCrowdstrikeFalcon

  # From CI — comma-separated pack names (as output by detect job)
  python3 tools/preflight_xsoar_config.py --packs "SocFrameworkProofPointTap,soc-optimization-unified"
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Tuple

GITHUB_REPO     = "Palo-Cortex/secops-framework"

# ── Helpers ──────────────────────────────────────────────────────────────────

def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"ERROR: File not found: {path}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"ERROR: Failed to parse JSON {path}: {e}")


def check_url(url: str, label: str) -> Tuple[bool, str]:
    """
    Returns (ok, message).
    Follows redirects. HEAD first, falls back to GET for servers that block HEAD.
    """
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(url, method=method, headers={"User-Agent": "soc-framework-preflight/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                code = resp.status
                if code == 200:
                    return True, f"  ✓ {label}: {url}"
                return False, f"  ✗ {label}: HTTP {code} — {url}"
        except urllib.error.HTTPError as e:
            if method == "HEAD" and e.code in (405, 403):
                continue  # retry with GET
            return False, f"  ✗ {label}: HTTP {e.code} — {url}"
        except urllib.error.URLError as e:
            return False, f"  ✗ {label}: Connection error — {url} ({e.reason})"
        except Exception as e:
            return False, f"  ✗ {label}: {e} — {url}"
    return False, f"  ✗ {label}: Unreachable — {url}"


# ── Per-pack validation ───────────────────────────────────────────────────────

def validate_pack(pack_dir: Path) -> List[str]:
    """
    Validate xsoar_config.json for a single pack.
    Returns a list of error strings. Empty list = all checks passed.
    """
    config_path = pack_dir / "xsoar_config.json"
    errors = []

    if not config_path.exists():
        print(f"  (no xsoar_config.json — skipping)")
        return errors

    cfg = load_json(config_path)

    # ── 1. custom_packs zip URLs ──────────────────────────────────────────────
    custom_packs = cfg.get("custom_packs", [])
    if custom_packs:
        print("  Checking custom_packs zip URLs...")
    for entry in custom_packs:
        url = entry.get("url", "")
        if not url:
            errors.append(f"  ✗ custom_packs entry missing 'url': {entry.get('id', '?')}")
            continue
        ok, msg = check_url(url, f"zip [{entry.get('id', '?')}]")
        print(msg)
        if not ok:
            errors.append(msg)

    # ── 2. pre_config_docs URLs ───────────────────────────────────────────────
    pre_docs = cfg.get("pre_config_docs", [])
    if pre_docs:
        print("  Checking pre_config_docs URLs...")
    for entry in pre_docs:
        url = entry.get("url", "")
        if not url:
            continue
        ok, msg = check_url(url, f"pre_doc [{entry.get('name', '?')}]")
        print(msg)
        if not ok:
            errors.append(msg)

    # ── 3. post_config_docs URLs ──────────────────────────────────────────────
    post_docs = cfg.get("post_config_docs", [])
    if post_docs:
        print("  Checking post_config_docs URLs...")
    for entry in post_docs:
        url = entry.get("url", "")
        if not url:
            continue
        ok, msg = check_url(url, f"post_doc [{entry.get('name', '?')}]")
        print(msg)
        if not ok:
            errors.append(msg)

    return errors


# ── Main ─────────────────────────────────────────────────────────────────────

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
        errors = validate_pack(pack_dir)
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
