#!/usr/bin/env python3
"""
Usage:
    python3 tools/pack_prep.py Packs/SocFrameworkCrowdstrikeFalcon
"""

import subprocess
import sys
from pathlib import Path


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 tools/pack_prep.py Packs/<PackName>")
        sys.exit(1)

    pack_path = Path(sys.argv[1])

    if not pack_path.exists():
        print(f"Error: Pack path not found: {pack_path}")
        sys.exit(1)

    pack_name = pack_path.name
    failed = False

    # ── Step 1: Normalize rule IDs and adopted flags ──────────────────────────
    print(f"\n=== Normalizing rule IDs: {pack_path} ===\n")
    subprocess.run(
        [sys.executable, "tools/normalize_ruleid_adopted.py", "--root", str(pack_path), "--fix"]
    )

    # ── Step 2: Validate xsoar_config.json — JSON validity ───────────────────
    config_path = pack_path / "xsoar_config.json"
    if config_path.exists():
        print(f"\n=== Checking xsoar_config.json (JSON validity): {config_path} ===\n")
        rc = subprocess.run(
            [sys.executable, "tools/validate_xsoar_configs.py", "--packs", pack_name]
        ).returncode
        if rc != 0:
            print("xsoar_config.json is invalid JSON — fix before uploading.")
            failed = True
    else:
        print(f"\n--- No xsoar_config.json in {pack_path} — skipping config check ---")

    # ── Step 3: Check cross-pack dependency versions ──────────────────────────
    # Non-blocking warning: flags any dependency custom_packs entry that is
    # behind the current version of the referenced pack.  Interactive TTY
    # prompts to fix in-place; run with --fix to apply silently.
    if config_path.exists():
        print(f"\n=== Checking cross-pack dependency versions: {pack_name} ===\n")
        subprocess.run(
            [sys.executable, "tools/check_dependency_versions.py",
             "--packs", pack_name]
        )
        # Non-blocking — stale versions warn but do not block upload.
        # Auto-fix:  python3 tools/check_dependency_versions.py --fix

    # ── Step 4: Preflight xsoar_config.json — URL format check (no HTTP) ─────
    # Runs format validation only (--no-http skips doc URL live checks).
    # Full HTTP checks run in CI via the preflight job.
    if config_path.exists() and not failed:
        print(f"\n=== Preflight xsoar_config.json (URL format): {config_path} ===\n")
        rc = subprocess.run(
            [sys.executable, "tools/preflight_xsoar_config.py",
             "--packs", pack_name, "--no-http"]
        ).returncode
        if rc != 0:
            print("xsoar_config.json preflight failed — fix zip URL format before uploading.")
            failed = True

    # ── Step 5: demisto-sdk validate ─────────────────────────────────────────
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    error_log = output_dir / "sdk_errors.txt"

    print(f"\n=== Validating: {pack_path} (output → {error_log}) ===\n")
    with open(error_log, "w") as log:
        rc = subprocess.run(
            ["demisto-sdk", "validate", "-i", str(pack_path)],
            stdout=log, stderr=log
        ).returncode

    if rc == 0:
        print("SDK validation passed.")
    else:
        print(f"SDK validation errors written to {error_log}")
        failed = True

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
