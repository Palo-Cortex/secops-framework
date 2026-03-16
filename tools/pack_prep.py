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

    pack = sys.argv[1]

    if not Path(pack).exists():
        print(f"Error: Pack path not found: {pack}")
        sys.exit(1)

    print(f"\n=== Normalizing rule IDs: {pack} ===\n")
    subprocess.run(
        [sys.executable, "tools/normalize_ruleid_adopted.py", "--root", pack, "--fix"]
    )

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    error_log = output_dir / "sdk_errors.txt"

    print(f"\n=== Validating: {pack} (output → {error_log}) ===\n")
    with open(error_log, "a") as log:
        rc = subprocess.run(
            ["demisto-sdk", "validate", "-i", pack],
            stdout=log, stderr=log
        ).returncode

    if rc == 0:
        print("Validation passed.")
    else:
        print(f"Validation errors written to {error_log}")

    sys.exit(rc)


if __name__ == "__main__":
    main()
