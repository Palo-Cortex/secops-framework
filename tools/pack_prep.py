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

    print(f"\n=== Validating: {pack} (output → sdk_errors.txt) ===\n")
    with open("sdk_errors.txt", "a") as log:
        rc = subprocess.run(
            ["demisto-sdk", "validate", "-i", pack],
            stdout=log, stderr=log
        ).returncode

    if rc == 0:
        print("Validation passed.")
    else:
        print("Validation errors written to sdk_errors.txt")

    sys.exit(rc)


if __name__ == "__main__":
    main()
