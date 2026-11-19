#!/usr/bin/env python3
"""Run every pack test file, each in its own pytest process, and fail on any failure.

Script tests load their script as a module named after it, and several test files
stub `demistomock` and `CommonServerPython` differently. In one pytest process
those stubs collide and about a hundred tests fail that pass on their own, so each
file runs alone, from its own directory, the way its author ran it.

A test file that runs no tests counts as a failure: a file that pytest silently
skips is a test nobody is running.

Usage:
    python3 tools/run_pack_tests.py soc-optimization-unified
    python3 tools/run_pack_tests.py soc-optimization-unified,soc-framework-nist-ir-ai
    python3 tools/run_pack_tests.py --all

Exit code 0 when every file passes, 1 otherwise. Test files are *_test.py,
*_test_*.py and test_*.py under Packs/<pack>/.
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKS = ROOT / "Packs"
PATTERNS = ("*_test.py", "*_test_*.py", "test_*.py")
NO_TESTS = 5  # pytest's exit code when it collected nothing


def test_files(pack):
    found = set()
    for pattern in PATTERNS:
        found.update(p for p in (PACKS / pack).rglob(pattern)
                     if "__pycache__" not in p.parts and "node_modules" not in p.parts)
    return sorted(found)


def run(path):
    """(passed, summary line) for one test file."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-W", "ignore", path.name],
        cwd=path.parent, capture_output=True, text=True, timeout=600,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    summary = re.sub(r" in [0-9.]+s", "", lines[-1]).strip("= ") if lines else "no output"
    if proc.returncode == NO_TESTS:
        return False, "no tests ran"
    return proc.returncode == 0, summary


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("packs", nargs="?", default="", help="comma-separated pack directories")
    ap.add_argument("--all", action="store_true", help="every pack under Packs/")
    a = ap.parse_args()
    if a.all:
        packs = sorted(p.name for p in PACKS.iterdir() if p.is_dir())
    else:
        packs = [p.strip() for p in a.packs.split(",") if p.strip()]
    if not packs:
        ap.error("name a pack or use --all")

    failed, missing, total = [], [], 0
    for pack in packs:
        if not (PACKS / pack).is_dir():
            print(f"::error::Packs/{pack} does not exist")
            missing.append(pack)
            continue
        files = test_files(pack)
        if not files:
            continue
        print(f"=== {pack} ({len(files)} test file(s))")
        for path in files:
            total += 1
            ok, summary = run(path)
            rel = path.relative_to(ROOT)
            print(f"  {'PASS' if ok else 'FAIL'}  {rel}  {summary}")
            if not ok:
                failed.append(str(rel))
                if os.environ.get("GITHUB_ACTIONS"):
                    print(f"::error file={rel}::{summary}")

    print(f"\n{total - len(failed)} of {total} test file(s) passed")
    if failed:
        print("Failed:\n  " + "\n  ".join(failed))
    if missing:
        print("No such pack:\n  " + "\n  ".join(missing))
    return 1 if failed or missing else 0


if __name__ == "__main__":
    sys.exit(main())
