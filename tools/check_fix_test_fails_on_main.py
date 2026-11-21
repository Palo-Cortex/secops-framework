#!/usr/bin/env python3
"""Fail if a fix's tests would also pass without the fix.

A test only proves a fix if it would have caught the bug. For a pull request
whose title starts with ``fix``, this takes the test files the pull request
adds or changes, runs them against the base branch's code, and requires at
least one of them to fail there. Each file runs alone, from its own folder,
the way ``run_pack_tests.py`` runs it.

A fix that changes no Python code (a fixture, a doc) is not checked. A fix
that changes code but no test fails: it needs one.

Runs in the PR gate. Exit 1 when the fix is not proven; exit 0 otherwise.

Usage::

    python tools/check_fix_test_fails_on_main.py --title "fix(tools): ..." --base origin/main
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_pack_tests import run  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_TEST_NAMES = ("*_test.py", "*_test_*.py", "test_*.py")  # as run_pack_tests.py finds them
TOOL_TEST_NAMES = ("test_*.py",)  # tools/ has check_test_data.py, which is not a test


def is_fix(title: str) -> bool:
    return re.match(r"fix\b", title.strip(), re.IGNORECASE) is not None


def split_changes(paths: list[str]) -> tuple[list[str], list[str]]:
    """The changed Python code under Packs/ and tools/, and the changed test files."""
    code, tests = [], []
    for path in paths:
        if not path.endswith(".py") or not path.startswith(("Packs/", "tools/")):
            continue
        name = Path(path).name
        patterns = TOOL_TEST_NAMES if path.startswith("tools/") else PACK_TEST_NAMES
        (tests if any(fnmatch.fnmatch(name, p) for p in patterns) else code).append(path)
    return code, tests


def verdict(code: list[str], passed_on_main: dict[str, bool]) -> tuple[bool, str]:
    if not code:
        return True, "no code changed, so there is nothing for a test to prove"
    if not passed_on_main:
        return False, "the fix changes code but adds or changes no test"
    failing = [path for path, passed in passed_on_main.items() if not passed]
    if failing:
        return True, "fails on main as it should: " + ", ".join(failing)
    return False, "the new or changed tests all pass on main, so none of them shows the bug"


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout


def results_on_base(base: str, tests: list[str], changed: list[str]) -> dict[str, bool]:
    """Run the pull request's test files against the base branch's code."""
    tmp = Path(tempfile.mkdtemp(prefix="fix-check-"))
    worktree = tmp / "base"
    _git("worktree", "add", "--detach", "-q", str(worktree), base)
    try:
        # The tests and any test data they read come from the pull request; everything else from base.
        for path in tests + [p for p in changed if "/test_data/" in p]:
            target = worktree / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / path, target)
        return {path: run(worktree / path)[0] for path in tests}
    finally:
        _git("worktree", "remove", "--force", str(worktree))
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail if a fix's tests also pass without the fix.")
    parser.add_argument("--title", required=True, help="the pull request title")
    parser.add_argument("--base", default="origin/main", help="branch or commit to compare against")
    args = parser.parse_args(argv)

    if not is_fix(args.title):
        print("OK    not a fix, nothing to check")
        return 0
    changed = [p for p in _git("diff", "--name-only", "--diff-filter=ACMR", f"{args.base}...HEAD").splitlines() if p]
    code, tests = split_changes(changed)
    ok, why = verdict(code, results_on_base(args.base, tests, changed) if code and tests else {})
    if ok:
        print(f"OK    {why}")
        return 0
    print(f"FIX NOT PROVEN: {why}")
    print("\nWrite a test that fails on main, then make the fix. See *Tests first* in "
          "docs/contributing/engineering-practices.md.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
