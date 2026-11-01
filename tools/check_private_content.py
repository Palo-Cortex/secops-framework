#!/usr/bin/env python3
"""Fail if content that belongs in a private repo is in this one.

The AI Prompt recipes (bodies, input bindings, authoring notes) were moved to
the private ``socfw-nist-ir-ai`` repo in Nov 2026 and must not come back. This
gate checks two things, from ``policies/private_content.json``:

  * ``paths``        — glob patterns that must not exist in the working tree
                       (``*.prompt.md``, ``AI_PROMPTS.md``, ``prompts/`` ...)
  * ``fingerprints`` — strings that only occur inside the private prompt
                       bodies; any text file containing one fails, whatever
                       it is called

Runs in ``check_contribution.py`` before the upload and in the PR gate. Exit
1 with the offending paths; exit 0 when clean.

Usage::

    python tools/check_private_content.py            # whole tree
    python tools/check_private_content.py --staged   # only files in the index
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = REPO_ROOT / "policies" / "private_content.json"
TEXT_SUFFIXES = {".md", ".txt", ".yml", ".yaml", ".json", ".py", ".sh", ".html", ".csv", ".prompt"}
SKIP_DIRS = {".git", "site", "node_modules", "__pycache__", ".pytest_cache", "input_tsv", "output", "out"}


def tracked_files(staged_only: bool) -> list[Path]:
    args = ["git", "ls-files", "--cached", "--others", "--exclude-standard"]
    if staged_only:
        args = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"]
    out = subprocess.run(args, cwd=REPO_ROOT, capture_output=True, text=True, check=False).stdout
    return [REPO_ROOT / p for p in out.splitlines() if p]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Fail if private content is in the public repo.")
    p.add_argument("--staged", action="store_true", help="check only files staged for commit")
    args = p.parse_args(argv)

    if not POLICY.exists():
        print(f"ERROR: {POLICY} not found", file=sys.stderr)
        return 2
    policy = json.loads(POLICY.read_text())
    path_globs: list[str] = policy.get("paths", [])
    fingerprints: list[str] = policy.get("fingerprints", [])
    allow: set[str] = set(policy.get("allow", []))   # the policy file and this script name the fingerprints

    failures: list[str] = []
    for path in tracked_files(args.staged):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if any(part in SKIP_DIRS for part in path.parts) or rel in allow:
            continue
        if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(path.name, g) for g in path_globs):
            failures.append(f"{rel}: path matches a private-content pattern")
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for fp in fingerprints:
            if fp in text:
                failures.append(f"{rel}: contains a private prompt fingerprint ({fp[:40]}...)")
                break

    if failures:
        print("PRIVATE CONTENT IN PUBLIC REPO:")
        for f in failures:
            print(f"  {f}")
        print(
            "\nThe AI Prompt recipes live in Palo-Cortex/socfw-nist-ir-ai (private). "
            "Remove the file(s) above; reference the prompt master instead. "
            "See policies/private_content.json.",
            file=sys.stderr,
        )
        return 1
    print("OK    no private content in the public tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
