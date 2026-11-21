#!/usr/bin/env python3
"""Fail if a changed Python file has more ruff findings than it has on main.

Code on main does not meet ``ruff.toml`` yet, so failing on every finding
would block every pull request. Instead, each Python file a pull request
adds or changes is checked against its version on the base branch: for every
rule, the count may stay the same or go down, never up. A new file must be
clean. Old debt goes down as files are worked on.

For files on a high-risk path (see the guide's *High-risk paths*), the
existing findings are listed too, so the debt in code that acts on customer
systems stays visible each time it is touched.

Runs in the PR gate. Exit 1 when a file gained findings; exit 0 otherwise.

Usage::

    python tools/check_ruff_no_new.py                    # against origin/main
    python tools/check_ruff_no_new.py --base origin/main
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Keep in step with "High-risk paths" in docs/contributing/engineering-practices.md.
HIGH_RISK_PREFIXES = (
    "Packs/soc-optimization-unified/Scripts/SOCCommandWrapper/",
    "Packs/soc-optimization-unified/Scripts/SOCFWConfig/",
    "Packs/soc-optimization-unified/Scripts/SOCFWPhaseExecutor/",
    "Packs/soc-optimization-unified/Scripts/SOCFWEmergencyResponse/",
    "Packs/soc-framework-nist-ir-ai/Scripts/SOCFWCloseDecision/",
    "tools/check_contribution.py",
)


def high_risk(path: str) -> bool:
    return path.startswith(HIGH_RISK_PREFIXES)


def added_findings(base: Counter, head: Counter) -> dict[str, int]:
    """Rules whose count went up from base to head, with how many were added."""
    return {rule: head[rule] - base[rule] for rule in sorted(head) if head[rule] > base[rule]}


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False)


def _ruff_counts(path: str, source: str | None) -> Counter:
    """Ruff findings by rule for a file, read from disk or from the given source."""
    cmd = ["ruff", "check", "--output-format", "json", "--exit-zero"]
    cmd += ["--stdin-filename", path, "-"] if source is not None else [path]
    out = subprocess.run(cmd, cwd=REPO_ROOT, input=source, capture_output=True, text=True, check=True).stdout
    return Counter(item["code"] or "syntax" for item in json.loads(out or "[]"))


def changed_files(base: str) -> list[str]:
    out = _git("diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD", "--", "*.py").stdout
    return [p for p in out.splitlines() if p]


def _summary(counts: Counter) -> str:
    return ", ".join(f"{rule} {n}" for rule, n in counts.most_common())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail if a changed file gained ruff findings.")
    parser.add_argument("--base", default="origin/main", help="branch or commit to compare against")
    args = parser.parse_args(argv)

    failures = []
    for path in changed_files(args.base):
        shown = _git("show", f"{args.base}:{path}")
        base = _ruff_counts(path, shown.stdout) if shown.returncode == 0 else Counter()
        head = _ruff_counts(path, None)
        added = added_findings(base, head)
        if added:
            failures.append(f"{path}: {_summary(Counter(added))} more than on {args.base}")
        if high_risk(path) and head:
            print(f"NOTE  {path} is a high-risk path with {sum(head.values())} existing findings: {_summary(head)}")

    if failures:
        print("FILES WITH MORE RUFF FINDINGS THAN ON THE BASE BRANCH:")
        for f in failures:
            print(f"  {f}")
        print("\nRun `ruff check <file>` and fix the findings the change added. "
              "Existing findings can stay; see ruff.toml.", file=sys.stderr)
        return 1
    print("OK    no changed file gained ruff findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
