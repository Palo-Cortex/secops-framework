#!/usr/bin/env python3
"""Fail if a changed Python file has more ruff findings than on main, or leaves a touched function undocumented.

Code on main does not meet ``ruff.toml`` yet, so failing on every finding
would block every pull request. Instead, each Python file a pull request
adds or changes is checked against its version on the base branch: for every
rule, the count may stay the same or go down, never up. A new file must be
clean. Old debt goes down as files are worked on.

A function the pull request touches (any of its lines added or changed) must
also leave with a docstring and type hints: its D1 and ANN findings must be
gone, whatever they were on the base branch. Code nobody touched keeps its old
findings. This is how the code becomes self-documenting as it is worked on.

For files on a high-risk path (see the guide's *High-risk paths*), the
existing findings are listed too, so the debt in code that acts on customer
systems stays visible each time it is touched.

Runs in the PR gate. Exit 1 when a file gained findings or a touched function
is undocumented; exit 0 otherwise.

Usage::

    python tools/check_ruff_no_new.py                    # against origin/main
    python tools/check_ruff_no_new.py --base origin/main
"""

from __future__ import annotations

import argparse
import ast
import json
import re
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


# Rules a touched function must satisfy: docstrings (D1) and type hints on its
# arguments and return value.
DOC_RULES = ("D1", "ANN001", "ANN201")

HUNK = re.compile(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


def high_risk(path: str) -> bool:
    """True when the path is one where a wrong line acts on a customer's systems."""
    return path.startswith(HIGH_RISK_PREFIXES)


def changed_lines(diff: str) -> set[int]:
    """Line numbers on the branch side that a zero-context unified diff adds or changes."""
    lines = set()
    for start, count in HUNK.findall(diff):
        first = int(start)
        lines.update(range(first, first + (int(count) if count else 1)))
    return lines


def function_spans(source: str) -> list[tuple[int, int]]:
    """(first line, last line) of every function, decorators included, in source order."""
    spans = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            first = min([node.lineno] + [d.lineno for d in node.decorator_list])
            spans.append((first, node.end_lineno))
    return sorted(spans)


def undocumented_touched(
    findings: list[tuple[str, int]], spans: list[tuple[int, int]], touched: set[int]
) -> list[tuple[str, int]]:
    """Docstring and type-hint findings that sit in a function the change touched.

    Each finding belongs to the innermost function around its line, so editing an
    outer function does not make an untouched nested one fail.
    """
    result = []
    for code, row in findings:
        if not code.startswith(DOC_RULES):
            continue
        around = [span for span in spans if span[0] <= row <= span[1]]
        if not around:
            continue
        first, last = max(around)
        if any(first <= line <= last for line in touched):
            result.append((code, row))
    return result


def added_findings(base: Counter, head: Counter) -> dict[str, int]:
    """Rules whose count went up from base to head, with how many were added."""
    return {rule: head[rule] - base[rule] for rule in sorted(head) if head[rule] > base[rule]}


def _git(*args: str) -> subprocess.CompletedProcess:
    """Run git in the repo root without raising on a non-zero exit."""
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False)


def _ruff_findings(path: str, source: str | None) -> list[tuple[str, int]]:
    """(rule, line) of each ruff finding in a file, read from disk or from the given source."""
    cmd = ["ruff", "check", "--output-format", "json", "--exit-zero"]
    cmd += ["--stdin-filename", path, "-"] if source is not None else [path]
    out = subprocess.run(cmd, cwd=REPO_ROOT, input=source, capture_output=True, text=True, check=True).stdout
    return [(item["code"] or "syntax", item["location"]["row"]) for item in json.loads(out or "[]")]


def _counts(findings: list[tuple[str, int]]) -> Counter:
    """Findings counted by rule."""
    return Counter(code for code, _ in findings)


def _undocumented(path: str, base: str, findings: list[tuple[str, int]]) -> list[tuple[str, int]]:
    """Docstring and type-hint findings in the functions this branch touched in the file."""
    diff = _git("diff", "-U0", f"{base}...HEAD", "--", path).stdout
    try:
        spans = function_spans((REPO_ROOT / path).read_text())
    except SyntaxError:
        return []  # ruff reports the syntax error itself
    return undocumented_touched(findings, spans, changed_lines(diff))


def changed_files(base: str) -> list[str]:
    """Python files the branch adds, copies, modifies or renames relative to base."""
    out = _git("diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD", "--", "*.py").stdout
    return [p for p in out.splitlines() if p]


def _summary(counts: Counter) -> str:
    """Counts as "RULE n, RULE n", most frequent first."""
    return ", ".join(f"{rule} {n}" for rule, n in counts.most_common())


def main(argv: list[str] | None = None) -> int:
    """Check each changed file; print the failures and return the exit code."""
    parser = argparse.ArgumentParser(description="Fail if a changed file gained ruff findings.")
    parser.add_argument("--base", default="origin/main", help="branch or commit to compare against")
    args = parser.parse_args(argv)

    failures, undocumented = [], []
    for path in changed_files(args.base):
        shown = _git("show", f"{args.base}:{path}")
        base = _counts(_ruff_findings(path, shown.stdout)) if shown.returncode == 0 else Counter()
        findings = _ruff_findings(path, None)
        head = _counts(findings)
        added = added_findings(base, head)
        if added:
            failures.append(f"{path}: {_summary(Counter(added))} more than on {args.base}")
        undocumented += [f"{path}:{row}: {code}" for code, row in _undocumented(path, args.base, findings)]
        if high_risk(path) and head:
            print(f"NOTE  {path} is a high-risk path with {sum(head.values())} existing findings: {_summary(head)}")

    if undocumented:
        print("FUNCTIONS THIS CHANGE TOUCHED THAT LACK A DOCSTRING OR TYPE HINTS:")
        for u in undocumented:
            print(f"  {u}")
        print("\nA function you change leaves with a docstring and type hints. "
              "See docs/contributing/self-documenting-code.md.", file=sys.stderr)

    if failures:
        print("FILES WITH MORE RUFF FINDINGS THAN ON THE BASE BRANCH:")
        for f in failures:
            print(f"  {f}")
        print("\nRun `ruff check <file>` and fix the findings the change added. "
              "Existing findings can stay; see ruff.toml.", file=sys.stderr)
    if failures or undocumented:
        return 1
    print("OK    no changed file gained ruff findings; every touched function is documented")
    return 0


if __name__ == "__main__":
    sys.exit(main())
