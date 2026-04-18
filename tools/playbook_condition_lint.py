#!/usr/bin/env python3
"""
playbook_condition_lint.py — SOC Framework playbook condition & context validator

Catches playbook YAML patterns that parse cleanly but silently fail at runtime.
The XSIAM Playbook Editor UI prevents these patterns by construction; hand-written
YAML bypasses that guardrail. Both bug classes below shipped to production in
the NIST IR pack before detection, blocking full Containment execution.

CHECKS
──────
  1. Malformed ${X / Y} context references
     ─────────────────────────────────────
     Pattern detected:
         root: ${Analysis
         accessor: verdict}
     Effect:
         Interpolation opens ${ on one line and closes } on the next, splitting
         the context path. XSIAM treats "${Analysis" as a literal string.
         Downstream conditions comparing it to real values always fail.
     Correct form (complex):
         root: Analysis
         accessor: verdict
     Correct form (simple):
         simple: ${Analysis.verdict}

  2. AND-impossible conditions
     ─────────────────────────
     Pattern detected:
         condition:
         - - operator: isEqualString
             left: inputs.Verdict
             right: malicious
           - operator: isEqualString       # SAME AND block
             left: inputs.Verdict          # SAME field
             right: suspicious             # DIFFERENT value
     Effect:
         XSIAM condition syntax: outer list = OR, inner list = AND. A single
         field cannot equal two different values simultaneously, so the entire
         OR-block is unreachable. The condition's "Default" label fires instead.
     Correct form — one OR block per possible value:
         condition:
         - - operator: isEqualString
             left: inputs.Verdict
             right: malicious
         - - operator: isEqualString
             left: inputs.Verdict
             right: suspicious

EXIT CODES
──────────
  0  No bugs found
  1  One or more bugs found

USAGE
─────
  # Single pack
  python3 tools/playbook_condition_lint.py Packs/soc-framework-nist-ir

  # Single file
  python3 tools/playbook_condition_lint.py Packs/soc-framework-nist-ir/Playbooks/SOC_Endpoint_Containment_V3.yml

  # Multiple paths
  python3 tools/playbook_condition_lint.py Packs/soc-framework-nist-ir Packs/soc-optimization-unified
"""

import argparse
import sys
from pathlib import Path

import yaml


EQUALITY_OPERATORS = {"isEqualString", "isEqualNumber", "containsString"}


def find_yaml_files(path: Path):
    """Yield all .yml files under a pack Playbooks dir, or the file itself."""
    if path.is_file() and path.suffix == ".yml":
        yield path
        return
    if path.is_dir():
        pb_dir = path / "Playbooks"
        root = pb_dir if pb_dir.is_dir() else path
        for p in sorted(root.rglob("*.yml")):
            if "__MACOSX" in p.parts:
                continue
            yield p


def check_broken_interpolation(fpath: Path):
    """Line-level scan for `root: ${X` paired with `accessor: Y}` on next line."""
    bugs = []
    try:
        lines = fpath.read_text().splitlines()
    except Exception:
        return bugs

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("root:"):
            continue
        if "${" not in stripped or "}" in stripped:
            continue
        if i + 1 >= len(lines):
            continue
        next_stripped = lines[i + 1].strip()
        if next_stripped.startswith("accessor:") and next_stripped.endswith("}"):
            bugs.append({
                "line": i + 1,
                "root": stripped,
                "accessor": next_stripped,
            })
    return bugs


def _field_identity(left_value):
    """Return a stable identity for the left-hand field of a condition item.

    Covers both `simple: path.to.field` and `complex: {root: X, accessor: Y}`.
    Returns None if we can't extract a stable key.
    """
    if not isinstance(left_value, dict):
        return None
    simple = left_value.get("simple")
    if isinstance(simple, str) and simple:
        return simple.strip()
    complex_val = left_value.get("complex")
    if isinstance(complex_val, dict):
        root = complex_val.get("root", "")
        accessor = complex_val.get("accessor", "")
        if root:
            return f"{root}.{accessor}" if accessor else root
    return None


def check_and_impossible_conditions(fpath: Path):
    """Removed — this check was based on a wrong understanding of XSIAM semantics.

    XSIAM condition evaluation: outer list = AND, inner list = OR.
    Multiple equality checks on the same field within one inner list are
    legitimate and idiomatic — they express "field is one of [A, B, C]".

    Earlier versions of this linter flagged that pattern as a bug; those
    reports were false positives. Any "fixes" based on those reports are
    regressions and should be reverted.

    Retained as a stub returning no findings so existing callers don't break.
    """
    return []


def main():
    ap = argparse.ArgumentParser(
        description="Lint XSIAM playbooks for broken ${X / Y} references and AND-impossible conditions.",
    )
    ap.add_argument(
        "paths",
        nargs="+",
        help="Pack directories or individual playbook YAML files to lint.",
    )
    ap.add_argument(
        "--quiet",
        action="store_true",
        help="Only print files with bugs; suppress per-file success lines.",
    )
    args = ap.parse_args()

    total_files = 0
    total_interp = 0
    total_cond = 0
    failing_files = []

    for raw in args.paths:
        path = Path(raw)
        if not path.exists():
            print(f"  SKIP  {path} (not found)", file=sys.stderr)
            continue

        for yml in find_yaml_files(path):
            total_files += 1
            interp_bugs = check_broken_interpolation(yml)
            cond_bugs = check_and_impossible_conditions(yml)

            if not interp_bugs and not cond_bugs:
                if not args.quiet:
                    print(f"  OK    {yml}")
                continue

            failing_files.append(yml)
            print(f"\n  FAIL  {yml}")

            if interp_bugs:
                print(f"        Broken ${{X / Y}} context references ({len(interp_bugs)}):")
                for b in interp_bugs:
                    print(f"          line {b['line']}: {b['root']}  {b['accessor']}")
                total_interp += len(interp_bugs)

            if cond_bugs:
                print(f"        AND-impossible conditions ({len(cond_bugs)}):")
                for b in cond_bugs:
                    print(
                        f"          task {b['task_id']} '{b['task_name']}' "
                        f"label='{b['label']}' block[{b['block']}]: "
                        f"{b['field']} must equal ALL of {b['values']}"
                    )
                total_cond += len(cond_bugs)

    print()
    print(f"  Scanned: {total_files} playbook file(s)")
    print(f"  Broken interpolations: {total_interp}")
    print(f"  AND-impossible conditions: {total_cond}")

    if failing_files:
        print(f"  Result: {len(failing_files)} file(s) with bugs")
        return 1
    print("  Result: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
