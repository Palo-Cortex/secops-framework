#!/usr/bin/env python3
"""Refresh every generated documentation file in the right order.

A single entry point for contributors and CI. Replaces the manual sequence
of running four generators in the right order before each docs commit::

    1. generate_pack_overviews.py
    2. generate_schema_docs.py
    3. generate_mkdocs_nav.py
    4. generate_home_page.py

Order matters: ``generate_mkdocs_nav.py`` discovers per-pack pages from
each pack's ``docs_path``, so pack overviews and schema docs must land on
disk first.

Usage::

    python tools/prep_docs.py             # regenerate everything; commit the diffs
    python tools/prep_docs.py --check     # CI: fail non-zero if regen would change anything
    python tools/prep_docs.py --quiet     # suppress per-step banners (errors still print)

Exit codes:

    0   all generators ran cleanly (or --check passed with no drift)
    1   at least one generator failed (or --check found drift)

In the contributor flow, run this whenever you've touched anything under
``docs/``, ``schemas/``, ``Packs/*/xsoar_config.json``, or
``Packs/*/docs/``. Commit the resulting diffs alongside your content
changes.

In CI, run with ``--check`` in the PR gate workflow. If a contributor
forgets to regenerate before pushing, the gate will tell them which
generator's output drifted.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"

# Order is intentional. Pack-level pages must land on disk before the nav
# generator discovers them. Home page is independent but conventionally
# runs last so the site config is fully assembled before final render.
GENERATORS: list[tuple[str, str]] = [
    ("generate_pack_overviews.py", "Per-pack overview pages"),
    ("generate_schema_docs.py",    "Per-pack schema documentation"),
    ("generate_mkdocs_nav.py",     "mkdocs.yml navigation"),
    ("generate_home_page.py",      "docs/index.md home page"),
]


def run_generator(script: str, label: str, check_mode: bool, quiet: bool) -> tuple[bool, str]:
    """Run one generator. Return (success, captured_output)."""
    script_path = TOOLS_DIR / script
    if not script_path.exists():
        return False, f"ERROR: generator not found at {script_path}"

    cmd = [sys.executable, str(script_path)]
    if check_mode:
        cmd.append("--check")

    if not quiet:
        mode_label = "checking" if check_mode else "running"
        print(f"  → {mode_label}: {script}  ({label})")

    result = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    output_parts = []
    if result.stdout.strip():
        output_parts.append(result.stdout.rstrip())
    if result.stderr.strip():
        output_parts.append(result.stderr.rstrip())
    output = "\n".join(output_parts)

    return result.returncode == 0, output


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Run all documentation generators in the right order.",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Drift-detection mode for CI. Exit non-zero if any generator "
             "would change a file.",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress per-step banners (errors still print).",
    )
    args = parser.parse_args(argv)

    if not args.quiet:
        mode = "drift check" if args.check else "regeneration"
        print(f"prep_docs: {mode} across {len(GENERATORS)} generators")

    failures: list[tuple[str, str]] = []

    for script, label in GENERATORS:
        ok, output = run_generator(script, label, args.check, args.quiet)
        if not ok:
            failures.append((script, output))
            # Keep going so the contributor sees every failing generator
            # in one run instead of fixing them one at a time.
            if not args.quiet:
                print(f"    FAIL")
                for line in output.splitlines():
                    print(f"      {line}")
        elif output and not args.quiet:
            # Some generators print useful summaries even on success
            for line in output.splitlines():
                print(f"      {line}")

    if failures:
        print()
        if args.check:
            print(f"prep_docs: drift detected in {len(failures)} generator(s).")
            print("Fix locally with:  python3 tools/prep_docs.py")
        else:
            print(f"prep_docs: {len(failures)} generator(s) failed.")
        for script, _ in failures:
            print(f"  - {script}")
        return 1

    if not args.quiet:
        print()
        if args.check:
            print("prep_docs: no drift. Generated files match the templates.")
        else:
            print("prep_docs: all generators completed. Review and commit the diffs.")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
