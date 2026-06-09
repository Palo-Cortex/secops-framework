#!/usr/bin/env python3
"""
emit_lifecycle_content.py
=========================
Convenience wrapper around tools/generate_soc_framework_content.py that runs
emit (or validate) on ALL schemas for a lifecycle pack in a single command.

The pack name IS the identifier — same name in both locations:
    schemas dir : schemas/soc-framework/<pack>/
    pack root   : Packs/<pack>/

For each *.yaml in the schemas dir, invokes:
    python3 tools/generate_soc_framework_content.py emit \
        --mapping <yaml> --pack-root <pack-root>

USAGE
-----
    # Emit all schemas for soc-framework-posture into Packs/soc-framework-posture/
    python3 tools/emit_lifecycle_content.py soc-framework-posture

    # Validate only — catches schema errors without writing list JSON
    python3 tools/emit_lifecycle_content.py soc-framework-posture --validate-only

    # Limit to one schema (partial name match, case-insensitive)
    python3 tools/emit_lifecycle_content.py soc-framework-posture --schema NormalizeMap

    # Roundtrip — regenerate to temp + diff vs shipped
    python3 tools/emit_lifecycle_content.py soc-framework-posture --roundtrip

EXIT
----
    0 if all schemas succeed.
    1 if any schema fails. Failures listed in the summary; processing continues
      across all schemas so you see every failure in one run.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Pack name validation: lowercase letters, digits, hyphens. Must start with a
# letter, can't end with a hyphen. Matches the convention used by every pack
# in Packs/ and prevents shell/path surprises.
PACK_NAME_RE = re.compile(r"^[a-z][a-z0-9-]*[a-z0-9]$")

GENERATOR_REL = Path("tools") / "generate_soc_framework_content.py"


def find_repo_root(start: Path) -> Path:
    """Walk up from `start` looking for tools/generate_soc_framework_content.py."""
    for parent in [start, *start.parents]:
        if (parent / GENERATOR_REL).is_file():
            return parent
    raise SystemExit(
        f"Could not find repo root. Looked for {GENERATOR_REL} from {start} upward. "
        "Run from inside the repo or pass --repo-root."
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "pack",
        help=(
            "Pack name (folder under both schemas/soc-framework/ and Packs/). "
            "E.g. soc-framework-posture, soc-framework-nist-ir."
        ),
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--validate-only",
        action="store_true",
        help="Run validate subcommand only. Don't write list JSON.",
    )
    mode.add_argument(
        "--roundtrip",
        action="store_true",
        help="Run roundtrip subcommand. Regenerates to temp + diffs vs shipped.",
    )
    p.add_argument(
        "--schema",
        default=None,
        help=(
            "Limit to schemas whose filename contains this substring "
            "(case-insensitive). E.g. --schema NormalizeMap."
        ),
    )
    p.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Repo root override. Default: auto-detect from cwd.",
    )
    args = p.parse_args()
    if not PACK_NAME_RE.match(args.pack):
        raise SystemExit(
            f"Invalid pack name '{args.pack}'. Must be lowercase letters, "
            "digits, and hyphens, starting with a letter and not ending with "
            "a hyphen (matches convention of every pack in Packs/)."
        )
    return args


def resolve_subcommand(args: argparse.Namespace) -> str:
    if args.validate_only:
        return "validate"
    if args.roundtrip:
        return "roundtrip"
    return "emit"


def main() -> int:
    args = parse_args()
    repo_root = (args.repo_root or find_repo_root(Path.cwd())).resolve()

    schemas_dir = repo_root / "schemas" / "soc-framework" / args.pack
    pack_root = repo_root / "Packs" / args.pack
    generator = repo_root / GENERATOR_REL

    if not generator.is_file():
        raise SystemExit(f"Generator not found: {generator}")
    if not schemas_dir.is_dir():
        raise SystemExit(
            f"Schemas dir not found: {schemas_dir}\n"
            f"(Have you scaffolded the lifecycle? "
            f"python3 tools/scaffold_lifecycle.py --lifecycle-id <id> ...)"
        )
    if not pack_root.is_dir():
        raise SystemExit(f"Pack root not found: {pack_root}")

    schemas = sorted(schemas_dir.glob("*.yaml"))
    if args.schema:
        needle = args.schema.lower()
        schemas = [s for s in schemas if needle in s.stem.lower()]
        if not schemas:
            raise SystemExit(
                f"No schemas matched --schema '{args.schema}' in {schemas_dir}"
            )
    if not schemas:
        raise SystemExit(f"No *.yaml schemas found in {schemas_dir}")

    subcommand = resolve_subcommand(args)
    needs_pack_root = subcommand in ("emit", "roundtrip")

    print(f"Pack       : {args.pack}")
    print(f"Subcommand : {subcommand}")
    print(f"Schemas dir: {schemas_dir.relative_to(repo_root)}")
    if needs_pack_root:
        print(f"Pack root  : {pack_root.relative_to(repo_root)}")
    print(f"Found      : {len(schemas)} schema(s)")
    print()

    failures: list[Path] = []
    for s in schemas:
        rel = s.relative_to(repo_root)
        print(f"━━━ {rel} ━━━")
        cmd = [
            sys.executable,
            str(generator),
            subcommand,
            "--mapping",
            str(s),
        ]
        if needs_pack_root:
            cmd += ["--pack-root", str(pack_root)]
        result = subprocess.run(cmd, cwd=repo_root)
        if result.returncode != 0:
            failures.append(s)
        print()

    print("─" * 60)
    ok_count = len(schemas) - len(failures)
    print(f"Summary: {ok_count} ok, {len(failures)} failed")
    if failures:
        for s in failures:
            print(f"  FAIL: {s.relative_to(repo_root)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
