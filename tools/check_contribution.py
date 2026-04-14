#!/usr/bin/env python3
"""
check_contribution.py
─────────────────────────────────────────────────────────────────────────────
Pre-merge contribution validation orchestrator.

Runs the full SOC Framework contribution check chain against all packs
changed on the current branch. This is the single entry point for both
local development and CI — the same command, the same output, the same
exit code in both environments.

WORKFLOW
────────
  1. normalize_contribution.py   Strip UI export artifacts, rename to canonical
                                 filename, place in correct directory structure.
  2. correlation_rule_preflight   Validate correlation rule YAML and script .py
                                 files against known platform gotchas that the
                                 SDK does not catch (empty mitre_defs, missing
                                 null fields, empty .py files, MITRE mappings).
  3. pack_prep.py                SDK validation, xsoar_config JSON integrity,
                                 cross-pack dependency version check.
  4. fix_errors.py (report)      Report BA101/BA106 issues without auto-fixing.
                                 Errors here mean normalize didn't catch something
                                 — useful signal for improving the pipeline.
  5. check_contracts.py          Layer contract violations — setIssue from
                                 Workflow, wrong namespace writes, missing
                                 Lifecycle phase boundaries.
  6. validate_shadow_mode.py     Shadow mode consistency across all UC actions.
  7. upload_package.sh           Deploy changed packs to review tenant.
                                 Runs in both local and CI — credentials come
                                 from .env locally, GitHub Secrets in CI.
                                 Includes platform health check — aborts if
                                 API endpoints are unhealthy.

EXIT CODES
──────────
  0  All checks passed. Upload succeeded (or skipped with --no-upload).
  1  One or more checks failed. Review output before merging.

SCOPE
─────
By default, git diff origin/main finds the changed packs automatically.
Use --input to target a specific pack when not on a branch.

Usage:
  # Full run — find changed packs from git diff, validate and upload
  python3 tools/check_contribution.py

  # Dry run — validate only, skip upload
  python3 tools/check_contribution.py --no-upload

  # Target a specific pack
  python3 tools/check_contribution.py --input Packs/soc-framework-nist-ir

  # CI mode — same as default but formats output for GitHub Actions annotations
  python3 tools/check_contribution.py --ci
"""

import argparse
import subprocess
import sys
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# ANSI colour helpers
# ─────────────────────────────────────────────────────────────────────────────

_TTY = sys.stdout.isatty()

def _c(code, t):  return f"\033[{code}m{t}\033[0m" if _TTY else t
def OK(t):   return _c("32;1", t)
def ERR(t):  return _c("31;1", t)
def WARN(t): return _c("33;1", t)
def INFO(t): return _c("36",   t)
def BOLD(t): return _c("1",    t)
def DIM(t):  return _c("2",    t)
def STEP(t): return _c("35;1", t)


# ─────────────────────────────────────────────────────────────────────────────
# Git integration — find changed packs
# ─────────────────────────────────────────────────────────────────────────────

def _git_diff_packs(base: str, diff_filter: str) -> list[Path]:
    """Return pack directories matching the given git diff filter."""
    try:
        result = subprocess.run(
            ["git", "diff", base, "--name-only", f"--diff-filter={diff_filter}"],
            capture_output=True, text=True, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    packs: dict[str, Path] = {}
    for line in result.stdout.splitlines():
        p = Path(line.strip())
        if p.parts and p.parts[0] == "Packs" and len(p.parts) > 1:
            pack_name = p.parts[1]
            pack_path = Path("Packs") / pack_name
            if (pack_path / "pack_metadata.json").exists():
                packs[pack_name] = pack_path

    return sorted(packs.values())


def git_changed_packs(base: str = "origin/main") -> list[Path]:
    """
    Return pack directories that have added or modified files on this branch.

    Uses --diff-filter=ACMR to exclude deletions — removing a file from a
    pack doesn't constitute a contribution that needs validating.
    """
    return _git_diff_packs(base, "ACMR")


def git_new_packs(base: str = "origin/main") -> list[Path]:
    """
    Return pack directories that have genuinely new (Added) files only.

    Used to scope normalize_contribution — running normalize on modified
    existing files would strip content that is already correctly structured.
    Only new additions need normalization.
    """
    return _git_diff_packs(base, "A")


# ─────────────────────────────────────────────────────────────────────────────
# Step runner — executes a tool and captures result
# ─────────────────────────────────────────────────────────────────────────────

class StepResult:
    def __init__(self, name: str, rc: int, output: str):
        self.name   = name
        self.rc     = rc
        self.output = output

    @property
    def passed(self) -> bool:
        return self.rc == 0


def run_step(
    name: str,
    cmd: list[str],
    ci_mode: bool = False,
    allow_fail: bool = False,
) -> StepResult:
    """
    Run a single pipeline step, stream output to stdout, and return a result.

    allow_fail: if True, a non-zero exit code is treated as a warning rather
                than a hard failure (used for fix_errors report-only mode).
    """
    print(f"\n  {STEP('▶')}  {BOLD(name)}")
    print(f"     {DIM(' '.join(str(c) for c in cmd))}")
    print()

    result = subprocess.run(cmd, text=True)

    if result.returncode == 0:
        print(f"\n  {OK('✓')}  {name} passed")
    elif allow_fail:
        print(f"\n  {WARN('⚠')}  {name} reported issues (non-blocking)")
    else:
        print(f"\n  {ERR('✗')}  {name} FAILED")
        if ci_mode:
            # GitHub Actions error annotation
            print(f"::error::{name} failed — see output above")

    return StepResult(name, result.returncode if not allow_fail else 0, "")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOC Framework pre-merge contribution validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--input", "-i", default=None,
        help="Specific pack directory to validate (default: git diff scope)",
    )
    parser.add_argument(
        "--base", default="origin/main",
        help="Git base ref for diff (default: origin/main)",
    )
    parser.add_argument(
        "--no-upload", action="store_true",
        help="Skip upload to review tenant (validate only)",
    )
    parser.add_argument(
        "--ci", action="store_true",
        help="CI mode — emit GitHub Actions annotations",
    )
    args = parser.parse_args()

    # ── Resolve packs to validate ─────────────────────────────────────────────
    if args.input:
        input_path = Path(args.input)
        if not input_path.exists():
            print(ERR(f"✗ not found: {input_path}"))
            sys.exit(1)
        if not (input_path / "pack_metadata.json").exists():
            print(ERR(f"✗ not a pack directory (no pack_metadata.json): {input_path}"))
            sys.exit(1)
        packs = [input_path]
    else:
        packs = git_changed_packs(args.base)

    # ── Header ────────────────────────────────────────────────────────────────
    print()
    print("━" * 62)
    print("  check_contribution.py — SOC Framework pre-merge validator")
    if args.input:
        print(f"  scope  : {INFO(str(args.input))}")
    else:
        print(f"  scope  : {INFO(f'git diff {args.base}')}")
    if args.no_upload:
        print(f"  upload : {WARN('skipped (--no-upload)')}")
    print("━" * 62)

    if not packs:
        print(WARN("\n  No changed packs found."))
        print(DIM(
            "  Run 'git fetch origin' if you expected changes,\n"
            "  or use --input <pack> to target a specific pack."
        ))
        sys.exit(0)

    print(f"\n  {len(packs)} pack(s) in scope: "
          + ", ".join(INFO(p.name) for p in packs))

    # ── Step 1: Normalize ─────────────────────────────────────────────────────
    # Only runs on genuinely new (Added) files — never on modifications to
    # existing content. Running normalize on modified files strips structure
    # that was already correct when the content was first contributed.
    results: list[StepResult] = []

    if args.input:
        # Explicit pack: always normalize — caller knows what they're doing
        normalize_cmd = [sys.executable, "tools/normalize_contribution.py",
                         "--input", str(args.input)]
        results.append(run_step("Normalize contribution", normalize_cmd, args.ci))
    else:
        new_packs = git_new_packs(args.base)
        if new_packs:
            # New files found — normalize each pack that has additions
            for new_pack in new_packs:
                normalize_cmd = [sys.executable, "tools/normalize_contribution.py",
                                  "--input", str(new_pack)]
                results.append(run_step(
                    f"Normalize contribution — {new_pack.name}",
                    normalize_cmd, args.ci,
                ))
        else:
            print(f"\n  {OK('✓')}  Normalize — no new files (modifications only, skipped)")

    # ── Per-pack steps ────────────────────────────────────────────────────────
    for pack in packs:
        print(f"\n{'─' * 62}")
        print(f"  Pack: {BOLD(pack.name)}")
        print(f"{'─' * 62}")

        # ── Step 2: correlation_rule_preflight ────────────────────────────────
        preflight_script = Path("tools/correlation_rule_preflight.py")
        if preflight_script.exists():
            results.append(run_step(
                f"correlation_rule_preflight — {pack.name}",
                [sys.executable, str(preflight_script), str(pack)],
                args.ci,
            ))

        # ── Step 3: pack_prep ─────────────────────────────────────────────────
        results.append(run_step(
            f"pack_prep — {pack.name}",
            [sys.executable, "tools/pack_prep.py", str(pack)],
            args.ci,
        ))

        # ── Step 4: fix_errors (report only) ──────────────────────────────────
        # fix_errors reads from output/sdk_errors.txt produced by pack_prep.
        # We run it in report mode — it prints what it would fix but makes no
        # changes. If it fires, normalize missed something worth investigating.
        sdk_errors = Path("output/sdk_errors.txt")
        if sdk_errors.exists() and sdk_errors.stat().st_size > 0:
            results.append(run_step(
                f"fix_errors report — {pack.name}",
                [sys.executable, "tools/fix_errors.py", str(sdk_errors), "--dry-run"],
                args.ci,
                allow_fail=True,   # report only — not a hard block
            ))
        else:
            print(f"\n  {OK('✓')}  fix_errors — no SDK errors to report")

        # ── Step 5: check_contracts ───────────────────────────────────────────
        results.append(run_step(
            f"check_contracts — {pack.name}",
            [sys.executable, "tools/check_contracts.py", "--input", str(pack)],
            args.ci,
        ))

    # ── Step 6: validate_shadow_mode (once, --all) ────────────────────────────
    # Always runs across the entire framework — shadow mode consistency is a
    # global property, not per-pack. One broken action affects every playbook.
    print(f"\n{'─' * 62}")
    print(f"  Framework-wide checks")
    print(f"{'─' * 62}")

    results.append(run_step(
        "validate_shadow_mode --all",
        [sys.executable, "tools/validate_shadow_mode.py", "--all"],
        args.ci,
    ))

    # ── Step 7: upload ────────────────────────────────────────────────────────
    if not args.no_upload:
        for pack in packs:
            results.append(run_step(
                f"upload — {pack.name}",
                ["bash", "tools/upload_package.sh", str(pack)],
                args.ci,
            ))
    else:
        print(f"\n  {DIM('⊘  Upload skipped (--no-upload)')}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("━" * 62)
    failures = [r for r in results if not r.passed]

    if not failures:
        print(OK(f"  ✓ All checks passed — {len(packs)} pack(s) validated"))
        if not args.no_upload:
            print(OK(f"  ✓ Uploaded to tenant — review and open PR"))
    else:
        print(ERR(f"  ✗ {len(failures)} check(s) failed:"))
        for f in failures:
            print(ERR(f"      • {f.name}"))
        print()
        print(DIM("  Fix the errors above before opening a PR."))

    print("━" * 62)
    print()

    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
