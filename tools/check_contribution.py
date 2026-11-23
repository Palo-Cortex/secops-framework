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
  2.5. playbook_condition_lint   Validate playbook YAML for patterns that parse
                                 cleanly but silently fail at runtime — broken
                                 ${X / Y} context interpolations and
                                 AND-impossible condition blocks.
  3. pack_prep.py                SDK validation, xsoar_config JSON integrity,
                                 cross-pack dependency version check.
  4. fix_errors.py (report)      Report BA101/BA106 issues without auto-fixing.
                                 Errors here mean normalize didn't catch something
                                 — useful signal for improving the pipeline.
  5. check_contracts.py          Layer contract violations — setIssue from
                                 Workflow, wrong namespace writes, missing
                                 Lifecycle phase boundaries.
  5a. run_pack_tests.py          The pack's unit tests, one pytest process per
                                 file (the PR gate runs the same).
  5d. check_action_args.py       Every vendor response in SOCFrameworkActions_V3
                                 against the command's arguments in
                                 policies/vendor_command_specs.json.
  6. validate_shadow_mode.py     Shadow mode consistency across all UC actions.
  7. prep_docs.py --check        Documentation drift gate — wraps the four
                                 doc generators (pack overviews, schema docs,
                                 mkdocs nav, home page). Fails if a schema or
                                 pack edit lands without regenerating docs.
  8. upload_package.sh           Deploy changed packs to review tenant.
  9. verify_tenant_content.py    Confirm the upload did not remove other packs' content.
                                 Runs in both local and CI — credentials come
                                 from povkit exec locally, GitHub Secrets in CI.
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
  python3 tools/check_contribution.py --input Packs/soc-framework-nist-ir-ai

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


def packs_with_contributor_copies() -> list[Path]:
    """
    Return pack directories that contain any `*_copy.yml` or `*_copy.json`.

    `_copy` is the contributor convention for submitting a replacement
    playbook or list. XSIAM's "Save a Copy" bakes `_copy` into both the
    filename AND the internal id/name fields, so a committed _copy file
    won't be caught by a content-hash duplicate check — the id and name
    differ from the canonical file.

    normalize_contribution.py is the only thing that knows how to merge:
    it strips the _copy suffix from internal fields, writes the result
    to the canonical filename, and deletes the _copy. If a _copy is
    still on disk after normalize, that pack was never in normalize's
    scope — usually because the _copy file was committed on a previous
    branch rather than added on the current one.

    This helper forces any pack with a lingering _copy file back into
    the normalize scope regardless of git diff.
    """
    packs: dict[str, Path] = {}
    root = Path("Packs")
    if not root.is_dir():
        return []
    for pattern in ("*_copy.yml", "*_copy.json"):
        for p in root.rglob(pattern):
            try:
                idx = p.parts.index("Packs")
                pack_name = p.parts[idx + 1]
                pack_path = Path("Packs") / pack_name
                if (pack_path / "pack_metadata.json").exists():
                    packs[pack_name] = pack_path
            except (ValueError, IndexError):
                continue
    return sorted(packs.values())


# ─────────────────────────────────────────────────────────────────────────────
# Step runner — executes a tool and captures result
# ─────────────────────────────────────────────────────────────────────────────

class StepResult:
    def __init__(self, name: str, rc: int, output: str, remediation: str = ""):
        self.name        = name
        self.rc          = rc
        self.output      = output
        self.remediation = remediation

    @property
    def passed(self) -> bool:
        return self.rc == 0


def run_step(
    name: str,
    cmd: list[str],
    ci_mode: bool = False,
    allow_fail: bool = False,
    remediation: str = "",
) -> StepResult:
    """
    Run a single pipeline step, stream output to stdout, and return a result.

    allow_fail: if True, a non-zero exit code is treated as a warning rather
                than a hard failure (used for fix_errors report-only mode).
    remediation: human-readable instruction on how to repair a failure of this
                 check — echoed in the halt summary so the fix command sits
                 right next to the check name, not buried 200 lines above in
                 the streamed tool output.
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

    return StepResult(
        name,
        result.returncode if not allow_fail else 0,
        "",
        remediation,
    )


def abort_if_failed(results: list, gate_name: str) -> None:
    """Bail out immediately if any step in results failed.

    Called at pipeline gates where continuing would be a waste of time —
    e.g. no point running pack_prep if normalize failed, no point
    uploading if validation failed.
    """
    failures = [r for r in results if not r.passed]
    if not failures:
        return
    print()
    print("━" * 62)
    print(ERR(f"  ✗ Halting at gate: {gate_name}"))
    print(ERR(f"  ✗ {len(failures)} blocking failure(s):"))
    print()
    for f in failures:
        print(ERR(f"      • {f.name}"))
        if f.remediation:
            # Print each remediation line indented under the failed check name
            # so the fix instruction sits right next to what needs fixing,
            # not buried in 200 lines of streamed tool output above.
            for line in f.remediation.splitlines():
                print(f"        {DIM(line)}")
            print()
    print(DIM("  Upload skipped — nothing to deploy with broken content."))
    print("━" * 62)
    print()
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    """The gate's command line."""
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
    return parser.parse_args()


def _packs_in_scope(args: argparse.Namespace) -> list[Path]:
    """The pack named by --input, or the packs this branch changes. Exits on an --input that is not a pack."""
    if not args.input:
        return git_changed_packs(args.base)
    input_path = Path(args.input)
    if not input_path.exists():
        print(ERR(f"✗ not found: {input_path}"))
        sys.exit(1)
    if not (input_path / "pack_metadata.json").exists():
        print(ERR(f"✗ not a pack directory (no pack_metadata.json): {input_path}"))
        sys.exit(1)
    return [input_path]


def _print_header(args: argparse.Namespace) -> None:
    """The banner: what is in scope and whether it uploads."""
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


def _packs_to_normalize(base: str) -> list[Path]:
    """Packs with new files on this branch, then any other pack holding a contributor _copy file.

    Both signals mean "there's content here that needs to be merged into
    canonical form before anything downstream runs." The second catches the
    case where a _copy file was committed on a previous branch and never
    processed — git diff won't flag it as new, but it still needs normalize to
    collapse it into the canonical file.
    """
    packs = list(git_new_packs(base))
    for p in packs_with_contributor_copies():
        if p not in packs:
            packs.append(p)
    return packs


def _normalize_step(target: str | Path, name: str, ci_mode: bool) -> StepResult:
    """Run normalize_contribution on one pack."""
    return run_step(
        name,
        [sys.executable, "tools/normalize_contribution.py", "--input", str(target)],
        ci_mode,
        remediation=(
            "Normalize output above names the offending file(s). Common causes:\n"
            "  • MISLOCATION — file in wrong directory (move as instructed)\n"
            "  • missing/empty file — re-export from tenant\n"
            "  • non-UTF-8 encoding — re-export from tenant\n"
            "Re-run:\n"
            f"  python3 tools/normalize_contribution.py --input {target}"
        ),
    )


def _normalize(args: argparse.Namespace) -> list[StepResult]:
    """Step 1: merge new and _copy content into canonical form before anything else reads it.

    An explicit --input pack is always normalized; the caller knows what they
    are doing. Otherwise only packs with new files or a lingering _copy file.
    """
    if args.input:
        return [_normalize_step(args.input, "Normalize contribution", args.ci)]
    packs = _packs_to_normalize(args.base)
    if not packs:
        print(f"\n  {OK('✓')}  Normalize — no new files or _copy artifacts (skipped)")
        return []
    return [_normalize_step(pack, f"Normalize contribution — {pack.name}", args.ci) for pack in packs]


def _optional_steps(pack: Path, base: str, ci_mode: bool) -> list[StepResult]:
    """Steps 2 to 2.5: the per-pack checks whose tools may be absent from an older checkout."""
    results = []
    preflight_script = Path("tools/correlation_rule_preflight.py")
    if preflight_script.exists():
        results.append(run_step(
            f"correlation_rule_preflight — {pack.name}",
            # --tenant validates each changed rule's XQL against the live
            # dataset schema. A field the tenant does not know fails the pack
            # install as a bare 101704 with no field name, which every static
            # check misses (soc-crowdstrike-saas shipped broken this way).
            # --changed-only keeps it off the tenant unless a rule moved.
            [sys.executable, str(preflight_script), str(pack),
             "--tenant", "--changed-only", base],
            ci_mode,
            remediation=(
                "Preflight output above names the offending rule(s) and field(s).\n"
                "If it reports fields missing from the tenant dataset schema, the\n"
                "pack install will fail with 101704. When the tenant simply has no\n"
                "data for that product, read those fields from rawJSON and alias\n"
                "back to the canonical names — see the compatibility shim in\n"
                "schemas/vendors/crowdstrike-saas (7 fields) or crowdstrike-idp (11).\n"
                "Common fixes per SOC Framework correlation rule schema rules:\n"
                "  • remove top-level 'rule_id: 0'\n"
                "  • add 'fromversion: 8.0.0' (unquoted)\n"
                "  • both 'id:' and 'ruleid:' must be present, same value\n"
                "  • 'alert_category: User Defined' (not 'OTHER')\n"
                "Re-run after editing:\n"
                f"  python3 tools/correlation_rule_preflight.py {pack}"
            ),
        ))

    # A rule that writes into an issue field the platform owns (hostos, the
    # run-state fields) saves, installs and alerts without error, but left
    # about half the issues in a burst with their playbook never started.
    field_check = Path("tools/check_issue_field_targets.py")
    if field_check.exists():
        results.append(run_step(
            f"issue-field targets — {pack.name}",
            [sys.executable, str(field_check), str(pack)],
            ci_mode,
            remediation=(
                "Remove the named mapping from the vendor contract\n"
                "(schemas/vendors/<vendor>/<contract>.yaml), re-emit the rule with\n"
                "tools/generate_vendor_content.py emit, and gate again. The blocked\n"
                "list and the reason for each field: policies/restricted_issue_fields.json"
            ),
        ))

    # Catches playbook YAML patterns that parse cleanly but silently fail:
    # broken ${X / Y} context interpolations and AND-impossible conditions.
    # The XSIAM Playbook Editor UI prevents these by construction; hand-written
    # YAML bypasses that guardrail.
    condition_lint = Path("tools/playbook_condition_lint.py")
    if condition_lint.exists():
        results.append(run_step(
            f"playbook_condition_lint — {pack.name}",
            [sys.executable, str(condition_lint), str(pack), "--quiet"],
            ci_mode,
            remediation=(
                "Auto-fix available for stale-numeric-key issues:\n"
                f"  python3 tools/playbook_condition_lint.py {pack} --fix\n"
                "Other findings (broken interpolations, AND-impossible conditions,\n"
                "broken task refs, duplicate content) require manual review — see\n"
                "the tool output above for file paths and offending lines."
            ),
        ))
    return results


def _fix_errors_report(pack: Path, ci_mode: bool) -> list[StepResult]:
    """Step 4: what fix_errors would change in pack_prep's SDK errors, reported and never blocking.

    It runs in report mode and makes no changes. If it fires, normalize missed
    something worth investigating.
    """
    sdk_errors = Path("output/sdk_errors.txt")
    if not (sdk_errors.exists() and sdk_errors.stat().st_size > 0):
        print(f"\n  {OK('✓')}  fix_errors — no SDK errors to report")
        return []
    return [run_step(
        f"fix_errors report — {pack.name}",
        [sys.executable, "tools/fix_errors.py", str(sdk_errors), "--dry-run"],
        ci_mode,
        allow_fail=True,
    )]


def _pack_checks(pack: Path, base: str, ci_mode: bool) -> list[StepResult]:
    """Steps 2 to 5b for one pack, in order."""
    print(f"\n{'─' * 62}")
    print(f"  Pack: {BOLD(pack.name)}")
    print(f"{'─' * 62}")

    results = _optional_steps(pack, base, ci_mode)
    results.append(run_step(
        f"pack_prep — {pack.name}",
        [sys.executable, "tools/pack_prep.py", str(pack)],
        ci_mode,
        remediation=(
            "pack_prep chains several checks (rule ID normalization, JSON\n"
            "validity, dependency versions, xsoar_config preflight, SDK validate).\n"
            "Review the output above for which sub-step failed and its specific\n"
            "error. The SDK validate output is written to:\n"
            "  output/sdk_errors.txt\n"
            "Auto-fixes for common BA101/BA106/PA128 errors:\n"
            "  python3 tools/fix_errors.py output/sdk_errors.txt"
        ),
    ))
    results.extend(_fix_errors_report(pack, ci_mode))
    results.append(run_step(
        f"check_contracts — {pack.name}",
        [sys.executable, "tools/check_contracts.py", "--input", str(pack)],
        ci_mode,
        remediation=(
            "check_contracts validates SOC Framework layer contracts: EP vs\n"
            "Lifecycle, Foundation vs Workflow, context key namespaces. Review\n"
            "the output above — it names the specific playbook and contract\n"
            "violation. Fix by editing the playbook to match the expected\n"
            "namespace or call pattern, then re-run:\n"
            f"  python3 tools/check_contracts.py --input {pack}"
        ),
    ))
    # The pack's test files, each in its own pytest process - the same
    # runner the PR gate uses, so a branch that passes here passes there.
    results.append(run_step(
        f"unit tests — {pack.name}",
        [sys.executable, "tools/run_pack_tests.py", pack.name],
        ci_mode,
        remediation=(
            "A test file in this pack failed or ran no tests. The output above\n"
            "names it. Run that file on its own from its directory to see the\n"
            "failure, fix the code or the test, then re-run:\n"
            f"  python3 tools/run_pack_tests.py {pack.name}"
        ),
    ))
    # A script, list or list key added to a pack must be mentioned in the
    # pack's README, docs/capabilities.yml, or a hand-authored page under
    # docs/<pack>/. Only packs whose README carries the capabilities
    # markers are gated; the script skips the rest.
    results.append(run_step(
        f"check_readme_coverage — {pack.name}",
        [sys.executable, "tools/check_readme_coverage.py", str(pack)],
        ci_mode,
        remediation=(
            "Something this branch adds to the pack is not documented.\n"
            "The output above names it. Add it to the capability page it\n"
            "belongs to (docs/<pack>/*.md), to docs/capabilities.yml, or to\n"
            "the pack README, then re-run:\n"
            f"  python3 tools/check_readme_coverage.py {pack}"
        ),
    ))
    return results


def _repo_checks(ci_mode: bool) -> list[StepResult]:
    """Steps 5c to 7: the checks that run once over the whole repository, not per pack."""
    # The AI Prompt recipes live in the private socfw-nist-ir-ai repo. Fail
    # before anything else if a recipe path or a prompt fingerprint is here.
    results = [run_step(
        "check_private_content",
        [sys.executable, "tools/check_private_content.py"],
        ci_mode,
        remediation=(
            "Private content (an AI Prompt recipe, AI_PROMPTS.md, or a file carrying a\n"
            "prompt fingerprint) is in the public tree. Remove it; the recipes belong in\n"
            "Palo-Cortex/socfw-nist-ir-ai. Patterns: policies/private_content.json."
        ),
    )]

    # Every response in SOCFrameworkActions_V3 against the commands the vendors
    # define (policies/vendor_command_specs.json). A wrong argument name only
    # shows up the first time an action runs live, so it is caught here.
    results.append(run_step(
        "check_action_args",
        [sys.executable, "tools/check_action_args.py"],
        ci_mode,
        remediation=(
            "A response in SOCFrameworkActions_V3 names a command or argument the vendor\n"
            "does not have. Fix the mapping. If you mapped a new command, rebuild the spec\n"
            "file first: python3 tools/build_command_specs.py --content <demisto/content checkout>"
        ),
    ))

    print(f"\n{'─' * 62}")
    print("  Framework-wide checks")
    print(f"{'─' * 62}")

    # Shadow mode consistency is a global property, not per-pack. One broken
    # action affects every playbook.
    results.append(run_step(
        "validate_shadow_mode --all",
        [sys.executable, "tools/validate_shadow_mode.py", "--all"],
        ci_mode,
        remediation=(
            "Shadow mode is the PoV safety contract — actions must be gated.\n"
            "Output above names the playbook and task where an action runs with\n"
            "shadow_mode=false outside the approved policy exemptions. Fix options:\n"
            "  • set shadow_mode: true for the action in SOCFrameworkActions_V3\n"
            "  • add the action to shadow_mode_policy.json with a documented reason\n"
            "    (only for genuinely read-only or sandbox-only actions)\n"
            "Re-run:\n"
            "  python3 tools/validate_shadow_mode.py --all"
        ),
    ))

    # Drift gate for the MkDocs site. Wraps four generators that read schemas,
    # pack metadata, and pack_catalog.json to produce docs/ and mkdocs.yml. A
    # schema or pack edit without a doc regen will fail here. Runs after
    # validate_shadow_mode so structural failures surface as themselves
    # (a broken schema would otherwise show up as a docs failure first).
    # Sits before the upload gate so a stale-docs PR fails CI without
    # burning a tenant deploy.
    results.append(run_step(
        "prep_docs --check",
        [sys.executable, "tools/prep_docs.py", "--check"],
        ci_mode,
        remediation=(
            "Documentation generators detected drift between committed docs/\n"
            "and what the generators would produce from current schemas, pack\n"
            "metadata, and pack_catalog.json. Regenerate locally:\n"
            "  python3 tools/prep_docs.py\n"
            "Then commit the resulting changes under docs/ and mkdocs.yml\n"
            "alongside the schema or pack edit that triggered them."
        ),
    ))
    return results


def _upload(packs: list[Path], args: argparse.Namespace) -> list[StepResult]:
    """Step 8: deploy each pack to the review tenant, then check no other pack's content went missing."""
    if args.no_upload:
        print(f"\n  {DIM('⊘  Upload skipped (--no-upload)')}")
        return []
    results = [run_step(f"upload — {pack.name}", ["bash", "tools/upload_package.sh", str(pack)], args.ci)
               for pack in packs]
    # --override-existing makes a pack's changes land, and on this tenant it can
    # also remove another pack's content. Silent when it happens; surfaces hours
    # later as a missing script or an unparseable list. Check while the cause is
    # still obvious.
    results.append(run_step(
        "verify tenant content",
        ["python3", "tools/verify_tenant_content.py", *[str(p) for p in packs]],
        args.ci,
    ))
    return results


def _summary(results: list[StepResult], packs: list[Path], uploaded: bool) -> int:
    """Print the outcome and return the exit code: 0 when every step passed."""
    print()
    print("━" * 62)
    failures = [r for r in results if not r.passed]

    if not failures:
        print(OK(f"  ✓ All checks passed — {len(packs)} pack(s) validated"))
        if uploaded:
            print(OK("  ✓ Uploaded to tenant — review and open PR"))
    else:
        print(ERR(f"  ✗ {len(failures)} check(s) failed:"))
        for f in failures:
            print(ERR(f"      • {f.name}"))
        print()
        print(DIM("  Fix the errors above before opening a PR."))

    print("━" * 62)
    print()
    return 0 if not failures else 1


def main() -> None:
    """Validate the changed packs, stop at the first gate that fails, and upload what passes."""
    args = _parse_args()
    packs = _packs_in_scope(args)
    _print_header(args)

    if not packs:
        print(WARN("\n  No changed packs found."))
        print(DIM(
            "  Run 'git fetch origin' if you expected changes,\n"
            "  or use --input <pack> to target a specific pack."
        ))
        sys.exit(0)

    print(f"\n  {len(packs)} pack(s) in scope: "
          + ", ".join(INFO(p.name) for p in packs))

    # pack_prep and everything downstream assumes normalized content.
    results = _normalize(args)
    abort_if_failed(results, "normalize")

    for pack in packs:
        results.extend(_pack_checks(pack, args.base, args.ci))
    results.extend(_repo_checks(args.ci))

    # No point shipping content that's known-broken. Halt here so the user fixes
    # issues locally instead of waiting for the upload to fail (or worse,
    # succeed and silently break the tenant).
    abort_if_failed(results, "pre-upload validation")

    results.extend(_upload(packs, args))
    sys.exit(_summary(results, packs, uploaded=not args.no_upload))


if __name__ == "__main__":
    main()
