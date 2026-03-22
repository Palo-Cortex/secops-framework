#!/usr/bin/env python3
"""
socfw_test_runner.py — SOC Framework test orchestrator.

Reads the regression map and your git diff to determine the minimum
set of tests needed for the change you made. Runs them in order:
  1. Static contract checks (socfw_validate.py)
  2. Unit tests (pytest, <1 second each)
  3. Smoke test checklist (prints warroom commands to run in your tenant)

Usage:
    python3 tools/socfw_test_runner.py                  # full run (pre-merge)
    python3 tools/socfw_test_runner.py --changed-only   # only tests relevant to git diff
    python3 tools/socfw_test_runner.py --stage unit      # unit tests only
    python3 tools/socfw_test_runner.py --stage static    # static checks only
    python3 tools/socfw_test_runner.py --stage smoke     # print smoke test checklist

Exit codes:
    0  — all automated checks passed
    1  — one or more failures
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def get_changed_files() -> list[str]:
    """Get changed files from git diff HEAD and staged."""
    try:
        unstaged = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            capture_output=True, text=True, check=True
        ).stdout.strip()
        staged = subprocess.run(
            ["git", "diff", "--staged", "--name-only"],
            capture_output=True, text=True, check=True
        ).stdout.strip()
        all_files = set()
        for line in (unstaged + "\n" + staged).split("\n"):
            if line.strip():
                all_files.add(line.strip())
        return list(all_files)
    except subprocess.CalledProcessError:
        return []


def match_changed_to_map(changed_files: list[str], regression_map: dict) -> list[str]:
    """Return list of change_pattern keys that match any changed file."""
    matched = set()
    for pattern_key, pattern_data in regression_map.get("change_patterns", {}).items():
        for match_pattern in pattern_data.get("matches", []):
            for changed in changed_files:
                # Match on filename component
                if match_pattern.split("/")[-1] in changed or match_pattern in changed:
                    matched.add(pattern_key)
                    break
    return sorted(matched)


def run_command(cmd: list[str], label: str) -> bool:
    """Run a command. Returns True if it passed."""
    print(f"\n  {CYAN}▶ {label}{RESET}")
    print(f"  {DIM}$ {' '.join(cmd)}{RESET}")
    result = subprocess.run(cmd, capture_output=False)
    if result.returncode == 0:
        print(f"  {GREEN}✅ Passed{RESET}")
        return True
    else:
        print(f"  {RED}❌ Failed (exit {result.returncode}){RESET}")
        return False


def run_static_checks(targets: list[str]) -> bool:
    """Run socfw_validate.py for given targets."""
    tools_dir = Path(__file__).parent
    validate_script = tools_dir / "socfw_validate.py"

    if not validate_script.exists():
        print(f"  {YELLOW}⚠  socfw_validate.py not found at {validate_script}{RESET}")
        return True  # Don't fail if tool not found

    all_passed = True
    for target in targets:
        if target == "--changed-only":
            passed = run_command(
                [sys.executable, str(validate_script), "--changed-only"],
                "Static contract check (changed files)"
            )
        elif target.startswith("--file"):
            # target might have placeholder — skip if so
            if "<changed_file>" in target:
                continue
            passed = run_command(
                [sys.executable, str(validate_script)] + target.split(),
                f"Static contract check: {target}"
            )
        elif target.startswith("--pack"):
            passed = run_command(
                [sys.executable, str(validate_script)] + target.split(),
                f"Static contract check: {target}"
            )
        else:
            continue
        if not passed:
            all_passed = False

    return all_passed


def run_unit_tests(test_paths: list[str]) -> bool:
    """Run pytest for given test files/selectors."""
    if not test_paths:
        return True

    all_passed = True
    for test_path in test_paths:
        # Resolve relative to repo root
        full_path = Path(test_path)
        if not full_path.exists():
            # Try from Packs/ too
            alt = Path("Packs/soc-optimization-unified") / test_path
            if alt.exists():
                full_path = alt
            else:
                print(f"  {YELLOW}⚠  Unit test not found: {test_path} — skipping{RESET}")
                continue

        passed = run_command(
            [sys.executable, "-m", "pytest", str(full_path), "-v", "--tb=short"],
            f"Unit tests: {full_path.name}"
        )
        if not passed:
            all_passed = False

    return all_passed


def print_smoke_checklist(scenarios: list[str], smoke_map: dict, fixture_path: str = "email_chain_test_fixture.json"):
    """Print the warroom commands to run for each smoke scenario."""
    print(f"\n{BOLD}{'─'*60}")
    print(f"🧪 Smoke Test Checklist — Run in XSIAM Tenant")
    print(f"{'─'*60}{RESET}")
    print(f"\n{DIM}Fixture: {fixture_path}")
    print(f"Run these in the XSIAM playground warroom for a new alert.{RESET}\n")

    for scenario_id in scenarios:
        sc = smoke_map.get(scenario_id)
        if not sc:
            print(f"  {YELLOW}⚠  Unknown scenario {scenario_id}{RESET}")
            continue

        print(f"\n{BOLD}[ {scenario_id} ] {sc['description']}{RESET}")

        if sc.get("inject_method") == "manual":
            note = sc.get("note", "")
            print(f"  {YELLOW}Manual test required — no automated fixture.{RESET}")
            if note:
                print(f"  {DIM}{note}{RESET}")
            continue

        print(f"  Playbook: {sc['playbook_to_run']}")
        print(f"  Validates: {', '.join(sc['validates'])}")
        print(f"\n  {BOLD}1. Seed context{RESET} (run each !SetAndHandleEmpty command):")
        print(f"  {DIM}Load fixture: jq '.scenarios[] | select(.id==\"{scenario_id}\") | .context_seed[]' {fixture_path}{RESET}")
        print(f"\n  {BOLD}2. Trigger playbook{RESET}:")
        print(f"  {DIM}!RunPlaybook playbook=\"{sc['playbook_to_run']}\"{RESET}")
        print(f"\n  {BOLD}3. Validate context{RESET}:")
        print(f"  {DIM}!Print value=${{Analysis.Email.verdict}}        → must be '{sc.get('scenario_id', '').replace('SC-0', '')}'{RESET}")
        print(f"  {DIM}!Print value=${{Analysis.Email.response_recommended}}{RESET}")
        print(f"\n  {BOLD}4. Verify Shadow Mode{RESET}:")
        print(f"  {DIM}Run XQL: search dataset=xsiam_socfw_ir_execution_raw | filter alert_id=\"<this_alert>\" | fields action, execution_mode, shadow_mode{RESET}")
        print(f"  {DIM}→ All C/E/R records must show execution_mode=shadow{RESET}")

    print(f"\n{DIM}{'─'*60}")
    print("Full validation checklist: see email_chain_test_fixture.json > validation_checklist")
    print(f"{'─'*60}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="SOC Framework test orchestrator")
    parser.add_argument("--changed-only", action="store_true",
                        help="Only run tests relevant to files changed in git diff")
    parser.add_argument("--stage", choices=["static", "unit", "smoke", "all"],
                        default="all", help="Run only a specific test stage")
    parser.add_argument("--map", default="tools/regression_map.json",
                        help="Path to regression_map.json")
    args = parser.parse_args()

    # Load regression map
    map_path = Path(args.map)
    if not map_path.exists():
        print(f"{RED}Error: regression_map.json not found at {map_path}{RESET}", file=sys.stderr)
        sys.exit(2)

    regression_map = json.loads(map_path.read_text())

    print(f"\n{BOLD}SOC Framework — Test Runner{RESET}")
    print("─" * 60)

    # Determine what to test
    if args.changed_only:
        changed = get_changed_files()
        if not changed:
            print(f"{YELLOW}No changed files detected in git diff.{RESET}")
            print("Running always-run checks only.")
            matched_patterns = []
        else:
            print(f"Changed files ({len(changed)}):")
            for f in sorted(changed):
                print(f"  {DIM}{f}{RESET}")
            matched_patterns = match_changed_to_map(changed, regression_map)
            if matched_patterns:
                print(f"\nMatched regression patterns: {', '.join(matched_patterns)}")
            else:
                print(f"\n{YELLOW}No regression patterns matched — running always-run checks only{RESET}")
    else:
        # Full run — collect all patterns
        matched_patterns = list(regression_map.get("change_patterns", {}).keys())
        print(f"Full run — all {len(matched_patterns)} patterns")

    # Build test sets from matched patterns
    static_targets = set()
    unit_tests = set()
    smoke_scenarios = set()

    # Always-run items
    always = regression_map.get("always_run", {})
    for target in always.get("static", []):
        static_targets.add(target)
    for test in always.get("unit", []):
        unit_tests.add(test)

    # Pattern-matched items
    for pattern_key in matched_patterns:
        pattern = regression_map["change_patterns"][pattern_key]
        run = pattern.get("run", {})
        for target in run.get("static", []):
            static_targets.add(target)
        for test in run.get("unit", []):
            unit_tests.add(test)
        for sc in run.get("smoke", []):
            smoke_scenarios.add(sc)

    total_failures = 0

    # ── Static ────────────────────────────────────────────────────────────────
    if args.stage in ("static", "all"):
        print(f"\n{BOLD}Stage 1 — Static Contract Checks{RESET}")
        if static_targets:
            if not run_static_checks(list(static_targets)):
                total_failures += 1
        else:
            print(f"  {DIM}No static checks for this change set{RESET}")

    # ── Unit ──────────────────────────────────────────────────────────────────
    if args.stage in ("unit", "all"):
        print(f"\n{BOLD}Stage 2 — Unit Tests{RESET}")
        if unit_tests:
            if not run_unit_tests(list(unit_tests)):
                total_failures += 1
        else:
            print(f"  {DIM}No unit tests for this change set{RESET}")

    # ── Smoke ─────────────────────────────────────────────────────────────────
    if args.stage in ("smoke", "all") and smoke_scenarios:
        print(f"\n{BOLD}Stage 3 — Smoke Test Checklist{RESET}")
        print_smoke_checklist(
            sorted(smoke_scenarios),
            regression_map.get("smoke_scenarios", {}),
        )
        print(f"{YELLOW}⚠  Smoke tests require manual tenant execution — not counted in exit code{RESET}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    if total_failures == 0:
        print(f"{GREEN}{BOLD}✅ All automated checks passed{RESET}")
        if smoke_scenarios:
            print(f"{YELLOW}   Run the smoke checklist above in your dev tenant before merging.{RESET}")
    else:
        print(f"{RED}{BOLD}❌ {total_failures} stage(s) failed — fix before uploading{RESET}")

    sys.exit(0 if total_failures == 0 else 1)


if __name__ == "__main__":
    main()
