#!/usr/bin/env python3
"""
check_foundation_continueonerror.py
====================================
SOC Framework CI guard — Foundation playbook continueonerror enforcement.

Rule: Every `regular` and `playbook` type task in any Foundation playbook
MUST have `continueonerror: true`. Foundation playbooks can never stop
the alert processing chain. This is architecture rule #1.

Usage:
    # Check all Foundation playbooks in a pack:
    python3 tools/check_foundation_continueonerror.py --pack Packs/soc-optimization-unified

    # Check a single file:
    python3 tools/check_foundation_continueonerror.py --file Packs/.../Foundation_-_Upon_Trigger_V3.yml

    # CI mode — exits 1 on any violation:
    python3 tools/check_foundation_continueonerror.py --pack Packs/soc-optimization-unified --ci

    # Also check non-Foundation playbooks (advisory, not blocking):
    python3 tools/check_foundation_continueonerror.py --pack Packs/soc-optimization-unified --all

Exit codes:
    0  No violations found
    1  Violations found (or --ci flag and violations present)
    2  Usage/file error
"""

import argparse
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip install pyyaml --break-system-packages")
    sys.exit(2)

# Task types that MUST have continueonerror: true in Foundation playbooks
ENFORCED_TYPES = {"regular", "playbook"}

# Task types that are exempt (structural, no execution risk)
EXEMPT_TYPES = {"start", "title", "condition", "section", "end"}

# Playbook name prefix that triggers enforcement
FOUNDATION_PREFIX = "Foundation_-_"

ANSI_RED   = "\033[91m"
ANSI_YELLOW= "\033[93m"
ANSI_GREEN = "\033[92m"
ANSI_CYAN  = "\033[96m"
ANSI_RESET = "\033[0m"
ANSI_BOLD  = "\033[1m"


def check_playbook(filepath: Path, enforce: bool = True) -> list[dict]:
    """
    Parse a playbook YAML and return a list of violation dicts.
    Each dict: {file, task_id, task_name, task_type}
    """
    violations = []
    try:
        with open(filepath) as f:
            content = f.read()
        pb = yaml.safe_load(content)
    except yaml.YAMLError as e:
        print(f"{ANSI_RED}YAML PARSE ERROR{ANSI_RESET} {filepath.name}: {e}")
        return []
    except OSError as e:
        print(f"{ANSI_RED}FILE ERROR{ANSI_RESET} {filepath}: {e}")
        return []

    if not isinstance(pb, dict):
        return []

    tasks = pb.get("tasks", {})
    if not isinstance(tasks, dict):
        return []

    for tid, task in tasks.items():
        if not isinstance(task, dict):
            continue
        ttype = task.get("type", "")
        if ttype not in ENFORCED_TYPES:
            continue
        has_coe = task.get("continueonerror", False)
        if not has_coe:
            task_name = task.get("task", {}).get("name", f"<task_{tid}>")
            violations.append({
                "file": filepath.name,
                "filepath": str(filepath),
                "task_id": str(tid),
                "task_name": task_name,
                "task_type": ttype,
            })

    return violations


def find_playbooks(pack_dir: Path, foundation_only: bool = True) -> list[Path]:
    """Find all matching playbook YAML files under pack_dir."""
    playbooks_dir = pack_dir / "Playbooks"
    if not playbooks_dir.exists():
        print(f"{ANSI_YELLOW}WARNING{ANSI_RESET}: No Playbooks directory found at {playbooks_dir}")
        return []

    files = sorted(playbooks_dir.glob("*.yml"))
    if foundation_only:
        files = [f for f in files if f.name.startswith(FOUNDATION_PREFIX)]
    return files


def print_report(all_violations: list[dict], scanned: int, advisory: list[dict] = None):
    """Print a formatted report."""
    print()
    print(f"{ANSI_BOLD}{'='*70}{ANSI_RESET}")
    print(f"{ANSI_BOLD} SOC Framework — Foundation continueonerror Audit{ANSI_RESET}")
    print(f"{ANSI_BOLD}{'='*70}{ANSI_RESET}")
    print(f"  Playbooks scanned : {scanned}")
    print(f"  Violations found  : {len(all_violations)}")
    print()

    if all_violations:
        print(f"{ANSI_RED}{ANSI_BOLD}VIOLATIONS — tasks missing continueonerror: true{ANSI_RESET}")
        print()
        current_file = None
        for v in all_violations:
            if v["file"] != current_file:
                current_file = v["file"]
                print(f"  {ANSI_CYAN}{current_file}{ANSI_RESET}")
            tag = f"{ANSI_YELLOW}[{v['task_type']}]{ANSI_RESET}"
            print(f"    task {v['task_id']:>4}  {tag}  {v['task_name']}")
        print()
        print(f"{ANSI_RED}{'─'*70}{ANSI_RESET}")
        print(f"{ANSI_RED}  WHY THIS MATTERS:{ANSI_RESET}")
        print(f"  Foundation playbooks are the alert processing spine — they run on")
        print(f"  EVERY alert. A task without continueonerror: true will STOP the")
        print(f"  entire chain if it errors (e.g. empty field, missing list).")
        print(f"  Upon Trigger must NEVER stop. Normalize Artifacts must NEVER stop.")
        print(f"  Product Classification must NEVER stop.")
        print()
        print(f"  FIX: Add `continueonerror: true` to each listed task.")
        print(f"  Use tools/fix_errors.py or patch manually with str_replace.")
        print(f"{'─'*70}")
    else:
        print(f"{ANSI_GREEN}✅  All Foundation playbooks clean.{ANSI_RESET}")
        print(f"  Every regular/playbook task has continueonerror: true.")

    if advisory:
        print()
        print(f"{ANSI_YELLOW}ADVISORY (non-Foundation) — {len(advisory)} task(s) without continueonerror{ANSI_RESET}")
        current_file = None
        for v in advisory:
            if v["file"] != current_file:
                current_file = v["file"]
                print(f"  {v['file']}")
            print(f"    task {v['task_id']:>4}  [{v['task_type']}]  {v['task_name']}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Enforce continueonerror: true on all Foundation playbook tasks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pack", metavar="PATH",
                       help="Path to a pack directory (e.g. Packs/soc-optimization-unified)")
    group.add_argument("--file", metavar="PATH",
                       help="Path to a single playbook YAML file")
    parser.add_argument("--ci", action="store_true",
                        help="CI mode: exit 1 on any violation (default: exit 0 with report)")
    parser.add_argument("--all", action="store_true",
                        help="Also scan non-Foundation playbooks (advisory only, never blocks CI)")
    args = parser.parse_args()

    all_violations = []
    advisory_violations = []
    scanned = 0

    if args.file:
        filepath = Path(args.file)
        if not filepath.exists():
            print(f"ERROR: File not found: {filepath}")
            sys.exit(2)
        is_foundation = filepath.name.startswith(FOUNDATION_PREFIX)
        violations = check_playbook(filepath)
        scanned = 1
        if is_foundation:
            all_violations.extend(violations)
        else:
            advisory_violations.extend(violations)

    elif args.pack:
        pack_dir = Path(args.pack)
        if not pack_dir.exists():
            print(f"ERROR: Pack directory not found: {pack_dir}")
            sys.exit(2)

        foundation_files = find_playbooks(pack_dir, foundation_only=True)
        for fp in foundation_files:
            all_violations.extend(check_playbook(fp))
            scanned += 1

        if args.all:
            all_files = find_playbooks(pack_dir, foundation_only=False)
            non_foundation = [f for f in all_files if not f.name.startswith(FOUNDATION_PREFIX)]
            for fp in non_foundation:
                advisory_violations.extend(check_playbook(fp))
                scanned += 1

    print_report(
        all_violations,
        scanned,
        advisory=advisory_violations if args.all else None,
    )

    if all_violations and args.ci:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
