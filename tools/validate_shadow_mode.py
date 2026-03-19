#!/usr/bin/env python3
"""
validate_shadow_mode.py
=======================
Pre-commit check for the SOC Framework Universal Command shadow mode architecture.

Architecture (v2):
  shadow_mode is defined per-action in SOCFrameworkActions_V3_data.json.
  SOCCommandWrapper reads it from the action entry — NOT from playbook args.
  Playbooks must NOT pass shadow_mode / ShadowMode to SOCCommandWrapper.
  Playbooks must NOT declare ShadowMode as an input.

This script checks:
  1. No C/E/R playbook passes shadow_mode or ShadowMode to a UC task.
  2. No C/E/R playbook declares ShadowMode as an input.
  3. Every action called via SOCCommandWrapper has shadow_mode defined in
     SOCFrameworkActions_V3_data.json (optional, requires --actions-list).

Usage:
    python3 tools/validate_shadow_mode.py Packs/soc-framework-nist-ir
    python3 tools/validate_shadow_mode.py Packs/soc-framework-nist-ir Packs/soc-optimization-unified
    python3 tools/validate_shadow_mode.py --all
    python3 tools/validate_shadow_mode.py --all \
        --actions-list Packs/soc-optimization-unified/Lists/SOCFrameworkActions_V3/SOCFrameworkActions_V3_data.json

Exit codes:
    0  All checks passed
    1  One or more issues found (blocks commit)
"""

import sys
import os
import json
import yaml
import argparse

CER_PATTERNS = ['Containment', 'Eradication', 'Recovery']
SHADOW_KEYS  = ('shadow_mode', 'ShadowMode')


def is_cer_playbook(filename):
    return any(p in filename for p in CER_PATTERNS) and filename.endswith('.yml')


def find_playbook_files(roots):
    files = []
    for root in roots:
        for dirpath, _, filenames in os.walk(root):
            if '__MACOSX' in dirpath:
                continue
            for f in filenames:
                if is_cer_playbook(f):
                    files.append(os.path.join(dirpath, f))
    return sorted(files)


def load_actions_list(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        print(f"  warning: could not load actions list {path}: {e}")
        return {}


def check_file(filepath, actions_map):
    issues = []

    with open(filepath) as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            return [{'task_id': '?', 'action': '?', 'msg': f'YAML parse error: {e}'}]

    if not isinstance(data, dict):
        return []

    # Check 1: ShadowMode must NOT be in declared inputs
    for inp in data.get('inputs', []):
        if inp.get('key', '').lower() in ('shadowmode', 'shadow_mode'):
            issues.append({
                'task_id': 'inputs',
                'action':  inp['key'],
                'msg':     'ShadowMode input still declared — remove it (wrapper reads from action list)',
            })

    # Check 2 + 3: UC tasks must not pass shadow_mode; action must be in actions list
    for tid, task in data.get('tasks', {}).items():
        t  = task.get('task', {})
        sa = task.get('scriptarguments', {})

        is_wrapper = (
            'SOCCommandWrapper' in t.get('scriptName', '') or
            'SOCCommandWrapper' in t.get('script', '')
        )
        if not is_wrapper:
            continue

        action = sa.get('action', {}).get('simple', 'UNKNOWN_ACTION')

        # Check 2: must NOT pass shadow_mode
        for key in SHADOW_KEYS:
            if key in sa:
                issues.append({
                    'task_id': tid,
                    'action':  action,
                    'msg':     f'Still passes {key} — remove it (wrapper reads from action list)',
                })

        # Check 3: action must exist in actions_map with shadow_mode defined
        if actions_map and action != 'UNKNOWN_ACTION':
            entry = actions_map.get(action)
            if entry is None:
                issues.append({
                    'task_id': tid,
                    'action':  action,
                    'msg':     f'Action not found in SOCFrameworkActions_V3',
                })
            elif 'shadow_mode' not in entry:
                issues.append({
                    'task_id': tid,
                    'action':  action,
                    'msg':     f'No shadow_mode field in SOCFrameworkActions_V3 entry',
                })

    return issues


def main():
    parser = argparse.ArgumentParser(
        description='Validate SOC Framework UC shadow_mode architecture.')
    parser.add_argument('packs', nargs='*',
                        help='Pack directories to scan')
    parser.add_argument('--all', action='store_true',
                        help='Scan entire Packs/ directory')
    parser.add_argument('--actions-list', default=None,
                        help='Path to SOCFrameworkActions_V3_data.json')
    args = parser.parse_args()

    roots = args.packs or []
    if args.all or not roots:
        roots = ['Packs']

    files = find_playbook_files(roots)
    if not files:
        print(f"No C/E/R playbook files found in: {roots}")
        sys.exit(0)

    actions_map = load_actions_list(args.actions_list) if args.actions_list else {}

    suffix = f" + {len(actions_map)} action(s)" if actions_map else ""
    print(f"validate_shadow_mode — scanning {len(files)} C/E/R playbook(s){suffix}\n")

    all_issues = []
    for filepath in files:
        issues = check_file(filepath, actions_map)
        all_issues.extend(issues)

        rel = os.path.relpath(filepath)
        if issues:
            print(f"  ❌  {rel}")
            for issue in issues:
                print(f"       Task {str(issue['task_id']):>6}  {issue['action']:<35}  {issue['msg']}")
        else:
            print(f"  ✅  {rel}")

    print()
    if all_issues:
        print(f"FAILED — {len(all_issues)} issue(s) found. Fix before merging to main.\n")
        sys.exit(1)
    else:
        print(f"PASSED — all {len(files)} C/E/R playbook(s) correctly wired for action-list shadow_mode.\n")
        sys.exit(0)


if __name__ == '__main__':
    main()
