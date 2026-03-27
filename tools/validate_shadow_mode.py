#!/usr/bin/env python3
"""
validate_shadow_mode.py
=======================
Pre-commit / CI gate for the SOC Framework Universal Command shadow mode architecture.

Architecture (v3 -- per-action, SOCFrameworkActions_V3):
  shadow_mode is defined per-action in SOCFrameworkActions_V3_data.json.
  SOCCommandWrapper reads it from the action entry -- NOT from playbook args or
  SOCExecutionList_V3. The branch execution list controls routing only.

  C/E/R destructive actions MUST have shadow_mode: true.
  Read-only / enrichment / analysis actions MAY have shadow_mode: false, but only
  if explicitly approved in shadow_mode_policy.json with a documented reason.

This script checks:
  1. No playbook calling SOCCommandWrapper passes shadow_mode / ShadowMode as a
     script argument (old v1 pattern -- must be absent).
  2. No playbook calling SOCCommandWrapper declares ShadowMode as an input.
  3. Every action called via SOCCommandWrapper exists in SOCFrameworkActions_V3_data.json.
  4. Every action with shadow_mode: false is explicitly listed in shadow_mode_policy.json.
     Actions with shadow_mode: true always pass.
  5. Actions whose name cannot be statically resolved are checked against the
     dynamic_actions section of shadow_mode_policy.json. Listed = WARNING (not fail).
     Unlisted = FAIL.

Scan strategy:
  Playbooks are identified by CONTENT (presence of SOCCommandWrapper), not filename.
  This targets Action Playbooks -- the actual UC callers.

File locations (overridable via CLI):
  --actions-list  SOCFrameworkActions_V3_data.json
  --policy        shadow_mode_policy.json

Exit codes:
    0  All checks passed (warnings are printed but do not block)
    1  One or more hard failures found (blocks merge to main)
    2  A required file is missing or unreadable (blocks merge to main)

Usage:
    python3 tools/validate_shadow_mode.py
    python3 tools/validate_shadow_mode.py Packs/soc-framework-nist-ir
    python3 tools/validate_shadow_mode.py --all
    python3 tools/validate_shadow_mode.py --all \\
        --actions-list Packs/soc-optimization-unified/Lists/SOCFrameworkActions_V3/SOCFrameworkActions_V3_data.json \\
        --policy Packs/soc-optimization-unified/Lists/SOCFrameworkActions_V3/shadow_mode_policy.json
"""

import sys
import os
import json
import yaml
import argparse

DEFAULT_ACTIONS_LIST = (
    'Packs/soc-optimization-unified/Lists/SOCFrameworkActions_V3/'
    'SOCFrameworkActions_V3_data.json'
)
DEFAULT_POLICY = (
    'Packs/soc-optimization-unified/Lists/SOCFrameworkActions_V3/'
    'shadow_mode_policy.json'
)

FORBIDDEN_SHADOW_ARGS = ('shadow_mode', 'ShadowMode')
SHADOW_ON_VALUES      = (True, 'true', 'True', 'TRUE')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shadow_mode_is_on(value):
    return value in SHADOW_ON_VALUES


def load_json_file(path, label):
    """Load a JSON file. Exit code 2 on any failure."""
    if not os.path.exists(path):
        print(f"ERROR: {label} not found: {path}")
        sys.exit(2)
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"ERROR: could not parse {label} at {path}: {e}")
        sys.exit(2)
    if not isinstance(data, dict):
        print(f"ERROR: {label} is not a JSON object: {path}")
        sys.exit(2)
    return data


# ---------------------------------------------------------------------------
# File discovery -- content-based
# ---------------------------------------------------------------------------

def find_uc_playbook_files(roots):
    """Return every .yml that references SOCCommandWrapper."""
    files = []
    for root in roots:
        for dirpath, _, filenames in os.walk(root):
            if '__MACOSX' in dirpath:
                continue
            for f in filenames:
                if not f.endswith('.yml'):
                    continue
                path = os.path.join(dirpath, f)
                try:
                    with open(path, encoding='utf-8', errors='replace') as fh:
                        if 'SOCCommandWrapper' in fh.read():
                            files.append(path)
                except OSError:
                    pass
    return sorted(files)


# ---------------------------------------------------------------------------
# Per-file checker
# ---------------------------------------------------------------------------

def check_file(filepath, actions_map, policy):
    """
    Returns (issues, warnings).
    issues   -- hard failures that block merge
    warnings -- informational; logged but do not set exit code 1
    """
    issues   = []
    warnings = []

    production_allowed = policy.get('production_allowed', {})
    dynamic_actions    = policy.get('dynamic_actions', {})
    playbook_basename  = os.path.splitext(os.path.basename(filepath))[0]

    with open(filepath, encoding='utf-8', errors='replace') as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            return [{'task_id': '?', 'action': '?', 'msg': f'YAML parse error: {e}'}], []

    if not isinstance(data, dict):
        return [], []

    # ------------------------------------------------------------------
    # Check 1: ShadowMode must NOT be declared as a playbook input
    # ------------------------------------------------------------------
    for inp in data.get('inputs', []):
        key = inp.get('key', '')
        if key.lower() in ('shadowmode', 'shadow_mode'):
            issues.append({
                'task_id': 'inputs',
                'action':  key,
                'msg':     (
                    'ShadowMode input still declared -- remove it. '
                    'shadow_mode is read from SOCFrameworkActions_V3 per-action entry.'
                ),
            })

    # ------------------------------------------------------------------
    # Checks 2-5: walk every SOCCommandWrapper task
    # ------------------------------------------------------------------
    for tid, task in data.get('tasks', {}).items():
        t  = task.get('task', {})
        sa = task.get('scriptarguments', {})

        is_wrapper = (
            'SOCCommandWrapper' in t.get('scriptName', '') or
            'SOCCommandWrapper' in t.get('script', '')
        )
        if not is_wrapper:
            continue

        # Resolve action name
        action = (
            sa.get('action', {}).get('simple')
            or sa.get('action', {}).get('complex', {}).get('root', None)
        )

        # Check 2: must NOT pass shadow_mode / ShadowMode as a script argument
        for key in FORBIDDEN_SHADOW_ARGS:
            if key in sa:
                issues.append({
                    'task_id': tid,
                    'action':  action or 'UNKNOWN_ACTION',
                    'msg':     (
                        f'Still passes {key} as a script argument -- remove it. '
                        'shadow_mode is read from SOCFrameworkActions_V3 per-action entry.'
                    ),
                })

        # ------------------------------------------------------------------
        # UNKNOWN_ACTION -- runtime-resolved action name
        # ------------------------------------------------------------------
        if not action:
            if playbook_basename in dynamic_actions:
                warnings.append({
                    'task_id': tid,
                    'action':  'DYNAMIC',
                    'msg':     (
                        'Action name resolved at runtime (expected -- see dynamic_actions '
                        'in shadow_mode_policy.json). '
                        f'Reason: {dynamic_actions[playbook_basename].get("reason", "no reason given")}'
                    ),
                })
            else:
                issues.append({
                    'task_id': tid,
                    'action':  'UNKNOWN_ACTION',
                    'msg':     (
                        'Could not resolve action name from scriptarguments and playbook '
                        'is not listed in dynamic_actions in shadow_mode_policy.json. '
                        'Either hardcode the action name or add this playbook to dynamic_actions.'
                    ),
                })
            continue

        # ------------------------------------------------------------------
        # Check 3: action must exist in SOCFrameworkActions_V3
        # ------------------------------------------------------------------
        entry = actions_map.get(action)
        if entry is None:
            issues.append({
                'task_id': tid,
                'action':  action,
                'msg':     (
                    f'Action "{action}" not found in SOCFrameworkActions_V3. '
                    'Add it with the correct shadow_mode value before merging.'
                ),
            })
            continue

        if 'shadow_mode' not in entry:
            issues.append({
                'task_id': tid,
                'action':  action,
                'msg':     (
                    f'Action "{action}" has no shadow_mode field in SOCFrameworkActions_V3. '
                    'Add shadow_mode: true (destructive) or shadow_mode: false with a '
                    'corresponding entry in shadow_mode_policy.json (read-only/enrichment).'
                ),
            })
            continue

        # ------------------------------------------------------------------
        # Check 4: shadow_mode: false requires a policy exemption
        # ------------------------------------------------------------------
        if shadow_mode_is_on(entry['shadow_mode']):
            # shadow_mode: true -- always OK
            pass
        else:
            # shadow_mode: false -- must be explicitly approved in policy
            if action in production_allowed:
                warnings.append({
                    'task_id': tid,
                    'action':  action,
                    'msg':     (
                        f'shadow_mode: false -- approved in policy. '
                        f'Category: {production_allowed[action].get("category", "??")}. '
                        f'Reason: {production_allowed[action].get("reason", "no reason given")}'
                    ),
                })
            else:
                issues.append({
                    'task_id': tid,
                    'action':  action,
                    'msg':     (
                        f'Action "{action}" has shadow_mode: false but is NOT listed in '
                        'shadow_mode_policy.json production_allowed. '
                        'Add a policy entry with a documented reason, or set shadow_mode: true.'
                    ),
                })

    return issues, warnings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Validate SOC Framework UC shadow_mode architecture (per-action, v3).')
    parser.add_argument('packs', nargs='*',
                        help='Pack directories to scan (default: entire Packs/ tree)')
    parser.add_argument('--all', action='store_true',
                        help='Scan entire Packs/ directory')
    parser.add_argument('--actions-list', default=DEFAULT_ACTIONS_LIST,
                        help=f'Path to SOCFrameworkActions_V3_data.json (default: {DEFAULT_ACTIONS_LIST})')
    parser.add_argument('--policy', default=DEFAULT_POLICY,
                        help=f'Path to shadow_mode_policy.json (default: {DEFAULT_POLICY})')
    args = parser.parse_args()

    roots = args.packs or []
    if args.all or not roots:
        roots = ['Packs']

    actions_map = load_json_file(args.actions_list, 'SOCFrameworkActions_V3')
    policy      = load_json_file(args.policy, 'shadow_mode_policy')

    files = find_uc_playbook_files(roots)
    if not files:
        print(f"No playbooks referencing SOCCommandWrapper found in: {roots}")
        sys.exit(0)

    production_allowed_count = len(policy.get('production_allowed', {}))
    print(
        f"validate_shadow_mode (v3 -- per-action)\n"
        f"  {len(files)} playbook(s) | {len(actions_map)} action(s) | "
        f"{production_allowed_count} policy exemption(s)\n"
    )

    all_issues   = []
    all_warnings = []

    for filepath in files:
        issues, warnings = check_file(filepath, actions_map, policy)
        all_issues.extend(issues)
        all_warnings.extend(warnings)

        rel = os.path.relpath(filepath)

        if issues:
            print(f"  \u274c  {rel}")
            for issue in issues:
                print(
                    f"       \u2717 Task {str(issue['task_id']):>6}  "
                    f"{issue['action']:<40}  {issue['msg']}"
                )
        elif warnings:
            print(f"  \u26a0\ufe0f  {rel}")
            for warn in warnings:
                print(
                    f"       \u26a0 Task {str(warn['task_id']):>6}  "
                    f"{warn['action']:<40}  {warn['msg']}"
                )
        else:
            print(f"  \u2705  {rel}")

    print()

    if all_warnings:
        print(f"  {len(all_warnings)} approved production-mode action(s) noted above (policy-exempted, not blocking).")

    print()

    if all_issues:
        print(
            f"FAILED -- {len(all_issues)} issue(s) found.\n"
            "  Destructive actions must have shadow_mode: true in SOCFrameworkActions_V3.\n"
            "  Read-only/enrichment actions with shadow_mode: false must have a\n"
            "  documented entry in shadow_mode_policy.json production_allowed.\n"
        )
        sys.exit(1)
    else:
        print(
            f"PASSED -- {len(files)} playbook(s) clean. "
            "All UC actions are correctly gated.\n"
        )
        sys.exit(0)


if __name__ == '__main__':
    main()
