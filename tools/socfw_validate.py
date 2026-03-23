#!/usr/bin/env python3
"""
socfw_validate.py — SOC Framework static contract validator.

Checks Framework-specific rules that demisto-sdk does not know about.
Runs entirely from the filesystem — no tenant, no SDK install required.

Usage:
    python3 tools/socfw_validate.py
    python3 tools/socfw_validate.py --pack Packs/soc-framework-nist-ir
    python3 tools/socfw_validate.py --file Packs/soc-framework-nist-ir/Playbooks/SOC_Email_Analysis_V3.yml
    python3 tools/socfw_validate.py --changed-only   # reads git diff, tests only changed files

Exit codes:
    0 — all checks passed
    1 — one or more FAIL results
    2 — usage error
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

# ── Terminal colours ──────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):   print(f"  {GREEN}✅ PASS{RESET}  {msg}")
def fail(msg): print(f"  {RED}❌ FAIL{RESET}  {msg}")
def warn(msg): print(f"  {YELLOW}⚠  WARN{RESET}  {msg}")
def info(msg): print(f"  {CYAN}ℹ  INFO{RESET}  {msg}")

# ── Locate pack roots ─────────────────────────────────────────────────────────
def find_pack_root(start: Path) -> Path:
    """Walk up from start until we find a pack_metadata.json."""
    for parent in [start] + list(start.parents):
        if (parent / "pack_metadata.json").exists():
            return parent
    return start

def find_all_playbooks(root: Path):
    return list(root.rglob("Playbooks/*.yml"))

def find_all_lists(root: Path):
    return list(root.rglob("Lists/**/*.json"))

# ── Known rules ───────────────────────────────────────────────────────────────

# Playbooks that are allowed to read issue.* fields — Foundation only
FOUNDATION_PLAYBOOKS = {
    "Foundation - Normalize Email_V3",
    "Foundation - Normalize Endpoint_V3",
    "Foundation - Normalize Identity_V3",
    "Foundation - Normalize Network_V3",
    "Foundation - Normalize Cloud_V3",
    "Foundation - Normalize Generic_V3",
    "Foundation - Normalize Artifacts",
    "Foundation - Product Classification_V3",
    "Foundation - Upon Trigger V3",
    "Foundation - Enrichment_V3",
    "Foundation - Dedup_V3",
    "Foundation - Performance Capture_V3",
    "Foundation - Assessment_V3",
    "Foundation - Escalation_V3",
    "Foundation - Case Sync_V3",
    "Foundation - Data Integrity_V3",
    "Foundation - Environment Detection_V3",
    "Foundation - Error Handling_V3",
    "Foundation Common - Extract Indicators from alerts",
    "Foundation - Get Alert Tasks and Store to Dataset_V3",
}

# Vendor-specific alert field patterns that should not appear in NIST IR playbooks
VENDOR_LOGIC_PATTERNS = [
    r"alert\.proofpointtap\w*",
    r"alert\.crowdstrike\w*",
    r"alert\.ms_aad\w*",
    r"alert\.okta_\w*",
    r"issue\.fw_email_",      # should only be in Normalize Email
    r"issue\.socfwemail",      # should only be in Normalize Email
]

# Actions that MUST use SOCCommandWrapper (C/E/R phase)
CEF_PHASE_KEYWORDS = ["Containment", "Eradication", "Recovery"]

# Actions whose shadow_mode must be false (Analysis phase — always execute)
ANALYSIS_ACTIONS_MUST_EXECUTE = [
    "soc-enrich-file", "soc-enrich-ip", "soc-enrich-domain",
    "soc-enrich-user", "soc-enrich-endpoint", "soc-enrich-ioc",
    "soc-get-email-events", "soc-get-email-forensics",
    "soc-detonate-file", "soc-file-exists", "soc-audit-inbox-rules",
]

# Actions whose shadow_mode must be true (C/E/R — never fire without explicit flip)
CEF_ACTIONS_MUST_SHADOW = [
    "soc-isolate-endpoint", "soc-deisolate-endpoint", "soc-kill-process",
    "soc-disable-user", "soc-enable-user", "soc-reset-password",
    "soc-revoke-tokens", "soc-clear-sessions",
    "soc-retract-email", "soc-quarantine-email", "soc-block-sender",
    "soc-unblock-sender", "soc-search-and-delete-email",
    "soc-remove-inbox-rules", "soc-block-indicators",
    "soc-remove-file", "soc-delete-file", "soc-quarantine-files",
    "soc-remove-persistence",
]


# ── Check functions ───────────────────────────────────────────────────────────

def check_yaml_header(path: Path, data: dict) -> list:
    """HEADER checks: adopted first, fromversion, version, id==name."""
    issues = []
    raw = path.read_text()
    first_line = raw.strip().split("\n")[0].strip()

    if first_line != "adopted: true":
        issues.append(f"HEADER: 'adopted: true' must be first line (got: {first_line[:50]})")

    fv = data.get("fromversion")
    if fv and fv not in ("6.10.0", "5.0.0", "6.0.0", ""):
        issues.append(f"HEADER: fromversion={fv} (expected 6.10.0)")
    if fv == "5.0.0":
        issues.append(f"HEADER_WARN: fromversion=5.0.0 (pre-existing; blocks force-merge — fix separately)")

    v = data.get("version")
    if v is not None and v != -1:
        # WARN not FAIL — version is reset to -1 on upload by the platform.
        # Pre-existing on most pack files. Only a FAIL if building from scratch.
        issues.append(f"HEADER_WARN: version={v} — reset to -1 on platform upload (pre-existing)")

    pid = data.get("id", "")
    name = data.get("name", "")
    if pid and name and pid != name:
        issues.append(f"HEADER: id '{pid}' != name '{name}'")

    return issues


def check_task_routing(data: dict) -> list:
    """ROUTING: every nexttask ID exists; every non-start task is reachable."""
    issues = []
    tasks = data.get("tasks", {})
    if not tasks:
        return issues

    task_ids = set(str(k) for k in tasks)

    # All nexttask references must exist
    for tid, t in tasks.items():
        for branch, targets in t.get("nexttasks", {}).items():
            if isinstance(targets, list):
                for target in targets:
                    if str(target) not in task_ids:
                        issues.append(f"ROUTING: task {tid} nexttask '{target}' does not exist in tasks")

    # Reachability — every task except starttask must be referenced
    start = str(data.get("starttaskid", "0"))
    reachable = {start}
    changed = True
    while changed:
        changed = False
        for tid, t in tasks.items():
            if str(tid) in reachable:
                for targets in t.get("nexttasks", {}).values():
                    if isinstance(targets, list):
                        for tgt in targets:
                            if str(tgt) not in reachable:
                                reachable.add(str(tgt))
                                changed = True

    for tid in task_ids:
        if tid not in reachable and tid != start:
            # Warn, not fail — some title-only tasks are intentionally terminal
            task_name = tasks[tid].get("task", {}).get("name", "")
            issues.append(f"ROUTING_WARN: task {tid} ('{task_name}') not reachable from starttask")

    return issues


def check_context_contracts(path: Path, data: dict) -> list:
    """CONTEXT: no issue.* reads below Foundation; no vendor-specific alert fields."""
    issues = []
    pb_name = data.get("name", "")

    if pb_name in FOUNDATION_PLAYBOOKS:
        return issues  # Foundation is allowed to read issue.*

    tasks_yaml = yaml.dump(data.get("tasks", {}))

    # Check issue.* reads — only allowed in Foundation
    issue_reads = re.findall(r"issue\.(fw_email_|socfwemail|emailmessageid|emailsenderip|reporteremailaddress)", tasks_yaml)
    if issue_reads:
        issues.append(f"CONTEXT: Non-Foundation playbook reads issue.* fields: {set(issue_reads)}")

    # Check vendor-specific alert field reads
    for pattern in VENDOR_LOGIC_PATTERNS:
        matches = re.findall(pattern, tasks_yaml)
        if matches:
            issues.append(f"CONTEXT: Vendor-specific field reference: {set(matches)}")

    return issues


def check_uc_compliance(data: dict) -> list:
    """SHADOW: C/E/R phase tasks must call SOCCommandWrapper, not vendor commands directly."""
    issues = []
    pb_name = data.get("name", "")

    # Determine if this is a C/E/R workflow playbook
    is_cer = any(phase in pb_name for phase in CEF_PHASE_KEYWORDS)
    if not is_cer:
        return issues

    for tid, t in data.get("tasks", {}).items():
        task_type = t.get("task", {}).get("type", "")
        script = t.get("task", {}).get("scriptName", "") or t.get("task", {}).get("script", "")
        name = t.get("task", {}).get("name", "")

        # Regular tasks that call a command (iscommand=True) but not via SOCCommandWrapper
        is_command = t.get("task", {}).get("iscommand", False)
        if task_type == "regular" and is_command and script != "SOCCommandWrapper":
            # Allow: SetAndHandleEmpty, Print, Builtin, SOCFWHealthCheck
            native = {"SetAndHandleEmpty", "SetMultipleValues", "Set", "Print",
                      "DeleteContext", "SOCFWHealthCheck", "Builtin|||setIssue",
                      "Builtin|||setIssueStatus", "Builtin|||closeInvestigation"}
            if script not in native and not script.startswith("Builtin|||"):
                issues.append(f"SHADOW: C/E/R task {tid} ('{name}') calls '{script}' directly — must use SOCCommandWrapper")

    return issues


def check_actions_list(actions_path: Path) -> list:
    """ACTIONS: validate SOCFrameworkActions_V3_data.json contracts."""
    issues = []
    try:
        actions = json.loads(actions_path.read_text())
    except Exception as e:
        return [f"ACTIONS: Cannot parse {actions_path.name}: {e}"]

    # Analysis actions must have shadow_mode=False
    for key in ANALYSIS_ACTIONS_MUST_EXECUTE:
        if key in actions:
            if actions[key].get("shadow_mode") is not False:
                issues.append(f"ACTIONS: {key} must have shadow_mode=false (Analysis phase always executes)")

    # C/E/R actions must have shadow_mode=True
    for key in CEF_ACTIONS_MUST_SHADOW:
        if key in actions:
            if actions[key].get("shadow_mode") is not True:
                issues.append(f"ACTIONS: {key} must have shadow_mode=true (C/E/R defaults to shadow)")

    # Required actions must exist
    required = ["soc-detonate-file", "soc-remove-inbox-rules",
                "soc-search-and-delete-email", "soc-block-indicators"]
    for key in required:
        if key not in actions:
            issues.append(f"ACTIONS: Required action '{key}' is missing from SOCFrameworkActions_V3")

    # soc-remove-inbox-rule (singular) must NOT exist — renamed to plural
    if "soc-remove-inbox-rule" in actions:
        issues.append("ACTIONS: Old key 'soc-remove-inbox-rule' (singular) still exists — must be 'soc-remove-inbox-rules'")

    # soc-detonate-file must have Cortex Core as first/baseline vendor
    det = actions.get("soc-detonate-file", {})
    if det and "Cortex Core - IR" not in det.get("responses", {}):
        issues.append("ACTIONS: soc-detonate-file missing 'Cortex Core - IR' baseline entry")

    return issues


def check_feature_flags(flags_path: Path) -> list:
    """FLAGS: all SOCFWFeatureFlags must default to enabled=false."""
    issues = []
    try:
        flags = json.loads(flags_path.read_text())
    except Exception as e:
        return [f"FLAGS: Cannot parse {flags_path.name}: {e}"]

    meta_keys = {"id", "name", "_comment", "description"}
    for key, value in flags.items():
        if key in meta_keys:
            continue
        if not isinstance(value, dict):
            issues.append(f"FLAGS: {key} must be an object with 'enabled' key")
            continue
        if "enabled" not in value:
            issues.append(f"FLAGS: {key} missing 'enabled' key")
        elif value["enabled"] is not False:
            issues.append(f"FLAGS: {key}.enabled={value['enabled']} — all flags must default to false")
        if "description" not in value:
            issues.append(f"FLAGS: {key} missing 'description' — descriptions are the documentation")

    # Required flags must exist
    required_flags = [
        "sandbox_detonation", "email_authentication", "email_header_scoring",
        "email_process_original", "email_indicator_hunting", "email_phishing_ml",
    ]
    for flag in required_flags:
        if flag not in flags:
            issues.append(f"FLAGS: Required flag '{flag}' missing from SOCFWFeatureFlags")

    return issues


def check_product_category_map(map_path: Path) -> list:
    """ROUTING: SOCProductCategoryMap entries have required keys."""
    issues = []
    try:
        cmap = json.loads(map_path.read_text())
    except Exception as e:
        return [f"CATMAP: Cannot parse {map_path.name}: {e}"]

    valid_categories = {"Email", "Endpoint", "Identity", "Network", "SaaS", "Workload", "PAM", "Data"}
    for dataset_key, entry in cmap.items():
        if not isinstance(entry, dict):
            continue
        cat = entry.get("category")
        if cat and cat not in valid_categories:
            issues.append(f"CATMAP: '{dataset_key}' has unknown category '{cat}'")
        for required_key in ("category", "type", "confidence"):
            if required_key not in entry:
                issues.append(f"CATMAP: '{dataset_key}' missing required key '{required_key}'")

    return issues


# ── Runner ────────────────────────────────────────────────────────────────────

def validate_playbook(path: Path, verbose: bool = False) -> tuple[int, int]:
    """Returns (fail_count, warn_count)."""
    fails = 0
    warns = 0
    try:
        data = yaml.safe_load(path.read_text())
    except Exception as e:
        fail(f"{path.name}: YAML parse error — {e}")
        return 1, 0

    pb_name = data.get("name", path.stem)
    all_issues = []
    all_issues += check_yaml_header(path, data)
    all_issues += check_task_routing(data)
    all_issues += check_context_contracts(path, data)
    all_issues += check_uc_compliance(data)

    real_fails = [i for i in all_issues if not i.endswith("_WARN)") and "_WARN" not in i.split(":")[0]]
    warns_list = [i for i in all_issues if "_WARN" in i.split(":")[0]]

    if not real_fails and not warns_list:
        if verbose:
            ok(f"{pb_name}")
    else:
        for issue in real_fails:
            fail(f"{pb_name}: {issue}")
            fails += 1
        for issue in warns_list:
            warn(f"{pb_name}: {issue}")
            warns += 1

    return fails, warns


def validate_list_file(path: Path, verbose: bool = False) -> tuple[int, int]:
    """Validate a list JSON file based on its name."""
    name = path.name
    issues = []
    warns = []

    if "SOCFrameworkActions_V3_data" in name:
        all_issues = check_actions_list(path)
        issues = [i for i in all_issues if "_WARN" not in i.split(":")[0]]
        warns = [i for i in all_issues if "_WARN" in i.split(":")[0]]
    elif "SOCFWFeatureFlags_data" in name:
        all_issues = check_feature_flags(path)
        issues = [i for i in all_issues if "_WARN" not in i.split(":")[0]]
        warns = [i for i in all_issues if "_WARN" in i.split(":")[0]]
    elif "SOCProductCategoryMap_V3_data" in name:
        all_issues = check_product_category_map(path)
        issues = [i for i in all_issues if "_WARN" not in i.split(":")[0]]
    else:
        if verbose:
            info(f"Skipping {name} (no specific checks)")
        return 0, 0

    if not issues and not warns:
        if verbose:
            ok(name)
    else:
        for issue in issues:
            fail(f"{name}: {issue}")
        for w in warns:
            warn(f"{name}: {w}")

    return len(issues), len(warns)


def get_changed_files() -> list[Path]:
    """Get list of changed YAML/JSON files from git diff."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            capture_output=True, text=True, check=True
        )
        staged = subprocess.run(
            ["git", "diff", "--staged", "--name-only"],
            capture_output=True, text=True, check=True
        )
        files = set(result.stdout.strip().split("\n") + staged.stdout.strip().split("\n"))
        return [Path(f) for f in files if f and (f.endswith(".yml") or f.endswith(".json"))]
    except subprocess.CalledProcessError:
        return []


def main():
    parser = argparse.ArgumentParser(description="SOC Framework static contract validator")
    parser.add_argument("--pack", help="Path to a single pack root directory")
    parser.add_argument("--file", help="Path to a single playbook or list file")
    parser.add_argument("--changed-only", action="store_true",
                        help="Only validate files changed in git (diff HEAD + staged)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print PASS results too (default: only failures)")
    parser.add_argument("--packs-dir", default="Packs",
                        help="Root directory containing all packs (default: Packs)")
    args = parser.parse_args()

    total_fails = 0
    total_warns = 0
    files_checked = 0

    print(f"\n{BOLD}SOC Framework — Static Contract Validation{RESET}")
    print("─" * 56)

    # ── Collect target files ──────────────────────────────────────────────────
    playbook_files: list[Path] = []
    list_files: list[Path] = []

    if args.file:
        p = Path(args.file)
        if not p.exists():
            print(f"Error: {p} not found", file=sys.stderr)
            sys.exit(2)
        if p.suffix == ".yml":
            playbook_files = [p]
        elif p.suffix == ".json":
            list_files = [p]

    elif args.changed_only:
        changed = get_changed_files()
        if not changed:
            info("No changed files found in git diff.")
            sys.exit(0)
        info(f"Changed files: {len(changed)}")
        for f in changed:
            if f.suffix == ".yml" and "Playbooks" in str(f):
                playbook_files.append(f)
            elif f.suffix == ".json" and "Lists" in str(f):
                list_files.append(f)

    elif args.pack:
        pack_root = Path(args.pack)
        playbook_files = find_all_playbooks(pack_root)
        list_files = find_all_lists(pack_root)

    else:
        # Default: scan both packs
        packs_root = Path(args.packs_dir)
        if packs_root.exists():
            for pack_dir in packs_root.iterdir():
                if pack_dir.is_dir():
                    playbook_files += find_all_playbooks(pack_dir)
                    list_files += find_all_lists(pack_dir)
        else:
            print(f"Error: '{args.packs_dir}' directory not found. Run from repo root or use --pack.",
                  file=sys.stderr)
            sys.exit(2)

    # ── Run checks ───────────────────────────────────────────────────────────
    if playbook_files:
        print(f"\n{BOLD}Playbooks ({len(playbook_files)}){RESET}")
        for path in sorted(playbook_files):
            f, w = validate_playbook(path, verbose=args.verbose)
            total_fails += f
            total_warns += w
            files_checked += 1

    if list_files:
        print(f"\n{BOLD}List files ({len(list_files)}){RESET}")
        for path in sorted(list_files):
            f, w = validate_list_file(path, verbose=args.verbose)
            total_fails += f
            total_warns += w
            files_checked += 1

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'─' * 56}")
    print(f"Files checked: {files_checked}")
    if total_fails == 0:
        print(f"{GREEN}{BOLD}✅ All contract checks passed{RESET}", end="")
        if total_warns:
            print(f"  {YELLOW}({total_warns} warnings — pre-existing, not blocking){RESET}")
        else:
            print()
        sys.exit(0)
    else:
        print(f"{RED}{BOLD}❌ {total_fails} failure(s){RESET}", end="")
        if total_warns:
            print(f"  {YELLOW}+ {total_warns} warning(s){RESET}")
        else:
            print()
        sys.exit(1)


if __name__ == "__main__":
    main()
