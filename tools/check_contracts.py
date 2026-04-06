#!/usr/bin/env python3
"""
check_contracts.py
──────────────────────────────────────────────────────────────────────────────
SOC Framework layer contract validator.

Checks that playbooks respect the layer contracts defined by the framework:

  Foundation  — reads issue.*, writes SOCFramework.*
  Lifecycle   — reads SOCFramework.*, writes phase namespaces (Analysis.* etc.),
                calls setParentIncident at phase completion
  Workflow    — reads SOCFramework.* + issue.*, writes Analysis.*/Containment.*/etc.,
                must NOT write SOCFramework.*, must NOT call setIssue/setIncident
  Comms       — fire-and-forget, no phase namespace writes
  JOB         — no alert context, no issue.* reads
  Entry Point — no contract checks (trigger only)

All detection is textual — the script reads raw YAML text and applies regex
patterns. yaml.dump is never called. This keeps detection fast and consistent
with the normalize_contribution.py approach.

Severity levels:
  ERROR   — contract violation that will cause incorrect runtime behaviour.
            CI exits 1 on any error.
  WARN    — architectural issue that does not break execution but violates
            the layer contract. Use --strict to treat warnings as errors.

Usage:
  # Check only what changed on this branch (safe default)
  python3 tools/check_contracts.py

  # Preview — same output, no side effects (always the case; script is read-only)
  python3 tools/check_contracts.py --dry-run

  # Treat warnings as errors (for strict CI gate)
  python3 tools/check_contracts.py --strict

  # Check a specific file
  python3 tools/check_contracts.py --input Packs/soc-framework-nist-ir/Playbooks/SOC_Email_Exposure_Evaluation_V3.yml

  # Check an entire pack
  python3 tools/check_contracts.py --input Packs/soc-framework-nist-ir
"""

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Layer classification
# ─────────────────────────────────────────────────────────────────────────────

# NIST IR lifecycle phase names — used to distinguish Lifecycle from Workflow
NIST_PHASES = {"Analysis", "Containment", "Eradication", "Recovery"}

# Lifecycle playbook names exactly — SOC_<Phase>_V3 with no category prefix
LIFECYCLE_NAMES = {f"SOC_{phase}_V3" for phase in NIST_PHASES}

# Additional lifecycle variant — the top-level NIST IR entry
LIFECYCLE_NAMES.add("SOC_NIST_IR_(800-61)_V3")
LIFECYCLE_NAMES.add("EP_IR_NIST_(800-61)_V3")


def identify_layer(playbook_name: str) -> str:
    """
    Classify a playbook into its SOC Framework layer from its name.

    Naming conventions:
      EP_*                          → entry_point
      Foundation_-_*                → foundation
      JOB_-_*                       → job
      SOC_<Phase>_V3                → lifecycle   (no category prefix)
      SOC_<Category>_<Phase>_V3     → workflow    (has category prefix)
      SOC_Comms_*                   → comms
      SOC_<Category>_V3             → workflow    (category-only, no phase)
      anything else                 → unknown

    Names are normalised (spaces → underscores) before matching so that
    'SOC Recovery_V3' and 'SOC_Recovery_V3' both classify as lifecycle.
    """
    n = playbook_name.strip()

    # Normalise spaces to underscores for pattern matching.
    # The name field in YAML uses spaces between words but LIFECYCLE_NAMES
    # and prefix checks use underscores. Both forms must match correctly.
    n_norm = n.replace(" ", "_")

    if n_norm.startswith("EP_"):
        return "entry_point"

    if n_norm.startswith("Foundation_-_"):
        return "foundation"

    if n_norm.startswith("JOB_-_"):
        return "job"

    if n_norm in LIFECYCLE_NAMES:
        return "lifecycle"

    if n_norm.startswith("SOC_Comms_"):
        return "comms"

    if n_norm.startswith("SOC_"):
        return "workflow"

    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Finding data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single contract violation found in a playbook."""
    severity: str       # "ERROR" or "WARN"
    rule:     str       # short rule identifier
    task_id:  str       # task id where the violation was found, or "" for file-level
    task_name: str      # task name, or "" for file-level
    message:  str       # human-readable description
    suggestion: str     # what to do instead


@dataclass
class PlaybookResult:
    """All findings for a single playbook file."""
    path:     Path
    name:     str
    layer:    str
    findings: list[Finding] = field(default_factory=list)

    @property
    def errors(self):
        return [f for f in self.findings if f.severity == "ERROR"]

    @property
    def warnings(self):
        return [f for f in self.findings if f.severity == "WARN"]


# ─────────────────────────────────────────────────────────────────────────────
# YAML task extraction — textual, no yaml.dump
# ─────────────────────────────────────────────────────────────────────────────

# Matches the start of a task block: two-space-indented quoted integer key
_TASK_START_RE = re.compile(r"""^  ['"]\d+['"]\s*:\s*$""", re.MULTILINE)

# Fields we care about within a task block
_TASK_NAME_RE    = re.compile(r"""^\s{6}name\s*:\s*['"]?(.+?)['"]?\s*$""", re.MULTILINE)
_TASK_ID_RE      = re.compile(r"""^  ['"](\d+)['"]\s*:\s*$""", re.MULTILINE)
_SCRIPT_RE       = re.compile(r"""^\s+script\s*:\s*(.+)$""", re.MULTILINE)
_KEY_RE          = re.compile(r"""^\s+key\s*:\s*\n\s+simple\s*:\s*(.+)$""", re.MULTILINE)
_KEY_SIMPLE_RE   = re.compile(r"""key\s*:\s*\n\s*simple\s*:\s*(\S+)""")


def extract_tasks(text: str) -> list[dict]:
    """
    Extract a lightweight representation of each task from raw YAML text.

    Returns a list of dicts with keys: id, name, script, set_keys
      id        — task ID string (e.g. '0', '5')
      name      — task name from the task.name field
      script    — script value (e.g. 'SetAndHandleEmpty', 'Builtin|||setIssue')
      set_keys  — list of context key strings from scriptarguments.key.simple
    """
    tasks = []

    # Split on task boundary markers
    # Each boundary is a line like:  '5':
    boundaries = list(_TASK_ID_RE.finditer(text))
    if not boundaries:
        return tasks

    for i, m in enumerate(boundaries):
        tid   = m.group(1)
        start = m.start()
        end   = boundaries[i + 1].start() if i + 1 < len(boundaries) else len(text)
        block = text[start:end]

        # Extract task name from the task: sub-block
        name = ""
        name_m = re.search(r"""task\s*:\s*\n(?:.*\n)*?\s+name\s*:\s*['"]?(.+?)['"]?\s*\n""", block)
        if name_m:
            name = name_m.group(1).strip().strip('"\'')

        # Extract script field
        script = ""
        script_m = re.search(r"""^\s+script\s*:\s*(.+)$""", block, re.MULTILINE)
        if script_m:
            script = script_m.group(1).strip().strip('"\'')

        # Extract context key being set (scriptarguments.key.simple)
        set_keys = []
        for km in re.finditer(r"""key\s*:\s*\n\s+simple\s*:\s*(\S+)""", block):
            set_keys.append(km.group(1).strip())

        # Extract contract:allow annotations from the task description.
        # Format: # contract:allow RULE_ID — reason
        # Any rule ID listed here is suppressed for this specific task.
        # Multiple annotations on separate lines are supported.
        allowed_rules: set[str] = set()
        for ann_m in re.finditer(r"contract:allow\s+(\w+)", block):
            allowed_rules.add(ann_m.group(1).strip())

        tasks.append({
            "id":            tid,
            "name":          name,
            "script":        script,
            "set_keys":      set_keys,
            "allowed_rules": allowed_rules,
        })

    return tasks


def playbook_name_from_text(text: str) -> str:
    """Extract the playbook name from raw YAML text."""
    m = re.search(r"^name\s*:\s*(.+)$", text, re.MULTILINE)
    if m:
        return m.group(1).strip().strip("'\"")
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# Contract rules
# ─────────────────────────────────────────────────────────────────────────────

# Namespaces that belong to specific layers
_SOCFRAMEWORK_PREFIX = "SOCFramework."
_PHASE_PREFIXES      = ("Analysis.", "Containment.", "Eradication.", "Recovery.",
                        "Email.", "Endpoint.", "Identity.", "Network.", "SaaS.",
                        "Workload.", "PAM.", "Data.", "UC.")

# Builtin scripts that write directly to the alert or case
_SET_ISSUE          = "Builtin|||setIssue"
_SET_INCIDENT       = "Builtin|||setIncident"
_SET_PARENT_INCIDENT = "Builtin|||setParentIncident"


def _check_workflow(tasks: list[dict]) -> list[Finding]:
    """
    Rules for Workflow layer playbooks.

    A Workflow playbook is category-specific logic inside a NIST IR phase.
    It knows Email vs Endpoint vs Identity. It routes to Action Playbooks.

    Contracts:
      - Must NOT write to SOCFramework.* (belongs to Foundation)
      - Must NOT call setIssue (writes to the alert record, not the case)
      - Must NOT call setIncident (Foundation's job)
      - WARN if setParentIncident called mid-workflow (should be Lifecycle boundary)
    """
    findings = []

    for t in tasks:
        # setIssue from Workflow — writes to the alert, not the case
        # This is a hard error because it writes to the wrong object entirely.
        # Suppress with: # contract:allow WORKFLOW_SET_ISSUE — <reason>
        if _SET_ISSUE in t["script"] and "WORKFLOW_SET_ISSUE" not in t["allowed_rules"]:
            findings.append(Finding(
                severity   = "ERROR",
                rule       = "WORKFLOW_SET_ISSUE",
                task_id    = t["id"],
                task_name  = t["name"],
                message    = "setIssue called from Workflow layer — writes to the alert record, not the case.",
                suggestion = (
                    "Write the value to a phase-namespace context key (e.g. Analysis.Email.AffectedRecipients) "
                    "and let the Lifecycle playbook call setParentIncident at the phase boundary."
                ),
            ))

        # setIncident from Workflow — Foundation's job
        # Suppress with: # contract:allow WORKFLOW_SET_INCIDENT — <reason>
        if _SET_INCIDENT in t["script"] and "WORKFLOW_SET_INCIDENT" not in t["allowed_rules"]:
            findings.append(Finding(
                severity   = "ERROR",
                rule       = "WORKFLOW_SET_INCIDENT",
                task_id    = t["id"],
                task_name  = t["name"],
                message    = "setIncident called from Workflow layer — this is Foundation's responsibility.",
                suggestion = (
                    "Write to a phase-namespace context key. "
                    "Foundation writes to case fields at phase boundaries."
                ),
            ))

        # setParentIncident from Workflow — should be at Lifecycle boundary
        # Suppress with: # contract:allow WORKFLOW_SET_PARENT_INCIDENT — <reason>
        if _SET_PARENT_INCIDENT in t["script"] and "WORKFLOW_SET_PARENT_INCIDENT" not in t["allowed_rules"]:
            findings.append(Finding(
                severity   = "WARN",
                rule       = "WORKFLOW_SET_PARENT_INCIDENT",
                task_id    = t["id"],
                task_name  = t["name"],
                message    = "setParentIncident called from Workflow layer — should be at Lifecycle phase boundary.",
                suggestion = (
                    "Move the setParentIncident call to the terminal task of the Lifecycle playbook "
                    "(SOC_Analysis_V3, SOC_Containment_V3, etc.) after this Workflow completes."
                ),
            ))

        # SOCFramework.* written from Workflow — wrong namespace.
        # Suppress with: # contract:allow WORKFLOW_WRITES_SOCFRAMEWORK — <reason>
        if "WORKFLOW_WRITES_SOCFRAMEWORK" not in t["allowed_rules"]:
            for key in t["set_keys"]:
                if key.startswith(_SOCFRAMEWORK_PREFIX):
                    findings.append(Finding(
                        severity   = "WARN",
                        rule       = "WORKFLOW_WRITES_SOCFRAMEWORK",
                        task_id    = t["id"],
                        task_name  = t["name"],
                        message    = f"Workflow writes to SOCFramework.* namespace: {key}",
                        suggestion = (
                            f"Rename to the phase namespace instead. "
                            f"Example: {key.replace('SOCFramework.', 'Analysis.')} "
                            f"(or the appropriate phase prefix for this playbook). "
                            f"If intentional, annotate with: "
                            f"# contract:allow WORKFLOW_WRITES_SOCFRAMEWORK — <reason>"
                        ),
                    ))

    return findings


def _check_foundation(tasks: list[dict]) -> list[Finding]:
    """
    Rules for Foundation layer playbooks.

    Foundation runs on every alert. It reads issue.* and writes SOCFramework.*.
    It may call setIncident to write to the case at trigger time.

    Contracts:
      - Must NOT read from Analysis.*, Containment.*, etc.
        (those namespaces don't exist yet when Foundation runs)
      - Must NOT write to Analysis.* etc.
      - WARN if calling setParentIncident (setIncident is the correct call here)
    """
    findings = []

    for t in tasks:
        if _SET_PARENT_INCIDENT in t["script"]:
            findings.append(Finding(
                severity   = "WARN",
                rule       = "FOUNDATION_SET_PARENT_INCIDENT",
                task_id    = t["id"],
                task_name  = t["name"],
                message    = "Foundation calls setParentIncident — setIncident is more appropriate at trigger time.",
                suggestion = "Use setIncident for Foundation-level case field writes.",
            ))

        # Foundation writing to phase namespaces
        for key in t["set_keys"]:
            if any(key.startswith(p) for p in _PHASE_PREFIXES) and \
               not key.startswith("UC."):
                findings.append(Finding(
                    severity   = "WARN",
                    rule       = "FOUNDATION_WRITES_PHASE_NAMESPACE",
                    task_id    = t["id"],
                    task_name  = t["name"],
                    message    = f"Foundation writes to phase namespace: {key}",
                    suggestion = (
                        "Foundation should only write to SOCFramework.* keys. "
                        "Phase namespaces (Analysis.*, Containment.*, etc.) belong to Lifecycle/Workflow."
                    ),
                ))

    return findings


def _check_lifecycle(tasks: list[dict], text: str) -> list[Finding]:
    """
    Rules for Lifecycle layer playbooks.

    Lifecycle playbooks own the NIST IR phase controller logic.
    They call Workflow sub-playbooks and write phase summaries to the case.

    Contracts:
      - Should call setParentIncident at the terminal task (or sub-playbook does it)
      - Must NOT write to SOCFramework.* directly
      - WARN if writing directly to SOCFramework.*
    """
    findings = []
    has_set_parent = any(_SET_PARENT_INCIDENT in t["script"] for t in tasks)

    # Missing setParentIncident is a warning — the sub-playbook may handle it
    if not has_set_parent:
        findings.append(Finding(
            severity   = "WARN",
            rule       = "LIFECYCLE_MISSING_SET_PARENT",
            task_id    = "",
            task_name  = "",
            message    = "Lifecycle playbook has no setParentIncident call.",
            suggestion = (
                "Add a setParentIncident task at the terminal position to write phase "
                "outputs (verdict, story, timestamp) to the case. This is how analysts "
                "see phase results in the case layout."
            ),
        ))

    # Note: SOCFramework.phase and similar housekeeping keys are legitimately
    # written by lifecycle playbooks to track framework state. A full check
    # of lifecycle SOCFramework.* writes would require an allowlist of
    # permitted keys and is deferred — the critical check is on workflow layer.

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Per-file check
# ─────────────────────────────────────────────────────────────────────────────

def check_playbook(path: Path) -> Optional[PlaybookResult]:
    """
    Run all contract checks against a single playbook file.
    Returns None if the file should be skipped (not a playbook, unreadable, etc.)
    """
    if path.suffix.lower() not in (".yml", ".yaml"):
        return None

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None

    # Must be a playbook (has tasks: mapping)
    if not re.search(r"^tasks\s*:", text, re.MULTILINE):
        return None

    name  = playbook_name_from_text(text)
    layer = identify_layer(name)
    tasks = extract_tasks(text)

    result = PlaybookResult(path=path, name=name, layer=layer)

    if layer == "workflow":
        result.findings = _check_workflow(tasks)
    elif layer == "foundation":
        result.findings = _check_foundation(tasks)
    elif layer == "lifecycle":
        result.findings = _check_lifecycle(tasks, text)
    # entry_point, job, comms, unknown — no contract checks currently

    return result


# ─────────────────────────────────────────────────────────────────────────────
# File collection — same git diff approach as normalize_contribution.py
# ─────────────────────────────────────────────────────────────────────────────

def git_changed_files(base: str = "origin/main") -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "diff", base, "--name-only", "--diff-filter=AM"],
            capture_output=True, text=True, check=True,
        )
        return [Path(f) for f in result.stdout.splitlines() if f.strip()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def collect_playbooks(input_path: Optional[Path], base: str) -> list[Path]:
    """
    Collect playbook YAML files to check.

    Same scoping rules as normalize_contribution.py:
      - Specific file → just that file
      - Directory or None → git diff filtered to Playbooks/ under Packs/
    """
    if input_path is not None and input_path.is_file():
        return [input_path]

    changed = git_changed_files(base)

    if changed:
        packs_playbooks = [
            f for f in changed
            if f.parts and f.parts[0] == "Packs"
            and "Playbooks" in f.parts
            and f.suffix.lower() in (".yml", ".yaml")
        ]
        if input_path is not None:
            try:
                rel = input_path.resolve().relative_to(Path.cwd())
            except ValueError:
                rel = input_path
            packs_playbooks = [
                f for f in packs_playbooks
                if str(f).startswith(str(rel))
            ]
        return sorted(packs_playbooks)

    # No git diff — fall back to directory walk if input given
    if input_path is not None and input_path.is_dir():
        return sorted(
            p for p in input_path.rglob("*.yml")
            if "Playbooks" in p.parts
            and not any(part.startswith(".") for part in p.parts)
        )

    return []


# ─────────────────────────────────────────────────────────────────────────────
# ANSI colours
# ─────────────────────────────────────────────────────────────────────────────

_TTY = sys.stdout.isatty()

def _c(code, t):  return f"\033[{code}m{t}\033[0m" if _TTY else t
def ERR(t):  return _c("31;1", t)
def WARN(t): return _c("33;1", t)
def OK(t):   return _c("32;1", t)
def INFO(t): return _c("36",   t)
def DIM(t):  return _c("2",    t)
def BOLD(t): return _c("1",    t)


# ─────────────────────────────────────────────────────────────────────────────
# Report output
# ─────────────────────────────────────────────────────────────────────────────

def print_finding(f: Finding, indent: str = "    ") -> None:
    icon  = ERR("✗  ERROR") if f.severity == "ERROR" else WARN("⚠  WARN")
    loc   = f"task {f.task_id}" if f.task_id else "file"
    tname = f" — {f.task_name}" if f.task_name else ""
    print(f"{indent}{icon}  [{loc}{tname}]")
    print(f"{indent}   {f.message}")
    print(f"{indent}   → {DIM(f.suggestion)}")


def print_result(r: PlaybookResult) -> None:
    if not r.findings:
        return

    print(f"\n  {INFO('PLAYBOOK')}  {DIM(str(r.path))}")
    print(f"    layer: {BOLD(r.layer.upper())}  ({r.name})")
    for f in r.findings:
        print()
        print_finding(f)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOC Framework layer contract validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--input", "-i", default=None,
        help="Specific file or directory to check (default: git diff scope)",
    )
    parser.add_argument(
        "--base", default="origin/main",
        help="Git base ref for diff (default: origin/main)",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Treat warnings as errors — CI exits 1 on any finding",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Alias for clarity — this script is always read-only",
    )
    args = parser.parse_args()

    input_path = Path(args.input).resolve() if args.input else None
    if input_path and not input_path.exists():
        print(ERR(f"✗ not found: {input_path}"))
        sys.exit(1)

    print()
    print("━" * 62)
    print("  check_contracts.py — SOC Framework layer contract validator")
    if input_path:
        print(f"  scope  : {INFO(str(input_path))}")
    else:
        print(f"  scope  : {INFO(f'git diff {args.base}')}")
    if args.strict:
        print(f"  mode   : {WARN('strict — warnings treated as errors')}")
    print("━" * 62)

    playbooks = collect_playbooks(input_path, args.base)

    if not playbooks:
        print(WARN("\n  No playbooks found in scope."))
        if not input_path:
            print(DIM(
                "  Run 'git fetch origin' if you expected changes,\n"
                "  or use --input <file> to check a specific file."
            ))
        sys.exit(0)

    print(f"\n  {len(playbooks)} playbook(s) in scope\n")

    results       = []
    total_errors  = 0
    total_warnings = 0
    skipped       = 0

    for pb_path in playbooks:
        result = check_playbook(pb_path)
        if result is None:
            skipped += 1
            continue
        results.append(result)
        total_errors   += len(result.errors)
        total_warnings += len(result.warnings)
        print_result(result)

    # ── Summary ───────────────────────────────────────────────────────────────
    # Also print clean playbooks so it's clear they were checked
    clean = [r for r in results if not r.findings]
    if clean:
        print()
        for r in clean:
            print(f"  {OK('✓')}  {r.name}  {DIM(f'({r.layer})')}")

    print()
    print("━" * 62)

    if total_errors == 0 and total_warnings == 0:
        print(OK(f"  ✓ {len(results)} playbook(s) checked — all contracts satisfied"))
    else:
        if total_errors:
            print(ERR(f"  {total_errors} error(s)") + f"  |  " +
                  WARN(f"{total_warnings} warning(s)"))
        else:
            print(OK("  0 errors") + f"  |  " + WARN(f"{total_warnings} warning(s)"))

        if total_errors:
            print(ERR("  Errors must be resolved before merging."))
        if total_warnings and not args.strict:
            print(DIM("  Warnings are architectural — run with --strict to gate on them."))
        if total_warnings and args.strict:
            print(WARN("  Strict mode: warnings treated as errors."))

    print("━" * 62)
    print()

    # Exit 1 if errors, or if strict and any warnings
    if total_errors or (args.strict and total_warnings):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
