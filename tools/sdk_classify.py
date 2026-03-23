#!/usr/bin/env python3
"""
sdk_classify.py — Runs demisto-sdk validate and classifies errors as REAL vs NOISE.

The SDK produces many false positives when validating XSIAM content because it
defaults to XSOAR rules. This script runs validation with the correct marketplace
flag and classifies every error so you only act on real failures.

Usage:
    python3 tools/sdk_classify.py
    python3 tools/sdk_classify.py --pack Packs/soc-framework-nist-ir
    python3 tools/sdk_classify.py --file Packs/soc-framework-nist-ir/Playbooks/SOC_Email_Analysis_V3.yml
    python3 tools/sdk_classify.py --json   # output as JSON for CI parsing

Exit codes:
    0 — no REAL errors (NOISE errors are suppressed)
    1 — one or more REAL errors found
    2 — SDK not installed or other execution error

Categories:
    REAL          — genuine errors that will break runtime or upload. Must fix.
    PRE_EXISTING  — known open issues that existed before your change. Don't fix now.
    NOISE_XSIAM   — SDK applying XSOAR rules to XSIAM-targeted content. Suppress.
    NOISE_PROCESS — process issues (missing release notes, readme) for active dev. Suppress.
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ── Terminal colours ──────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ── Error classification rules ────────────────────────────────────────────────
# Each rule: (error_code_pattern, category, reason)
# Matched in order — first match wins.

CLASSIFICATION_RULES = [
    # ── Pre-existing known blockers — don't fix unless specifically targeting them ──
    ("BA106",           "PRE_EXISTING",  "fromversion on Foundation Upon_Trigger + Enrichment — known open blocker, pre-dates our changes"),
    ("RN108",           "NOISE_PROCESS", "Release notes missing — expected during active development cycle"),
    ("RM104",           "NOISE_PROCESS", "Readme missing — not required for internal Framework content"),

    # ── XSIAM-specific false positives ──────────────────────────────────────
    ("PB104",           "NOISE_XSIAM",   "Sub-playbook not found — called playbook lives in another pack or marketplace"),
    ("PB105",           "NOISE_XSIAM",   "Playbook input not used — false positive on optional gated inputs"),
    ("SC100",           "NOISE_XSIAM",   "Script not found — external marketplace script (AddDBotScoreToContext, etc.)"),
    ("SC105",           "NOISE_XSIAM",   "Script argument not valid — XSIAM-only script with different arg schema"),
    ("IN135",           "NOISE_XSIAM",   "Integration command not in XSOAR list — XSIAM-only integration"),
    ("DO100",           "NOISE_XSIAM",   "Dashboard global_id format — XSIAM uses string IDs, SDK expects UUID"),
    ("ST109",           "NOISE_XSIAM",   "system:true on content — acceptable for pack author"),
    ("GR100",           "NOISE_XSIAM",   "Graph validation — XSOAR graph requirements differ from XSIAM"),
    ("GR101",           "NOISE_XSIAM",   "Graph validation"),
    ("GR102",           "NOISE_XSIAM",   "Graph validation"),
    ("PA116",           "NOISE_XSIAM",   "Pack author — internal framework, not marketplace submission"),
    ("PA117",           "NOISE_XSIAM",   "Pack metadata — internal framework"),
    ("PA118",           "NOISE_XSIAM",   "Pack categories — internal framework"),
    ("BA109",           "NOISE_XSIAM",   "Content item not supported in marketplace version — XSIAM-only content type"),

    # ── Real errors that must be fixed ──────────────────────────────────────
    ("BA101",           "REAL",          "id and name fields do not match — breaks upload and reference resolution"),
    ("BA110",           "REAL",          "adopted:true not first key — required for pack content"),
    ("PB100",           "REAL",          "Playbook task references non-existent task ID — breaks runtime"),
    ("PB108",           "REAL",          "Condition task has no conditions defined — task always takes default branch"),
    ("BC100",           "REAL",          "Breaking change in content — requires major version bump"),
    ("BC101",           "REAL",          "Breaking change in content"),
    ("BA100",           "REAL",          "Generic content validation failure"),
    ("BA102",           "REAL",          "Version field error"),
    ("BA103",           "REAL",          "fromversion missing or invalid"),
    ("BA104",           "REAL",          "Content item ID missing"),
    ("BA105",           "REAL",          "Content item name missing"),
]

# Error codes to always classify as NOISE regardless of message content
ALWAYS_NOISE_CODES = {
    "RN108", "RM104", "PA116", "PA117", "PA118",
    "DO100", "GR100", "GR101", "GR102", "ST109", "BA109",
    "IN135", "SC100", "SC105",
}

# Error codes that are pre-existing known issues
PRE_EXISTING_CODES = {"BA106"}

# File patterns that are always pre-existing for known Foundation files
PRE_EXISTING_FILES = {
    "Foundation_-_Upon_Trigger_V3.yml",
    "Foundation_-_Enrichment_V3.yml",
}


@dataclass
class SDKError:
    code: str
    file: str
    line: str
    message: str
    raw: str
    category: str = "UNKNOWN"
    reason: str = ""


def classify_error(error: SDKError) -> SDKError:
    """Assign category to an SDK error."""

    # Always-noise codes
    if error.code in ALWAYS_NOISE_CODES:
        error.category = "NOISE_XSIAM"
        next(r for r in CLASSIFICATION_RULES if r[0] == error.code)
        for code, cat, reason in CLASSIFICATION_RULES:
            if code == error.code:
                error.reason = reason
                break
        return error

    # Pre-existing codes
    if error.code in PRE_EXISTING_CODES:
        error.category = "PRE_EXISTING"
        for code, cat, reason in CLASSIFICATION_RULES:
            if code == error.code:
                error.reason = reason
                break
        return error

    # Pre-existing files
    filename = Path(error.file).name if error.file else ""
    if filename in PRE_EXISTING_FILES and error.code in ("BA106", "BA103"):
        error.category = "PRE_EXISTING"
        error.reason = f"Pre-existing on {filename} — known open blocker"
        return error

    # PB104/PB105 — check if it's an external pack call (skip) vs internal missing (real)
    if error.code == "PB104":
        # External marketplace playbooks — these are known dependencies
        external_playbooks = {
            "Process Email - Generic v2",
            "Process Microsoft's Anti-Spam Headers",
            "Phishing - Machine Learning Analysis",
            "Entity Enrichment - Phishing v2",
            "Phishing - Indicators Hunting",
            "WildFire - Detonate file v2",
            "Detect & Manage Phishing Campaigns",
        }
        if any(pb in error.message for pb in external_playbooks):
            error.category = "NOISE_XSIAM"
            error.reason = "External marketplace playbook — expected dependency, not an error"
            return error
        # Unknown playbook — might be real
        error.category = "REAL"
        error.reason = "Unknown playbook reference — verify it exists in either pack"
        return error

    # Match classification rules in order
    for code_pattern, category, reason in CLASSIFICATION_RULES:
        if error.code == code_pattern or re.match(code_pattern, error.code):
            error.category = category
            error.reason = reason
            return error

    # Unknown error code — treat as real to be safe
    error.category = "REAL"
    error.reason = "Unknown error code — treating as real (update CLASSIFICATION_RULES if this is noise)"
    return error


def parse_sdk_output(raw_output: str) -> list[SDKError]:
    """Parse demisto-sdk validate output into structured errors."""
    errors = []

    # SDK output format: "Validating <file>..." then error lines
    # Error format: "  - [ERROR/WARNING] <code> - <message>" or
    #               "<file>:<line> - [<code>] <message>"
    current_file = ""

    for line in raw_output.split("\n"):
        # Track current file being validated
        file_match = re.match(r"^Validating (.+?)\.\.\.?$", line.strip())
        if file_match:
            current_file = file_match.group(1).strip()
            continue

        # Parse error lines — several SDK formats
        # Format 1: "   - [ERROR/WARNING] BA101: <file> - <message>"
        m1 = re.match(
            r"\s+[-•]\s+\[(ERROR|WARNING)\]\s+([A-Z0-9]+):\s*(.*?)(?:\s+-\s+(.*))?$",
            line
        )
        if m1:
            severity, code, file_or_msg, msg = m1.groups()
            errors.append(classify_error(SDKError(
                code=code,
                file=file_or_msg.strip() if file_or_msg else current_file,
                line="",
                message=msg.strip() if msg else file_or_msg.strip(),
                raw=line,
            )))
            continue

        # Format 2: "path/to/file.yml - [BA101] - message"
        m2 = re.match(r"(.+?)\s+-\s+\[([A-Z0-9]+)\]\s+-?\s*(.*)", line)
        if m2:
            fpath, code, msg = m2.groups()
            errors.append(classify_error(SDKError(
                code=code,
                file=fpath.strip(),
                line="",
                message=msg.strip(),
                raw=line,
            )))
            continue

        # Format 3: "  path/to/file.yml:123: error: [BA101] message"
        m3 = re.match(r"\s+(.+?):(\d+):\s+\w+:\s+\[([A-Z0-9]+)\]\s+(.*)", line)
        if m3:
            fpath, lineno, code, msg = m3.groups()
            errors.append(classify_error(SDKError(
                code=code,
                file=fpath.strip(),
                line=lineno,
                message=msg.strip(),
                raw=line,
            )))
            continue

    return errors


def run_sdk_validate(target: str | None, is_pack: bool = False) -> tuple[str, str, int]:
    """Run demisto-sdk validate and return (stdout, stderr, returncode)."""
    cmd = ["demisto-sdk", "validate", "--marketplace", "marketplacev2", "--no-conf-json"]

    if target:
        flag = "-i" if not is_pack else "-i"
        cmd += [flag, target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        print(f"{RED}Error: demisto-sdk not found. Install with: pip install demisto-sdk{RESET}",
              file=sys.stderr)
        sys.exit(2)


def render_results(errors: list[SDKError], json_output: bool = False, verbose: bool = False):
    """Print classified results."""

    real     = [e for e in errors if e.category == "REAL"]
    pre_ex   = [e for e in errors if e.category == "PRE_EXISTING"]
    noise    = [e for e in errors if e.category in ("NOISE_XSIAM", "NOISE_PROCESS")]
    unknown  = [e for e in errors if e.category == "UNKNOWN"]

    if json_output:
        print(json.dumps({
            "real": [{"code": e.code, "file": e.file, "message": e.message} for e in real],
            "pre_existing": [{"code": e.code, "file": e.file, "message": e.message} for e in pre_ex],
            "noise_count": len(noise),
            "total": len(errors),
        }, indent=2))
        return len(real) > 0

    print(f"\n{BOLD}SDK Validation — Classified Results{RESET}")
    print("─" * 56)

    if real:
        print(f"\n{RED}{BOLD}❌ REAL ERRORS ({len(real)}) — must fix before upload{RESET}")
        for e in real:
            print(f"  {RED}[{e.code}]{RESET} {e.file}")
            print(f"         {e.message}")
            if verbose:
                print(f"         {DIM}Reason: {e.reason}{RESET}")
    else:
        print(f"\n{GREEN}✅ No real errors{RESET}")

    if pre_ex:
        print(f"\n{YELLOW}{BOLD}⚠  PRE-EXISTING KNOWN ({len(pre_ex)}) — do not fix now{RESET}")
        for e in pre_ex:
            print(f"  {YELLOW}[{e.code}]{RESET} {DIM}{e.file}{RESET}")
            if verbose:
                print(f"         {DIM}{e.reason}{RESET}")

    if noise:
        print(f"\n{DIM}── {len(noise)} SDK false positives suppressed (XSIAM noise) ──{RESET}")
        if verbose:
            categories = {}
            for e in noise:
                categories.setdefault(e.reason, []).append(e.code)
            for reason, codes in sorted(categories.items()):
                print(f"  {DIM}[{', '.join(set(codes))}] {reason}{RESET}")

    if unknown:
        print(f"\n{CYAN}? UNCLASSIFIED ({len(unknown)}) — review and add to CLASSIFICATION_RULES{RESET}")
        for e in unknown:
            print(f"  [{e.code}] {e.file}: {e.message}")

    print(f"\n{'─' * 56}")
    print(f"Total: {len(errors)}  |  Real: {len(real)}  |  Pre-existing: {len(pre_ex)}  |  Suppressed: {len(noise)}")

    return len(real) > 0


def main():
    parser = argparse.ArgumentParser(description="Classify demisto-sdk validate output")
    parser.add_argument("--pack", help="Validate a specific pack directory")
    parser.add_argument("--file", "-i", help="Validate a specific file")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show suppressed noise categories and reasons")
    parser.add_argument("--raw", action="store_true",
                        help="Also print raw SDK output for debugging")
    args = parser.parse_args()

    target = args.pack or args.file
    is_pack = bool(args.pack)

    print(f"{BOLD}Running demisto-sdk validate --marketplace marketplacev2{RESET} ...", end="", flush=True)

    stdout, stderr, rc = run_sdk_validate(target, is_pack)

    print(" done")

    if args.raw:
        print(f"\n{DIM}=== RAW SDK OUTPUT ==={RESET}")
        print(stdout[:4000])
        if stderr:
            print(f"{DIM}=== STDERR ==={RESET}")
            print(stderr[:1000])

    errors = parse_sdk_output(stdout + "\n" + stderr)
    has_real = render_results(errors, json_output=args.json, verbose=args.verbose)

    sys.exit(1 if has_real else 0)


if __name__ == "__main__":
    main()
