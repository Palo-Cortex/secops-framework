#!/usr/bin/env python3
"""
playbook_condition_lint.py — SOC Framework playbook condition & context validator

Catches playbook YAML patterns that parse cleanly but silently fail at runtime.
The XSIAM Playbook Editor UI prevents these patterns by construction; hand-written
YAML bypasses that guardrail. Both bug classes below shipped to production in
the NIST IR pack before detection, blocking full Containment execution.

CHECKS
──────
  1. Malformed ${X / Y} context references
     ─────────────────────────────────────
     Pattern detected:
         root: ${Analysis
         accessor: verdict}
     Effect:
         Interpolation opens ${ on one line and closes } on the next, splitting
         the context path. XSIAM treats "${Analysis" as a literal string.
         Downstream conditions comparing it to real values always fail.
     Correct form (complex):
         root: Analysis
         accessor: verdict
     Correct form (simple):
         simple: ${Analysis.verdict}

  2. Broken task references
     ──────────────────────
     Pattern detected:
         tasks:
           "21":
             nexttasks:
               "#none#":
               - "201"           # task 201 does not exist
     Effect:
         The Playbook Editor's graph loader walks every task's nexttasks
         dict and aborts when it hits an unresolvable ID, making the
         playbook unopenable in the UI. Common cause: a task gets
         deleted but predecessors still reference it.
     Correct form:
         Point nexttasks at a real task ID, typically the Done title
         task for terminal branches.

  3. Scratch / backup / OS-copy files
     ──────────────────────────────
     Filenames matched:
         foo copy.yml, foo (1).yml, foo.yml.bak, foo.yml~,
         ._foo.yml, foo.yml.orig, foo.yml.rej
     Effect:
         Pack normalize treats every .yml as a playbook. Backup files
         and OS copy artifacts get processed and shipped, polluting the
         tenant with stale or duplicate content.
     Correct form:
         Delete these from the pack before commit.
     NOT flagged: foo_copy.yml — that is the intentional contributor
         convention for submitting a replacement playbook. The
         normalize_contribution.py step merges _copy contents into the
         canonical filename and deletes the _copy.

  4. Duplicate content
     ─────────────────
     Two files whose bytes are byte-for-byte identical (same SHA-256).
     Effect:
         Pointless copy left behind by accident. Ships twice, wastes
         pack space, and the SDK may reject the second as a conflict.
     Correct form:
         Delete one of them.
     The _copy contributor workflow is handled naturally: a genuine
         _copy submission has edited content, so its bytes differ from
         the original and it is not flagged. Only useless identical
         copies get reported.

  5. Stale numeric keys
     ──────────────────
     Pattern detected:
         contentitemexportablefields:
           '308':                       # was: contentitemfields
             packID: foo
         inputs:
         - key: AutoContainment
           '309':                       # was: value
             simple: "False"
     Effect:
         A YAML serializer has replaced named keys (contentitemfields,
         value) with quoted numeric strings — usually internal field IDs
         from a partial schema-aware export. The SDK uploads silently
         but drops the unrecognized keys: input defaults vanish and pack
         metadata is lost. Symptom: every input field appears blank in
         the UI even though defaults are defined in the source YAML.
     Correct form:
         contentitemexportablefields:
           contentitemfields:
             packID: foo
         inputs:
         - key: AutoContainment
           value:
             simple: "False"
     Auto-fix:
         Re-run with --fix. Repair uses targeted regex on raw text —
         never yaml.dump (which would itself reorder keys and break the
         Upon Trigger chain). Only this check is auto-fixable; checks
         1–4 are reported but not modified.

EXIT CODES
──────────
  0  No bugs found (or all stale-key bugs repaired with --fix)
  1  One or more bugs found

USAGE
─────
  # Single pack
  python3 tools/playbook_condition_lint.py Packs/soc-framework-nist-ir

  # Single file
  python3 tools/playbook_condition_lint.py Packs/soc-framework-nist-ir/Playbooks/SOC_Endpoint_Containment_V3.yml

  # Multiple paths
  python3 tools/playbook_condition_lint.py Packs/soc-framework-nist-ir Packs/soc-optimization-unified
"""

import argparse
import hashlib
import re
import sys
from pathlib import Path

import yaml


EQUALITY_OPERATORS = {"isEqualString", "isEqualNumber", "containsString"}


def find_yaml_files(path: Path):
    """Yield all .yml files under a pack Playbooks dir, or the file itself."""
    if path.is_file() and path.suffix == ".yml":
        yield path
        return
    if path.is_dir():
        pb_dir = path / "Playbooks"
        root = pb_dir if pb_dir.is_dir() else path
        for p in sorted(root.rglob("*.yml")):
            if "__MACOSX" in p.parts:
                continue
            yield p


def check_broken_interpolation(fpath: Path):
    """Line-level scan for `root: ${X` paired with `accessor: Y}` on next line."""
    bugs = []
    try:
        lines = fpath.read_text().splitlines()
    except Exception:
        return bugs

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("root:"):
            continue
        if "${" not in stripped or "}" in stripped:
            continue
        if i + 1 >= len(lines):
            continue
        next_stripped = lines[i + 1].strip()
        if next_stripped.startswith("accessor:") and next_stripped.endswith("}"):
            bugs.append({
                "line": i + 1,
                "root": stripped,
                "accessor": next_stripped,
            })
    return bugs


def check_broken_task_refs(fpath: Path):
    """Detect nexttasks references pointing to task IDs that don't exist.

    The XSIAM Playbook Editor's graph loader walks every task's nexttasks
    dict and aborts when it hits an unresolvable ID, leaving the playbook
    unopenable in the UI. Often caused by a task being deleted without
    updating predecessor references.
    """
    bugs = []
    try:
        with fpath.open() as f:
            pb = yaml.safe_load(f)
    except Exception:
        return bugs

    if not isinstance(pb, dict):
        return bugs

    tasks = pb.get("tasks") or {}
    if not isinstance(tasks, dict):
        return bugs

    valid_ids = set(tasks.keys())
    for tid, tdata in tasks.items():
        if not isinstance(tdata, dict):
            continue
        nexttasks = tdata.get("nexttasks") or {}
        if not isinstance(nexttasks, dict):
            continue
        task_name = tdata.get("task", {}).get("name", "") if isinstance(tdata.get("task"), dict) else ""
        for branch, targets in nexttasks.items():
            for target in (targets or []):
                if target not in valid_ids:
                    bugs.append({
                        "task_id": tid,
                        "task_name": task_name,
                        "branch": branch,
                        "missing_target": target,
                    })
    return bugs


# Filename patterns that indicate scratch copies / IDE backups / OS copy artifacts.
# These should never ship to the tenant.
#
# IMPORTANT: _copy.yml is NOT in this list. It is the intentional contributor
# convention for submitting a replacement playbook — normalize_contribution.py
# strips the suffix from the file's id/name fields and writes the result to
# the canonical filename, then deletes the _copy file. The merge logic lives
# in the normalizer; the linter must not flag legitimate submissions.
SCRATCH_FILE_PATTERNS = [
    re.compile(r" copy(?:\s*\d+)?\.yml$", re.IGNORECASE),       # macOS Finder: "foo copy.yml"
    re.compile(r"\s\(\d+\)\.yml$"),                             # "foo (1).yml"
    re.compile(r"\.yml\.bak$", re.IGNORECASE),                  # vim backups
    re.compile(r"\.yml~$"),                                     # emacs backups
    re.compile(r"^\._", re.IGNORECASE),                         # macOS resource forks
    re.compile(r"\.yml\.orig$", re.IGNORECASE),                 # merge conflict leftovers
    re.compile(r"\.yml\.rej$", re.IGNORECASE),                  # patch rejects
]


def check_scratch_files(pack_path: Path):
    """Flag any filename that matches scratch-copy / backup / OS-artifact patterns.

    These files should be deleted before commit. Having them in the pack means
    the contributor script will process and ship them, potentially overwriting
    real content with stale duplicates.
    """
    findings = []
    pb_dir = pack_path / "Playbooks" if (pack_path / "Playbooks").is_dir() else pack_path
    if not pb_dir.is_dir():
        return findings
    # Glob all files (not just .yml) because backup/scratch patterns can have
    # extensions like .yml.bak, .yml~, .yml.orig that wouldn't match *.yml.
    for p in sorted(pb_dir.rglob("*")):
        if not p.is_file():
            continue
        if "__MACOSX" in p.parts:
            continue
        name = p.name
        for pat in SCRATCH_FILE_PATTERNS:
            if pat.search(name):
                findings.append({
                    "path": p,
                    "pattern": pat.pattern,
                })
                break
    return findings


def check_duplicate_content(pack_path: Path):
    """Detect files with byte-identical content.

    A duplicate is literally the same bytes in two files — usually a
    pointless copy left behind by accident. Two files with the same `id`
    but different content are NOT duplicates; they are conflicts, which
    the SDK validator catches on its own.

    The _copy contributor workflow is handled automatically by this
    definition: a legitimate _copy submission has edited content (that's
    the whole point), so its bytes differ from the original and it is
    not flagged. A useless _copy that's identical to the original IS
    flagged, which is what we want.
    """
    findings = []
    pb_dir = pack_path / "Playbooks" if (pack_path / "Playbooks").is_dir() else pack_path
    if not pb_dir.is_dir():
        return findings

    hash_to_files = {}
    for p in sorted(pb_dir.rglob("*.yml")):
        if "__MACOSX" in p.parts:
            continue
        try:
            data = p.read_bytes()
        except Exception:
            continue
        digest = hashlib.sha256(data).hexdigest()
        hash_to_files.setdefault(digest, []).append(p)

    for digest, files in hash_to_files.items():
        if len(files) > 1:
            findings.append({"hash": digest[:12], "files": files})
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Check #5: stale numeric keys (CIEF + inputs)
# ─────────────────────────────────────────────────────────────────────────────
# Schema knowledge — anything else at these locations is suspicious. Numeric
# keys in particular are the smoking gun of a partial schema-aware serializer
# emitting internal field IDs in place of named keys.
_VALID_INPUT_KEYS = {"key", "value", "required", "description", "playbookInputQuery"}
_VALID_CIEF_KEYS = {"contentitemfields"}
_NUMERIC_KEY_RE = re.compile(r"^\d+$")


def check_stale_numeric_keys(fpath: Path):
    """Detect stale numeric-key corruption in playbook YAML.

    Returns list of bug dicts with location, observed key, expected key,
    and an is_numeric flag (True for the smoking-gun pattern, False for
    other unexpected keys at the same location).
    """
    bugs = []
    try:
        with fpath.open() as f:
            pb = yaml.safe_load(f)
    except Exception:
        return bugs

    if not isinstance(pb, dict):
        return bugs

    # contentitemexportablefields should contain only 'contentitemfields'
    cief = pb.get("contentitemexportablefields")
    if isinstance(cief, dict):
        for key in cief:
            if key in _VALID_CIEF_KEYS:
                continue
            bugs.append({
                "location": "contentitemexportablefields",
                "key": str(key),
                "expected": "contentitemfields",
                "is_numeric": bool(_NUMERIC_KEY_RE.match(str(key))),
            })

    # inputs[].* should only contain known keys
    for i, inp in enumerate(pb.get("inputs") or []):
        if not isinstance(inp, dict):
            continue
        label = inp.get("key", f"<index {i}>")
        for key in inp:
            if key in _VALID_INPUT_KEYS:
                continue
            bugs.append({
                "location": f"inputs[{label}]",
                "key": str(key),
                "expected": "value",
                "is_numeric": bool(_NUMERIC_KEY_RE.match(str(key))),
            })

    return bugs


# Repair regexes — targeted text edits, NEVER yaml.dump.
# Pattern A: contentitemexportablefields:\n  '<digits>':  →  contentitemfields:
_CIEF_STALE_KEY_RE_TEMPLATE = (
    r"^(contentitemexportablefields:\n)(\s+)'{stale}':"
)


def _find_inputs_section(text: str):
    """Locate (start, end) byte range of the inputs: section in raw text.
    start is just after the 'inputs:' line; end is at the next column-0 key.
    Returns None if no inputs section.
    """
    head = re.search(r"^inputs:\s*$", text, flags=re.MULTILINE)
    if not head:
        return None
    section_start = head.end()
    nxt = re.search(
        r"^[a-zA-Z][a-zA-Z0-9_]*\s*:",
        text[section_start:],
        flags=re.MULTILINE,
    )
    section_end = section_start + (nxt.start() if nxt else len(text) - section_start)
    return section_start, section_end


def fix_stale_numeric_keys(fpath: Path):
    """Repair stale-numeric-key corruption in playbook YAML.

    Strategy:
      1. Parse YAML to identify which numeric keys exist where.
      2. CIEF: replace 'NNN': directly under contentitemexportablefields:.
      3. Inputs: scope replacement to the inputs: text section, then replace
         any indented 'NNN': -> value:. Survives arbitrary key ordering
         within input blocks (some exports alphabetize, some don't).

    Never uses yaml.dump (would reorder keys and break the Upon Trigger
    chain). Returns (cief_repairs, input_repairs).
    """
    text = fpath.read_text()
    try:
        pb = yaml.safe_load(text)
    except Exception:
        return 0, 0
    if not isinstance(pb, dict):
        return 0, 0

    cief_n = 0
    input_n = 0

    # CIEF stale keys
    stale_cief = set()
    cief = pb.get("contentitemexportablefields") or {}
    if isinstance(cief, dict):
        for key in cief:
            if _NUMERIC_KEY_RE.match(str(key)):
                stale_cief.add(str(key))
    for stale in stale_cief:
        pattern = re.compile(
            _CIEF_STALE_KEY_RE_TEMPLATE.format(stale=re.escape(stale)),
            flags=re.MULTILINE,
        )
        text, n = pattern.subn(r"\1\2contentitemfields:", text)
        cief_n += n

    # Input stale keys (section-scoped so we don't touch tasks: or anywhere else)
    stale_inputs = set()
    for inp in (pb.get("inputs") or []):
        if not isinstance(inp, dict):
            continue
        for key in inp:
            if key in _VALID_INPUT_KEYS:
                continue
            if _NUMERIC_KEY_RE.match(str(key)):
                stale_inputs.add(str(key))

    if stale_inputs:
        bounds = _find_inputs_section(text)
        if bounds:
            section_start, section_end = bounds
            before = text[:section_start]
            section = text[section_start:section_end]
            after = text[section_end:]
            for stale in stale_inputs:
                pattern = re.compile(
                    r"^(\s+)'" + re.escape(stale) + r"':",
                    flags=re.MULTILINE,
                )
                section, n = pattern.subn(r"\1value:", section)
                input_n += n
            text = before + section + after

    if cief_n or input_n:
        fpath.write_text(text)
    return cief_n, input_n


def _field_identity(left_value):
    """Return a stable identity for the left-hand field of a condition item.

    Covers both `simple: path.to.field` and `complex: {root: X, accessor: Y}`.
    Returns None if we can't extract a stable key.
    """
    if not isinstance(left_value, dict):
        return None
    simple = left_value.get("simple")
    if isinstance(simple, str) and simple:
        return simple.strip()
    complex_val = left_value.get("complex")
    if isinstance(complex_val, dict):
        root = complex_val.get("root", "")
        accessor = complex_val.get("accessor", "")
        if root:
            return f"{root}.{accessor}" if accessor else root
    return None


def check_and_impossible_conditions(fpath: Path):
    """Removed — this check was based on a wrong understanding of XSIAM semantics.

    XSIAM condition evaluation: outer list = AND, inner list = OR.
    Multiple equality checks on the same field within one inner list are
    legitimate and idiomatic — they express "field is one of [A, B, C]".

    Earlier versions of this linter flagged that pattern as a bug; those
    reports were false positives. Any "fixes" based on those reports are
    regressions and should be reverted.

    Retained as a stub returning no findings so existing callers don't break.
    """
    return []


def main():
    ap = argparse.ArgumentParser(
        description="Lint XSIAM playbooks for broken ${X / Y} references and AND-impossible conditions.",
    )
    ap.add_argument(
        "paths",
        nargs="+",
        help="Pack directories or individual playbook YAML files to lint.",
    )
    ap.add_argument(
        "--quiet",
        action="store_true",
        help="Only print files with bugs; suppress per-file success lines.",
    )
    ap.add_argument(
        "--fix",
        action="store_true",
        help="Auto-repair stale numeric-key findings in place "
             "(check #5 only; checks 1-4 remain report-only).",
    )
    args = ap.parse_args()

    total_files = 0
    total_interp = 0
    total_cond = 0
    total_refs = 0
    total_scratch = 0
    total_dupes = 0
    total_stale = 0
    total_repaired = 0
    failing_files = []
    pack_failures = []

    for raw in args.paths:
        path = Path(raw)
        if not path.exists():
            print(f"  SKIP  {path} (not found)", file=sys.stderr)
            continue

        # Pack-level checks — run once per input path (when path is a pack or dir)
        if path.is_dir():
            scratch = check_scratch_files(path)
            dupes = check_duplicate_content(path)
            if scratch or dupes:
                pack_failures.append(path)
                print(f"\n  FAIL  {path} (pack-level)")
                if scratch:
                    print(f"        Scratch / backup / OS-copy files ({len(scratch)}):")
                    for f in scratch:
                        print(f"          {f['path']}  (matches pattern: {f['pattern']})")
                    total_scratch += len(scratch)
                if dupes:
                    print(f"        Duplicate content ({len(dupes)}):")
                    for d in dupes:
                        print(f"          sha256[{d['hash']}] appears in:")
                        for f in d["files"]:
                            print(f"              {f}")
                    total_dupes += len(dupes)

        for yml in find_yaml_files(path):
            total_files += 1
            interp_bugs = check_broken_interpolation(yml)
            cond_bugs = check_and_impossible_conditions(yml)
            ref_bugs = check_broken_task_refs(yml)
            stale_bugs = check_stale_numeric_keys(yml)

            # --fix is opt-in and only repairs stale-key findings; other
            # categories require human judgment so they stay report-only.
            if stale_bugs and args.fix:
                cief_n, input_n = fix_stale_numeric_keys(yml)
                if cief_n or input_n:
                    total_repaired += cief_n + input_n
                    print(f"  FIX   {yml}  (cief={cief_n}, inputs={input_n})")
                    # Re-check so anything --fix can't repair still surfaces.
                    stale_bugs = check_stale_numeric_keys(yml)

            if not interp_bugs and not cond_bugs and not ref_bugs and not stale_bugs:
                if not args.quiet:
                    print(f"  OK    {yml}")
                continue

            failing_files.append(yml)
            print(f"\n  FAIL  {yml}")

            if interp_bugs:
                print(f"        Broken ${{X / Y}} context references ({len(interp_bugs)}):")
                for b in interp_bugs:
                    print(f"          line {b['line']}: {b['root']}  {b['accessor']}")
                total_interp += len(interp_bugs)

            if cond_bugs:
                print(f"        AND-impossible conditions ({len(cond_bugs)}):")
                for b in cond_bugs:
                    print(
                        f"          task {b['task_id']} '{b['task_name']}' "
                        f"label='{b['label']}' block[{b['block']}]: "
                        f"{b['field']} must equal ALL of {b['values']}"
                    )
                total_cond += len(cond_bugs)

            if ref_bugs:
                print(f"        Broken task references ({len(ref_bugs)}):")
                for b in ref_bugs:
                    print(
                        f"          task {b['task_id']} '{b['task_name']}' "
                        f"branch '{b['branch']}' → missing task {b['missing_target']!r}"
                    )
                total_refs += len(ref_bugs)

            if stale_bugs:
                print(f"        Stale numeric keys ({len(stale_bugs)}):")
                for b in stale_bugs:
                    hint = " [stale numeric key]" if b["is_numeric"] else ""
                    print(
                        f"          {b['location']}: '{b['key']}' "
                        f"→ should be '{b['expected']}'{hint}"
                    )
                total_stale += len(stale_bugs)

    print()
    print(f"  Scanned: {total_files} playbook file(s)")
    print(f"  Broken interpolations: {total_interp}")
    print(f"  AND-impossible conditions: {total_cond}")
    print(f"  Broken task references: {total_refs}")
    print(f"  Scratch / backup files: {total_scratch}")
    print(f"  Duplicate content: {total_dupes}")
    print(f"  Stale numeric keys: {total_stale}")
    if total_repaired:
        print(f"  Auto-repaired (--fix): {total_repaired}")

    total_failing = len(failing_files) + len(pack_failures)
    if total_failing:
        print(f"  Result: {total_failing} issue(s) found")
        return 1
    print("  Result: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
