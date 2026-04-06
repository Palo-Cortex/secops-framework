#!/usr/bin/env python3
"""
normalize_contribution.py
─────────────────────────
Strips XSIAM UI export artifacts from contributed playbooks and list JSONs,
producing repo-ready files in place.

Contributors upload content directly into the correct pack directory via the
GitHub web UI. This script cleans up UI export artifacts before pack_prep
and SDK upload run.

Handles:
  Playbook YAML  — strips export fields, resets identity, fixes task keys
  List JSON      — verifies/sets id and name from JSON content or --name

Does NOT:
  - Run SDK validation (that is pack_prep.py)
  - Check SOC Framework contracts (that is check_contracts.py)

CRITICAL: All playbook edits are textual string replacements.
  yaml.dump is never used — it reorders keys and corrupts XSIAM playbook structure.

Usage:
  # Single file — normalize a UI export in place
  python3 tools/normalize_contribution.py \\
      --input Packs/soc-framework-nist-ir/Playbooks/SOC_Email_Exposure_Evaluation_V3_copy.yml

  # Entire pack directory
  python3 tools/normalize_contribution.py \\
      --input Packs/soc-framework-nist-ir

  # Override canonical name
  python3 tools/normalize_contribution.py \\
      --input Packs/soc-framework-nist-ir/Playbooks/SOC_Email_Exposure_Evaluation_V3_copy.yml \\
      --name "SOC Email Exposure Evaluation_V3"

  # Preview changes without writing — used by CI
  python3 tools/normalize_contribution.py \\
      --input Packs/soc-framework-nist-ir \\
      --dry-run

  # Write to a different location instead of in place
  python3 tools/normalize_contribution.py \\
      --input Packs/soc-framework-nist-ir/Playbooks/SOC_Email_Exposure_Evaluation_V3_copy.yml \\
      --out /tmp/review/

Output:
  By default, normalized files are written back to the same location as the
  input (in place). Use --out to redirect to a different directory or file.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional


# ── Pack metadata registry ────────────────────────────────────────────────────
# pack_id → canonical display name
PACK_NAMES = {
    "soc-framework-nist-ir":           "SOC Framework NIST IR",
    "soc-optimization-unified":        "SOC Framework Foundation",
    "SocFrameworkCrowdstrikeFalcon":   "SOC Framework CrowdStrike Falcon",
    "SocFrameworkProofPointTap":       "SOC Framework Proofpoint TAP",
    "soc-microsoft-defender":          "SOC Framework Microsoft Defender",
    "soc-microsoft-defender-email":    "SOC Framework Microsoft Defender Email",
    "SocFrameworkTrendMicroVisionOne": "SOC Framework Trend Micro Vision One",
}

# packName string variants (from XSIAM UI exports) → pack_id
# Covers old names, suffixes, capitalisation variants
PACK_NAME_TO_ID = {
    # nist-ir variants
    "soc framework nist ir":              "soc-framework-nist-ir",
    "soc framework nist ir (800-61)":     "soc-framework-nist-ir",
    "soc framework nist ir 800-61":       "soc-framework-nist-ir",
    # soc-optimization-unified variants
    "soc framework foundation":           "soc-optimization-unified",
    "soc optimization unified":           "soc-optimization-unified",
    "soc-optimization-unified":           "soc-optimization-unified",
    # vendor packs
    "soc framework crowdstrike falcon":   "SocFrameworkCrowdstrikeFalcon",
    "soc framework proofpoint tap":       "SocFrameworkProofPointTap",
    "soc framework microsoft defender":   "soc-microsoft-defender",
    "soc framework microsoft defender email": "soc-microsoft-defender-email",
    "soc framework trend micro vision one":   "SocFrameworkTrendMicroVisionOne",
}

# Lists always live in soc-optimization-unified regardless of which pack
# the contribution was submitted against.
LIST_PACK_ID = "soc-optimization-unified"


def detect_pack(content_type: str, text_or_data, override: Optional[str]) -> tuple:
    """
    Determine the target pack ID for a file.
    Returns (pack_id, pack_name, detection_method).
    override wins if provided.
    """
    if override:
        return override, PACK_NAMES.get(override, override), "explicit --pack"

    if content_type == "list":
        pid = LIST_PACK_ID
        return pid, PACK_NAMES.get(pid, pid), "auto (lists always → soc-optimization-unified)"

    if content_type == "playbook":
        # Read packName from contentitemfields
        m = re.search(r"[ \t]*packName\s*:\s*(.+)$", text_or_data, re.MULTILINE)
        if m:
            raw = m.group(1).strip().strip("\'\"")
            key = raw.lower()
            pid = PACK_NAME_TO_ID.get(key)
            if pid:
                return pid, PACK_NAMES.get(pid, pid), f"auto (packName: \'{raw}\')"

    return None, None, "unknown"

# ── UI export top-level keys to strip ────────────────────────────────────────
PLAYBOOK_DROP_KEYS = {
    "sourceplaybookid",
    "dirtyInputs",
    "vcShouldKeepItemLegacyProdMachine",
    "inputSections",
    "outputSections",
}

# ── Suffix patterns to strip from names ──────────────────────────────────────
# Only strip copy/export artifacts — _V3 is part of canonical naming, never strip it
NAME_SUFFIX_RE = re.compile(
    r"(?:_copy|_Copy|_export|_Export|_bak|_Bak|_old|_Old)+\s*$",
    re.IGNORECASE,
)

# A top-level YAML key: starts at column 0 with a word char, has a colon
_TOP_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*:")


# ── ANSI colours ──────────────────────────────────────────────────────────────
_TTY = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def OK(t):   return _c("32;1", t)
def WARN(t): return _c("33;1", t)
def ERR(t):  return _c("31;1", t)
def INFO(t): return _c("36",   t)
def DIM(t):  return _c("2",    t)


# ─────────────────────────────────────────────────────────────────────────────
# Content-type detection
# ─────────────────────────────────────────────────────────────────────────────

def detect_type(path: Path) -> Optional[str]:
    """
    Returns 'playbook', 'list', 'correlation_rule', or None.
    Detection is structural — does not rely on filename or extension.
    """
    suffix = path.suffix.lower()

    if suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return "list"
        except Exception:
            pass
        return None

    if suffix in (".yml", ".yaml"):
        try:
            content = path.read_text(encoding="utf-8")
        except Exception:
            return None
        if re.search(r"^tasks\s*:", content, re.MULTILINE):
            return "playbook"
        if re.search(r"^xql_query\s*:", content, re.MULTILINE):
            return "correlation_rule"

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Name helpers
# ─────────────────────────────────────────────────────────────────────────────

def canonical_name(raw: str) -> str:
    """Strip UI copy/export suffixes. Never strips _V3."""
    return NAME_SUFFIX_RE.sub("", raw).strip()


# ─────────────────────────────────────────────────────────────────────────────
# Playbook normalization — purely textual, no yaml.dump
# ─────────────────────────────────────────────────────────────────────────────

def _strip_top_level_key(text: str, key: str) -> tuple:
    """
    Remove a top-level YAML key and its entire value block.

    Handles:
      scalar:           key: value
      indented block:   key:\n  sub: val
      column-0 list:    key:\n- item        (XSIAM inputSections / outputSections)

    A continuation line is consumed if it:
      - is blank / whitespace-only
      - is indented (starts with space or tab)
      - starts with '-' at column 0 (block sequence item)

    Stops at the next column-0 YAML key.

    Returns (new_text, changed).
    """
    key_pattern = re.compile(
        r"^" + re.escape(key) + r"\s*:.*\n",
        re.MULTILINE,
    )
    m = key_pattern.search(text)
    if not m:
        return text, False

    start = m.start()
    end   = m.end()

    # Walk subsequent lines and consume those that belong to this value
    lines = text[end:].splitlines(keepends=True)
    consumed = 0
    for line in lines:
        # Blank line — always part of continuation
        if not line.strip():
            consumed += len(line)
            continue
        first_char = line[0]
        # Indented or list-item at col 0 — still part of this value
        if first_char in (" ", "\t", "-"):
            consumed += len(line)
            continue
        # Next top-level key — stop
        if _TOP_KEY_RE.match(line):
            break
        # Comments, document markers, etc. — consume
        consumed += len(line)

    return text[:start] + text[end + consumed:], True


def _reset_scalar(text: str, key: str, value: str) -> tuple:
    """
    Replace a top-level scalar key's value in raw YAML text.
    Returns (new_text, changed).
    """
    pattern = re.compile(r"^" + re.escape(key) + r"\s*:.*$", re.MULTILINE)
    new_line = f"{key}: {value}"
    m = pattern.search(text)
    if not m:
        return text, False
    if m.group(0) == new_line:
        return text, False
    return text[:m.start()] + new_line + text[m.end():], True


def _ensure_adopted_first(text: str) -> tuple:
    """
    Move 'adopted: true' to the first non-comment line.
    Returns (new_text, changed).
    """
    lines = text.splitlines(keepends=True)

    first_content = next(
        (i for i, l in enumerate(lines)
         if l.strip() and not l.strip().startswith("#")),
        0,
    )

    if lines[first_content].rstrip() == "adopted: true":
        return text, False  # already first

    # Remove existing adopted line (wherever it is)
    adopted_re = re.compile(r"^adopted\s*:\s*true[ \t]*\n?", re.MULTILINE)
    text_clean = adopted_re.sub("", text)

    # Re-find first content line and insert there
    lines_clean = text_clean.splitlines(keepends=True)
    first = next(
        (i for i, l in enumerate(lines_clean)
         if l.strip() and not l.strip().startswith("#")),
        0,
    )
    lines_clean.insert(first, "adopted: true\n")
    return "".join(lines_clean), True


def _normalize_scriptname(text: str) -> tuple:
    """
    Replace indented 'scriptName:' with 'script:' inside task blocks.
    Top-level 'scriptName:' (scripts directory) is left untouched.
    Returns (new_text, changed).
    """
    pattern = re.compile(r"^(\s+)scriptName(\s*:)", re.MULTILINE)
    new_text, n = pattern.subn(r"\1script\2", text)
    return new_text, n > 0


def _fix_task_id_mismatches(text: str) -> tuple:
    """
    Ensure each task's inner task.id matches its outer taskid.

    Pattern in XSIAM YAML:
      taskid: <outer-uuid>
      ...
      task:
        id: <inner-uuid>   ← must equal outer

    Strategy: for each taskid: line, scan the next ~600 chars for
    the 'task:\\n  id:' pattern and replace the inner uuid if it differs.

    Returns (new_text, changed).
    """
    outer_re = re.compile(
        r"^([ \t]*taskid\s*:\s*)([0-9a-fA-F\-]{36})([ \t]*\n)",
        re.MULTILINE,
    )
    inner_id_re = re.compile(
        r"([ \t]*task\s*:\s*\n[ \t]*id\s*:\s*)([0-9a-fA-F\-]{36})",
    )

    changed = False
    result  = text

    for outer_m in outer_re.finditer(text):
        outer_uuid = outer_m.group(2)
        window_start = outer_m.end()
        window_end   = min(window_start + 600, len(text))
        window       = text[window_start:window_end]

        inner_m = inner_id_re.search(window)
        if not inner_m:
            continue
        if inner_m.group(2) == outer_uuid:
            continue

        # Locate and replace in result (offsets may have shifted)
        search_from = outer_m.start()
        abs_pos = result.find(inner_m.group(0), search_from)
        if abs_pos == -1:
            continue

        old_inner = inner_m.group(0)
        new_inner = inner_m.group(1) + outer_uuid
        result  = result[:abs_pos] + new_inner + result[abs_pos + len(old_inner):]
        changed = True

    return result, changed


def _renumber_alphanumeric_task_ids(text: str) -> tuple:
    """
    Replace non-integer task IDs (e.g. '18a', '18b') with sequential integers.
    Updates both the task key declarations and all nexttasks references.

    Returns (new_text, changed).
    """
    # Task IDs in XSIAM YAML are always quoted ('0':, '18a':).
    # Unquoted keys at the same indent (task:, nexttasks:) are structural — skip them.
    task_key_re = re.compile(r"^  ['\"]([\w\-]+)['\"]\s*:\s*$", re.MULTILINE)

    alpha_ids = []
    max_int   = -1

    for m in task_key_re.finditer(text):
        tid = m.group(1)
        if re.match(r"^-?\d+$", tid):
            max_int = max(max_int, int(tid))
        else:
            if tid not in alpha_ids:
                alpha_ids.append(tid)

    if not alpha_ids:
        return text, False

    # Assign new integer IDs
    mapping = {}
    next_id = max_int + 1
    for alpha in alpha_ids:
        mapping[alpha] = str(next_id)
        next_id += 1

    result  = text
    changed = False

    for old_id, new_id in mapping.items():
        escaped = re.escape(old_id)

        # Task key declaration:  '18a':  or  18a:
        decl_re = re.compile(
            r"^(  )['\"]?" + escaped + r"['\"]?(\s*:)",
            re.MULTILINE,
        )
        result, n = decl_re.subn(r"\g<1>'" + new_id + r"'\2", result)
        if n:
            changed = True

        # nexttasks reference:  - '18a'  or  - "18a"  or  - 18a
        ref_re = re.compile(r"(- )['\"]?" + escaped + r"['\"]?")
        result, n = ref_re.subn(r"\g<1>'" + new_id + "'", result)
        if n:
            changed = True

    return result, changed


def _set_packid_packname(text: str, pack_id: str, pack_name: str) -> tuple:
    """
    Set packID and packName inside contentitemexportablefields.contentitemfields.
    Uses targeted regex — does not reserialize YAML.
    Returns (new_text, changed).
    """
    changed = False

    packid_re = re.compile(r"([ \t]*packID\s*:\s*).*$", re.MULTILINE)
    m = packid_re.search(text)
    if m:
        new_line = m.group(1) + pack_id
        if m.group(0) != new_line:
            text    = text[:m.start()] + new_line + text[m.end():]
            changed = True

    packname_re = re.compile(r"([ \t]*packName\s*:\s*).*$", re.MULTILINE)
    m = packname_re.search(text)
    if m:
        new_line = m.group(1) + pack_name
        if m.group(0) != new_line:
            text    = text[:m.start()] + new_line + text[m.end():]
            changed = True

    return text, changed


def normalize_playbook(
    text: str,
    pack_id: str,
    pack_name: str,
    override_name: Optional[str] = None,
) -> tuple:
    """
    Apply all normalization steps to a playbook YAML string.
    Returns (normalized_text, list_of_change_descriptions).
    """
    changes = []

    # 1. Strip UI export top-level keys
    for key in PLAYBOOK_DROP_KEYS:
        text, changed = _strip_top_level_key(text, key)
        if changed:
            changes.append(f"stripped: {key}")

    # 2. Canonical name
    name_m = re.search(r"^name\s*:\s*(.+)$", text, re.MULTILINE)
    if name_m:
        raw_name = name_m.group(1).strip().strip("'\"")
        canon    = override_name if override_name else canonical_name(raw_name)
        if canon != raw_name:
            text, changed = _reset_scalar(text, "name", canon)
            if changed:
                changes.append(f"name: '{raw_name}' → '{canon}'")

        # 3. id: set to canonical name
        id_m = re.search(r"^id\s*:\s*(.+)$", text, re.MULTILINE)
        if id_m:
            current_id = id_m.group(1).strip().strip("'\"")
            if current_id != canon:
                text, changed = _reset_scalar(text, "id", canon)
                if changed:
                    changes.append(f"id: '{current_id}' → '{canon}'")

    # 4. version: -1
    ver_m = re.search(r"^version\s*:\s*(.+)$", text, re.MULTILINE)
    if ver_m and ver_m.group(1).strip() != "-1":
        text, changed = _reset_scalar(text, "version", "-1")
        if changed:
            changes.append(f"version: {ver_m.group(1).strip()} → -1")

    # 5. adopted: true → first line
    text, changed = _ensure_adopted_first(text)
    if changed:
        changes.append("adopted: true moved to first line")

    # 6. packID / packName
    text, changed = _set_packid_packname(text, pack_id, pack_name)
    if changed:
        changes.append(f"packID → {pack_id}  packName → {pack_name}")

    # 7. scriptName → script (task blocks only)
    text, changed = _normalize_scriptname(text)
    if changed:
        changes.append("scriptName → script (all tasks)")

    # 8. Fix inner task.id mismatches
    text, changed = _fix_task_id_mismatches(text)
    if changed:
        changes.append("fixed task inner id to match outer taskid")

    # 9. Renumber alphanumeric task IDs
    text, changed = _renumber_alphanumeric_task_ids(text)
    if changed:
        changes.append("renumbered alphanumeric task IDs to integers")

    return text, changes


# ─────────────────────────────────────────────────────────────────────────────
# List JSON normalization
# ─────────────────────────────────────────────────────────────────────────────

def normalize_list(data: dict, canon: str) -> tuple:
    """
    Ensure top-level id and name match canon.
    Returns (normalized_data, list_of_changes).
    """
    changes = []
    if data.get("id") != canon:
        changes.append(f"id: '{data.get('id')}' → '{canon}'")
        data["id"] = canon
    if data.get("name") != canon:
        changes.append(f"name: '{data.get('name')}' → '{canon}'")
        data["name"] = canon
    return data, changes


# ─────────────────────────────────────────────────────────────────────────────
# Output path resolution
# ─────────────────────────────────────────────────────────────────────────────

def resolve_output_path(input_path: Path, out_dir: Optional[Path]) -> Path:
    if out_dir is None:
        # Default: write in place (same path as input)
        return input_path

    if out_dir.suffix:  # looks like a file path
        out_dir.parent.mkdir(parents=True, exist_ok=True)
        return out_dir

    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / input_path.name


# ─────────────────────────────────────────────────────────────────────────────
# Per-file processing
# ─────────────────────────────────────────────────────────────────────────────

def process_file(
    input_path: Path,
    pack_override: Optional[str],
    override_name: Optional[str],
    out_dir: Optional[Path],
    dry_run: bool,
) -> bool:
    content_type = detect_type(input_path)

    if content_type is None:
        print(WARN(f"  ⚠  {input_path.name}: unrecognized content type — skipping"))
        return False

    # ── Resolve pack for this file ────────────────────────────────────────────
    # Read raw text/data first so detect_pack can inspect packName for playbooks
    if content_type == "playbook":
        try:
            raw_text = input_path.read_text(encoding="utf-8")
        except Exception as e:
            print(ERR(f"    ✗ read error: {e}"))
            return False
        pack_id, pack_name, method = detect_pack(content_type, raw_text, pack_override)
    else:
        raw_text = None
        pack_id, pack_name, method = detect_pack(content_type, None, pack_override)

    if not pack_id:
        print(ERR(
            f"  ✗ {input_path.name}: could not detect target pack.\n"
            f"    Run with --pack <pack-id> to specify explicitly."
        ))
        return False

    print(f"\n  {INFO(content_type.upper())}  {DIM(str(input_path))}")
    print(f"    pack: {INFO(pack_id)}  {DIM(f'({method})')}")

    # ── Playbook ──────────────────────────────────────────────────────────────
    if content_type == "playbook":
        text = raw_text
        normalized, changes = normalize_playbook(text, pack_id, pack_name, override_name)

        if not changes:
            print(OK("    ✓ already clean — no changes needed"))
            return False

        prefix = "(dry-run) " if dry_run else ""
        for c in changes:
            print(f"    {prefix}{OK('●')} {c}")

        if not dry_run:
            out_path = resolve_output_path(input_path, out_dir)
            out_path.write_text(normalized, encoding="utf-8")
            print(f"    {OK('→')} {out_path}")

        return True

    # ── List JSON ─────────────────────────────────────────────────────────────
    if content_type == "list":
        try:
            data = json.loads(input_path.read_text(encoding="utf-8"))
        except Exception as e:
            print(ERR(f"    ✗ JSON parse error: {e}"))
            return False
        # pack_id already resolved above via detect_pack → LIST_PACK_ID

        # Canonical name: --name → JSON id (if no copy artifact) → filename stem
        if override_name:
            canon = override_name
        else:
            json_id = data.get("id") or data.get("name") or ""
            if json_id and not NAME_SUFFIX_RE.search(json_id):
                canon = json_id
            else:
                canon = NAME_SUFFIX_RE.sub("", input_path.stem).strip()

        normalized, changes = normalize_list(data, canon)

        if not changes:
            print(OK("    ✓ already clean — no changes needed"))
            return False

        prefix = "(dry-run) " if dry_run else ""
        for c in changes:
            print(f"    {prefix}{OK('●')} {c}")

        if not dry_run:
            out_path = resolve_output_path(input_path, out_dir)
            out_path.write_text(
                json.dumps(normalized, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            print(f"    {OK('→')} {out_path}")

        return True

    # ── Correlation rule ──────────────────────────────────────────────────────
    if content_type == "correlation_rule":
        print(WARN("    ⚠  correlation rule — use normalize_ruleid_adopted.py"))
        return False

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Directory walk
# ─────────────────────────────────────────────────────────────────────────────

def collect_input_files(input_path: Path) -> list:
    if input_path.is_file():
        return [input_path]

    files = []
    for p in sorted(input_path.rglob("*")):
        if not p.is_file():
            continue
        if any(part.startswith(".") for part in p.parts):
            continue
        if "normalized" in p.parts:
            continue
        if p.suffix.lower() in (".yml", ".yaml", ".json"):
            files.append(p)
    return files


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Normalize XSIAM UI export artifacts from contributed pack content",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--input", "-i", required=True,
                        help="File or directory to normalize")
    parser.add_argument("--pack", default=None,
                        help="Override target pack ID. Auto-detected if omitted.")
    parser.add_argument("--name", default=None,
                        help="Override canonical name (default: auto-strip suffix)")
    parser.add_argument("--out", "-o", default=None,
                        help="Output file or directory (default: in place, same as input)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show changes without writing")
    args = parser.parse_args()

    pack_override = args.pack
    input_path    = Path(args.input).resolve()
    out_dir       = Path(args.out).resolve() if args.out else None

    if not input_path.exists():
        print(ERR(f"✗ not found: {input_path}"))
        sys.exit(1)

    print()
    print("━" * 58)
    print("  normalize_contribution.py")
    if pack_override:
        print(f"  pack : {INFO(pack_override)} (override)")
    else:
        print(f"  pack : {DIM('auto-detect per file')}")
    if args.dry_run:
        print(f"  mode : {WARN('dry-run — no files written')}")
    else:
        print(f"  mode : {OK('fix')}")
    print("━" * 58)

    files = collect_input_files(input_path)
    if not files:
        print(WARN("  no processable files found"))
        sys.exit(0)

    total_changed = 0
    for f in files:
        if process_file(f, pack_override, args.name, out_dir, args.dry_run):
            total_changed += 1

    print()
    print("━" * 58)
    if total_changed == 0:
        print(OK("  ✓ all files already clean"))
    elif args.dry_run:
        print(WARN(f"  {total_changed} file(s) need changes (dry-run — nothing written)"))
        sys.exit(1)
    else:
        print(OK(f"  ✓ {total_changed} file(s) normalized"))
    print("━" * 58)
    print()


if __name__ == "__main__":
    main()
