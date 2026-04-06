#!/usr/bin/env python3
"""
normalize_contribution.py
─────────────────────────────────────────────────────────────────────────────
Strips XSIAM UI export artifacts from contributed playbooks and list JSONs.

SCOPE — what this script processes
───────────────────────────────────
By default the script uses `git diff origin/main` to find only the files
that were added or modified on the current branch. This is the safe default:
it never touches infrastructure files, existing repo content, or any file
that was not part of the current contribution.

Use --input <file> to point at a specific file explicitly (e.g. when running
outside a git repo, or to normalise a single known file).

CONTENT TYPE ROUTING — based on directory, not filename
────────────────────────────────────────────────────────
The directory a file lives in determines what it is and how it is processed.
The script never guesses from file contents alone.

  Packs/<pack>/Playbooks/*.yml      → playbook normalizer
  Packs/<pack>/Lists/**/*.json      → list normalizer
  Packs/<pack>/Scripts/             → identified but skipped (future work)
  Anything else                     → skipped silently

Infrastructure files that are ALWAYS skipped regardless of location:
  pack_metadata.json, xsoar_config.json, README.md, POST_CONFIG_README.md,
  .pack-ignore, .secrets-ignore, Author_image.png, ReleaseNotes/

PACK IDENTITY — derived from path, never guessed
─────────────────────────────────────────────────
The pack is always read from the file's path:
  Packs/soc-framework-nist-ir/Playbooks/foo.yml → soc-framework-nist-ir

The packName field inside the file is used as a cross-check only. If it
disagrees with the path, a warning is printed but the path always wins.
This means the script works correctly on repo-origin files that have no
packName field, and on files freshly exported from the UI.

WHAT GETS FIXED — playbooks
────────────────────────────
  - Strips UI export top-level keys:
      sourceplaybookid, dirtyInputs, vcShouldKeepItemLegacyProdMachine,
      inputSections, outputSections
  - Strips copy/export suffixes from name and id fields (_copy, _export, etc.)
  - Resets version to -1
  - Moves adopted: true to the first line
  - Sets packID and packName in contentitemfields to match the pack directory
  - Normalises scriptName → script in all task blocks
  - Fixes inner task.id to match outer taskid where they differ
  - Renumbers alphanumeric task IDs (e.g. 18a, 18b) to integers

WHAT GETS FIXED — lists
────────────────────────
  - Sets id and name to match the list directory name (SDK requirement)

WHAT IS NEVER TOUCHED
──────────────────────
  - pack_metadata.json
  - xsoar_config.json
  - IncidentFields, Layouts, CorrelationRules, ModelingRules, etc.
  - Scripts (identified, flagged for manual review)
  - Any file not changed on the current branch (when using git diff mode)

CRITICAL — all playbook edits are textual string replacements
─────────────────────────────────────────────────────────────
yaml.dump is never used. It reorders keys and corrupts XSIAM playbook
structure. Every change is a targeted regex or string replacement on the
raw file text.

Usage:
  # Normalise only what changed on this branch (safe default)
  python3 tools/normalize_contribution.py

  # Preview without writing (used by CI)
  python3 tools/normalize_contribution.py --dry-run

  # Normalise a specific file explicitly
  python3 tools/normalize_contribution.py --input Packs/soc-framework-nist-ir/Playbooks/SOC_Email_Exposure_Evaluation_V3_copy.yml

  # Normalise everything in a specific pack (only changed files)
  python3 tools/normalize_contribution.py --input Packs/soc-framework-nist-ir
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Pack registry
# ─────────────────────────────────────────────────────────────────────────────

# Maps pack directory name → canonical display name used in contentitemfields.
# Add a new line here when a new pack is added to the repo.
PACK_NAMES: dict[str, str] = {
    "soc-framework-nist-ir":           "SOC Framework NIST IR",
    "soc-optimization-unified":        "SOC Framework Foundation",
    "SocFrameworkCrowdstrikeFalcon":   "SOC Framework CrowdStrike Falcon",
    "SocFrameworkProofPointTap":       "SOC Framework Proofpoint TAP",
    "soc-microsoft-defender":          "SOC Framework Microsoft Defender",
    "soc-microsoft-defender-email":    "SOC Framework Microsoft Defender Email",
    "SocFrameworkTrendMicroVisionOne": "SOC Framework Trend Micro Vision One",
}

# Reverse lookup: packName strings from XSIAM UI exports → pack directory name.
# Covers name variants, old suffixes, and capitalisation differences.
# Used only as a cross-check against the path-derived pack ID.
PACK_NAME_TO_ID: dict[str, str] = {
    "soc framework nist ir":                  "soc-framework-nist-ir",
    "soc framework nist ir (800-61)":         "soc-framework-nist-ir",
    "soc framework nist ir 800-61":           "soc-framework-nist-ir",
    "soc framework foundation":               "soc-optimization-unified",
    "soc optimization unified":               "soc-optimization-unified",
    "soc-optimization-unified":               "soc-optimization-unified",
    "soc framework crowdstrike falcon":        "SocFrameworkCrowdstrikeFalcon",
    "soc framework proofpoint tap":           "SocFrameworkProofPointTap",
    "soc framework microsoft defender":       "soc-microsoft-defender",
    "soc framework microsoft defender email": "soc-microsoft-defender-email",
    "soc framework trend micro vision one":   "SocFrameworkTrendMicroVisionOne",
}


# ─────────────────────────────────────────────────────────────────────────────
# File exclusions
# ─────────────────────────────────────────────────────────────────────────────

# These filenames are always skipped unconditionally, regardless of where
# they live in the pack directory tree.
NEVER_PROCESS_FILENAMES: set[str] = {
    "pack_metadata.json",
    "xsoar_config.json",
    "README.md",
    "POST_CONFIG_README.md",
    ".pack-ignore",
    ".secrets-ignore",
    "Author_image.png",
    "CHANGELOG.md",
}

# Files in these directories are skipped. They have their own SDK schema
# and are not subject to the UI export normalisation that playbooks and
# lists need. Extend this set when new content type directories are added.
SKIP_CONTENT_DIRS: set[str] = {
    "IncidentFields",
    "IncidentTypes",
    "Layouts",
    "CorrelationRules",
    "ModelingRules",
    "XSIAMDashboards",
    "Dashboards",
    "Integrations",
    "Classifiers",
    "Widgets",
    "Triggers",
    "TestPlaybooks",
    "GenericDefinitions",
    "GenericModules",
    "GenericTypes",
    "Indicators",
    "Reports",
    "ReleaseNotes",
    "Automations",
    "Lookup",
}

# Suffix patterns stripped from playbook name and id fields.
# Only removes explicit copy/export markers — never strips _V3 or other
# version suffixes that are part of the canonical naming convention.
NAME_SUFFIX_RE = re.compile(
    r"(?:_copy|_Copy|_export|_Export|_bak|_Bak|_old|_Old)+\s*$",
    re.IGNORECASE,
)

# A top-level YAML key at column 0: word character, followed eventually by ':'
_TOP_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*:")


# ─────────────────────────────────────────────────────────────────────────────
# ANSI colour helpers
# ─────────────────────────────────────────────────────────────────────────────

_TTY = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def OK(t):   return _c("32;1", t)
def WARN(t): return _c("33;1", t)
def ERR(t):  return _c("31;1", t)
def INFO(t): return _c("36",   t)
def DIM(t):  return _c("2",    t)


# ─────────────────────────────────────────────────────────────────────────────
# Path analysis — derive pack and content type from the file's location
# ─────────────────────────────────────────────────────────────────────────────

def pack_from_path(path: Path) -> Optional[str]:
    """
    Derive the pack ID from the file's path.

    Looks for a 'Packs' component in the path and returns the next segment.
    Example: Packs/soc-framework-nist-ir/Playbooks/foo.yml → soc-framework-nist-ir

    Returns None if the file is not under a Packs directory.
    """
    parts = path.parts
    for i, part in enumerate(parts):
        if part == "Packs" and i + 1 < len(parts):
            return parts[i + 1]
    return None


def content_dir_from_path(path: Path) -> Optional[str]:
    """
    Return the content type directory name for this file.

    Looks for known content type directory names in the path.
    Example: Packs/soc-framework-nist-ir/Playbooks/foo.yml → 'Playbooks'

    Returns None if the file is not under a recognised content type directory.
    """
    known_dirs = {
        "Playbooks", "Lists", "Scripts",
        *SKIP_CONTENT_DIRS,
    }
    for part in path.parts:
        if part in known_dirs:
            return part
    return None


def should_skip(path: Path) -> tuple[bool, str]:
    """
    Determine whether a file should be skipped entirely.

    Returns (skip, reason) where reason is a human-readable explanation.
    """
    # Always skip by filename
    if path.name in NEVER_PROCESS_FILENAMES:
        return True, f"infrastructure file ({path.name})"

    # Always skip hidden files and macOS metadata
    if path.name.startswith(".") or path.name.startswith("._"):
        return True, "hidden/metadata file"

    # Always skip files we can't process.
    # .txt is accepted for list JSON exports — XSIAM sometimes exports lists
    # with a .txt extension. Content is still JSON; we detect by directory.
    if path.suffix.lower() not in (".yml", ".yaml", ".json", ".txt"):
        return True, f"unsupported extension ({path.suffix})"

    # Skip files in content type directories that we don't normalise
    content_dir = content_dir_from_path(path)
    if content_dir in SKIP_CONTENT_DIRS:
        return True, f"{content_dir}/ content (not normalised by this tool)"

    return False, ""


def content_type_from_path(path: Path) -> Optional[str]:
    """
    Determine the content type to apply based on directory location.

    Routing:
      Playbooks/*.yml  → 'playbook'
      Lists/**/*.json  → 'list'
      Scripts/         → 'script'
      anything else    → None (skip)
    """
    content_dir = content_dir_from_path(path)

    if content_dir == "Playbooks" and path.suffix.lower() in (".yml", ".yaml"):
        return "playbook"

    # Accept both .json and .txt in Lists/ — XSIAM exports can produce either
    if content_dir == "Lists" and path.suffix.lower() in (".json", ".txt"):
        return "list"

    if content_dir == "Scripts":
        return "script"

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Mislocation detection — read file content to verify it belongs where it landed
# ─────────────────────────────────────────────────────────────────────────────

def content_type_from_content(path: Path) -> Optional[str]:
    """
    Infer content type from what is actually inside the file.

    Used to cross-check against content_type_from_path(). If they disagree,
    the contributor put the file in the wrong directory.

    Detection signals:
      Playbook YAML     — has top-level 'tasks:' mapping
      Correlation rule  — has top-level 'xql_query:'
      Script YAML       — has top-level 'commonfields:' (XSOAR/XSIAM script marker)
      List JSON         — parseable JSON dict (any list content)

    Returns None if the type cannot be determined from content.
    """
    suffix = path.suffix.lower()

    if suffix in (".yml", ".yaml"):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None
        if re.search(r"^tasks\s*:", text, re.MULTILINE):
            return "playbook"
        if re.search(r"^xql_query\s*:", text, re.MULTILINE):
            return "correlation_rule"
        if re.search(r"^commonfields\s*:", text, re.MULTILINE):
            return "script"
        return None

    if suffix in (".json", ".txt"):
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(data, dict):
                return "list"
        except Exception:
            pass
        return None

    return None


# Where each content type should live — used to produce actionable error messages
EXPECTED_DIR: dict[str, str] = {
    "playbook":        "Playbooks/",
    "list":            "Lists/",
    "script":          "Scripts/",
    "correlation_rule": "CorrelationRules/",
}


def check_mislocation(path: Path) -> Optional[str]:
    """
    Return an error message if the file is in the wrong content type directory,
    or None if the location looks correct.

    Compares content_type_from_path() (where it landed) against
    content_type_from_content() (what it actually is).

    Only fires when the two disagree — if we can't determine the type from
    content, we give the contributor the benefit of the doubt and proceed.
    """
    dir_type     = content_type_from_path(path)
    content_type = content_type_from_content(path)

    # Can't determine from content — no basis for an error
    if content_type is None:
        return None

    # Types agree — correctly placed
    if dir_type == content_type:
        return None

    # Types disagree — mislocation
    expected_dir = EXPECTED_DIR.get(content_type, f"{content_type}/")
    actual_dir   = content_dir_from_path(path) or "unknown directory"
    pack_id      = pack_from_path(path) or "<pack>"

    return (
        f"  ✗  MISLOCATION: {path.name}\n"
        f"     This file is a {content_type.upper()} but was placed in {actual_dir}/.\n"
        f"     Move it to: Packs/{pack_id}/{expected_dir}\n"
        f"     Then run normalize again."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Git integration — find what changed on this branch
# ─────────────────────────────────────────────────────────────────────────────

def git_changed_files(base: str = "origin/main") -> list[Path]:
    """
    Return paths of files added or modified relative to base branch.

    Uses --diff-filter=AM to include only Added and Modified files.
    Deleted files are excluded — nothing to normalise there.

    Returns an empty list if git is not available or not in a repo.
    """
    try:
        result = subprocess.run(
            ["git", "diff", base, "--name-only", "--diff-filter=AM"],
            capture_output=True,
            text=True,
            check=True,
        )
        return [Path(f) for f in result.stdout.splitlines() if f.strip()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def collect_files(input_path: Optional[Path], base: str = "origin/main") -> list[Path]:
    """
    Build the list of files to process.

    If input_path is a specific file → process only that file.
    If input_path is a directory     → git diff filtered to files under that directory.
    If input_path is None            → git diff across the entire repo Packs/ tree.

    This ensures the script never processes more than what changed on the
    current branch, even when pointed at an entire pack directory.
    """
    if input_path is not None and input_path.is_file():
        # Explicit single file — process it unconditionally
        return [input_path]

    changed = git_changed_files(base)

    if not changed:
        # No git changes found — fall back to directory walk if input given
        if input_path is not None and input_path.is_dir():
            print(WARN(
                "  ⚠  No git diff results found. Falling back to directory walk.\n"
                "     Make sure you are on a branch and 'git fetch origin' has run."
            ))
            return _walk_directory(input_path)
        return []

    # Filter to Packs/ only (git diff may include tools/, .github/, etc.)
    packs_files = [f for f in changed if f.parts and f.parts[0] == "Packs"]

    # If an input directory was given, further filter to files under it
    if input_path is not None:
        # Normalise input_path to be relative so comparison works
        try:
            rel_input = input_path.resolve().relative_to(Path.cwd())
        except ValueError:
            rel_input = input_path
        packs_files = [
            f for f in packs_files
            if str(f).startswith(str(rel_input))
        ]

    return sorted(packs_files)


def _walk_directory(root: Path) -> list[Path]:
    """
    Walk a directory and return all candidate files.
    Used only as a fallback when git diff returns nothing.
    """
    files = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            skip, _ = should_skip(p)
            if not skip:
                files.append(p)
    return files


# ─────────────────────────────────────────────────────────────────────────────
# Playbook normalisation — textual string replacements, no yaml.dump
# ─────────────────────────────────────────────────────────────────────────────

def _strip_top_level_key(text: str, key: str) -> tuple[str, bool]:
    """
    Remove a top-level YAML key and its entire value block from raw text.

    Handles all YAML value formats:
      scalar:           key: value
      indented block:   key:\n  sub: val\n  sub: val
      column-0 list:    key:\n- item\n- item   (XSIAM inputSections pattern)

    A continuation line belongs to the key's value if it:
      - is blank / whitespace-only
      - starts with a space or tab (indented content)
      - starts with '-' at column 0 (block sequence item)

    Stops consuming when it reaches a line that starts at column 0 with
    a YAML key pattern (word character followed by colon).
    """
    key_pattern = re.compile(r"^" + re.escape(key) + r"\s*:.*\n", re.MULTILINE)
    m = key_pattern.search(text)
    if not m:
        return text, False

    start = m.start()
    end   = m.end()

    # Walk subsequent lines, consuming those that belong to this value
    lines    = text[end:].splitlines(keepends=True)
    consumed = 0
    for line in lines:
        if not line.strip():
            # Blank line — still part of the block
            consumed += len(line)
            continue
        first_char = line[0]
        if first_char in (" ", "\t", "-"):
            # Indented content or block sequence item
            consumed += len(line)
            continue
        if _TOP_KEY_RE.match(line):
            # Next top-level key — stop here
            break
        # Anything else (comments, document markers) — consume
        consumed += len(line)

    return text[:start] + text[end + consumed:], True


def _reset_scalar(text: str, key: str, value: str) -> tuple[str, bool]:
    """
    Set a top-level scalar key to a new value via targeted regex replacement.
    Replaces only the first occurrence (top-level keys appear once).
    Returns (new_text, changed).
    """
    pattern  = re.compile(r"^" + re.escape(key) + r"\s*:.*$", re.MULTILINE)
    new_line = f"{key}: {value}"
    m = pattern.search(text)
    if not m or m.group(0) == new_line:
        return text, False
    return text[:m.start()] + new_line + text[m.end():], True


def _ensure_adopted_first(text: str) -> tuple[str, bool]:
    """
    Ensure 'adopted: true' is the very first non-comment line.

    XSIAM's pack bundle installer requires this field to appear first.
    If it is already first, this is a no-op. If it appears elsewhere
    (e.g. at the end of a UI export), it is moved to the top.
    """
    lines = text.splitlines(keepends=True)

    # Find the index of the first non-blank, non-comment line
    first_content = next(
        (i for i, l in enumerate(lines)
         if l.strip() and not l.strip().startswith("#")),
        0,
    )

    if lines[first_content].rstrip() == "adopted: true":
        return text, False  # already in the right place

    # Remove adopted: true from wherever it currently is
    text_clean  = re.sub(r"^adopted\s*:\s*true[ \t]*\n?", "", text, flags=re.MULTILINE)
    lines_clean = text_clean.splitlines(keepends=True)

    # Re-find first content line after removal and insert adopted: true there
    first = next(
        (i for i, l in enumerate(lines_clean)
         if l.strip() and not l.strip().startswith("#")),
        0,
    )
    lines_clean.insert(first, "adopted: true\n")
    return "".join(lines_clean), True


def _normalize_scriptname(text: str) -> tuple[str, bool]:
    """
    Replace 'scriptName:' with 'script:' inside task blocks.

    The XSIAM UI exports playbook tasks using 'scriptName:' in some versions.
    The SDK and demisto-sdk validate expect 'script:'. This replacement is
    scoped to indented task blocks only (requires leading whitespace) to
    avoid touching top-level YAML keys in script YAMLs.
    """
    pattern  = re.compile(r"^(\s+)scriptName(\s*:)", re.MULTILINE)
    new_text, n = pattern.subn(r"\1script\2", text)
    return new_text, n > 0


def _fix_task_id_mismatches(text: str) -> tuple[str, bool]:
    """
    Ensure each task's inner task.id matches its outer taskid UUID.

    XSIAM UI exports sometimes produce tasks where the outer taskid field
    and the inner task.id field differ. The SDK validates that they match.

    Pattern in YAML:
      taskid: <outer-uuid>      ← identity key used by SDK
      ...
      task:
        id: <inner-uuid>        ← must equal outer taskid

    Strategy: for each 'taskid:' line, scan the next ~600 characters for
    the 'task:\\n  id:' sub-block and replace the inner id if it differs.
    The 600-char window is generous but bounded to avoid false matches
    in large files.
    """
    outer_re   = re.compile(
        r"^([ \t]*taskid\s*:\s*)([0-9a-fA-F\-]{36})([ \t]*\n)",
        re.MULTILINE,
    )
    inner_id_re = re.compile(
        r"([ \t]*task\s*:\s*\n[ \t]*id\s*:\s*)([0-9a-fA-F\-]{36})",
    )

    changed = False
    result  = text

    for outer_m in outer_re.finditer(text):
        outer_uuid   = outer_m.group(2)
        window_start = outer_m.end()
        window_end   = min(window_start + 600, len(text))
        window       = text[window_start:window_end]

        inner_m = inner_id_re.search(window)
        if not inner_m or inner_m.group(2) == outer_uuid:
            continue

        # Locate and replace in the result string (offsets may have shifted
        # from previous substitutions earlier in the same file)
        abs_pos = result.find(inner_m.group(0), outer_m.start())
        if abs_pos == -1:
            continue

        old_inner = inner_m.group(0)
        new_inner = inner_m.group(1) + outer_uuid
        result    = result[:abs_pos] + new_inner + result[abs_pos + len(old_inner):]
        changed   = True

    return result, changed


def _renumber_alphanumeric_task_ids(text: str) -> tuple[str, bool]:
    """
    Replace non-integer task IDs (e.g. '18a', '18b') with sequential integers.

    XSIAM task IDs must be quoted integers. Alphanumeric IDs sometimes appear
    in playbooks built outside the standard UI. This function:
      1. Scans for quoted task key declarations at 2-space indent
      2. Identifies any that are not pure integers
      3. Assigns them the next available integers after the current maximum
      4. Updates both the task key declarations and all nexttasks references

    Task IDs in XSIAM YAML are always quoted ('0':, '18a':). Unquoted keys
    at the same indent level are structural keys (task:, nexttasks:, etc.)
    and are excluded by requiring the quotes in the pattern.
    """
    # Match quoted task key declarations at 2-space indent: '18a':  "0":
    task_key_re = re.compile(r"""^  ['"]([\w\-]+)['"]\s*:\s*$""", re.MULTILINE)

    alpha_ids: list[str] = []
    max_int   = -1

    for m in task_key_re.finditer(text):
        tid = m.group(1)
        if re.match(r"^-?\d+$", tid):
            max_int = max(max_int, int(tid))
        elif tid not in alpha_ids:
            alpha_ids.append(tid)

    if not alpha_ids:
        return text, False

    # Build the old → new mapping starting from max_int + 1
    mapping  = {old: str(max_int + 1 + i) for i, old in enumerate(alpha_ids)}
    result   = text
    changed  = False

    for old_id, new_id in mapping.items():
        escaped = re.escape(old_id)

        # Replace task key declaration: '18a':  →  '25':
        decl_re = re.compile(
            r"^(  )['\"]?" + escaped + r"['\"]?(\s*:)",
            re.MULTILINE,
        )
        result, n = decl_re.subn(r"\g<1>'" + new_id + r"'\2", result)
        if n:
            changed = True

        # Replace nexttasks references: - '18a'  →  - '25'
        ref_re = re.compile(r"(- )['\"]?" + escaped + r"['\"]?")
        result, n = ref_re.subn(r"\g<1>'" + new_id + "'", result)
        if n:
            changed = True

    return result, changed


def _set_packid_packname(text: str, pack_id: str, pack_name: str) -> tuple[str, bool]:
    """
    Set packID and packName inside contentitemexportablefields.contentitemfields.

    The UI export often leaves packID empty ("") and packName set to an
    old variant like 'SOC Framework NIST IR (800-61)'. Both need to match
    the canonical values derived from the pack directory name.

    Uses targeted regex replacement to avoid resérialising the YAML.
    """
    changed = False

    for field, value in (("packID", pack_id), ("packName", pack_name)):
        pattern = re.compile(r"([ \t]*" + field + r"\s*:\s*).*$", re.MULTILINE)
        m = pattern.search(text)
        if m:
            new_line = m.group(1) + value
            if m.group(0) != new_line:
                text    = text[:m.start()] + new_line + text[m.end():]
                changed = True
        # If the field is absent, normalize_ruleid_adopted.py handles insertion

    return text, changed


def normalize_playbook(
    text: str,
    pack_id: str,
    pack_name: str,
    override_name: Optional[str] = None,
) -> tuple[str, list[str]]:
    """
    Apply all normalisation steps to a playbook YAML string.

    Steps run in order. Each step is idempotent — running the script twice
    on an already-normalised file produces no further changes.

    Returns (normalised_text, list_of_human_readable_change_descriptions).
    """
    changes: list[str] = []

    # 1. Strip UI export top-level keys that have no meaning in the repo
    for key in ("sourceplaybookid", "dirtyInputs",
                "vcShouldKeepItemLegacyProdMachine",
                "inputSections", "outputSections"):
        text, changed = _strip_top_level_key(text, key)
        if changed:
            changes.append(f"stripped: {key}")

    # 2. Canonical name — strip copy/export suffixes
    name_m = re.search(r"^name\s*:\s*(.+)$", text, re.MULTILINE)
    if name_m:
        raw_name = name_m.group(1).strip().strip("'\"")
        canon    = override_name if override_name else NAME_SUFFIX_RE.sub("", raw_name).strip()
        if canon != raw_name:
            text, changed = _reset_scalar(text, "name", canon)
            if changed:
                changes.append(f"name: '{raw_name}' → '{canon}'")

        # 3. id must equal the canonical name (not a tenant UUID)
        id_m = re.search(r"^id\s*:\s*(.+)$", text, re.MULTILINE)
        if id_m:
            current_id = id_m.group(1).strip().strip("'\"")
            if current_id != canon:
                text, changed = _reset_scalar(text, "id", canon)
                if changed:
                    changes.append(f"id: '{current_id}' → '{canon}'")

    # 4. version must be -1 in the repo (tenant version is meaningless here)
    ver_m = re.search(r"^version\s*:\s*(.+)$", text, re.MULTILINE)
    if ver_m and ver_m.group(1).strip() != "-1":
        text, changed = _reset_scalar(text, "version", "-1")
        if changed:
            changes.append(f"version: {ver_m.group(1).strip()} → -1")

    # 5. adopted: true must be the first line
    text, changed = _ensure_adopted_first(text)
    if changed:
        changes.append("adopted: true moved to first line")

    # 6. Pack identity in contentitemfields
    text, changed = _set_packid_packname(text, pack_id, pack_name)
    if changed:
        changes.append(f"packID → {pack_id} | packName → {pack_name}")

    # 7. Normalise scriptName → script in task blocks
    text, changed = _normalize_scriptname(text)
    if changed:
        changes.append("scriptName → script (all tasks)")

    # 8. Fix task UUID mismatches (outer taskid ≠ inner task.id)
    text, changed = _fix_task_id_mismatches(text)
    if changed:
        changes.append("fixed inner task.id to match outer taskid")

    # 9. Renumber any alphanumeric task IDs to integers
    text, changed = _renumber_alphanumeric_task_ids(text)
    if changed:
        changes.append("renumbered alphanumeric task IDs to integers")

    return text, changes


# ─────────────────────────────────────────────────────────────────────────────
# List normalisation
# ─────────────────────────────────────────────────────────────────────────────

def normalize_list(data: dict, canon: str) -> tuple[dict, list[str], dict]:
    """
    Split a single XSIAM list export into the two files the repo requires.

    XSIAM exports a list as one JSON blob containing everything:
      { "id": "...", "name": "...", <action-key>: {...}, ... }

    The repo requires two separate files per list:
      <ListName>.json       — descriptor: id, name, display_name, type
      <ListName>_data.json  — data: the full content JSON

    Returns (descriptor_dict, changes, data_dict) where:
      descriptor_dict  has the four required SDK fields
      data_dict        is the full original content (written as _data.json)
      changes          is the list of human-readable changes applied
    """
    changes: list[str] = []

    # Build the descriptor — four fields required by fix_errors / SDK
    descriptor: dict = {
        "id":           canon,
        "name":         canon,
        "display_name": canon,
        "type":         "json",
    }
    for field in ("id", "name", "display_name", "type"):
        if data.get(field) != descriptor[field]:
            old_val = data.get(field, "<missing>")
            changes.append(f"descriptor.{field}: '{old_val}' → '{descriptor[field]}'")

    # The data file is the full original content with id/name corrected
    data_out = dict(data)
    data_out["id"]   = canon
    data_out["name"] = canon

    return descriptor, changes, data_out


def list_canonical_name(path: Path, override: Optional[str]) -> str:
    """
    Derive the canonical name for a list file.

    Priority:
      1. --name override from CLI
      2. The subdirectory name under Lists/ — only if it IS a directory
         (i.e. has no file extension). This is the canonical identity
         used by normalize_ruleid_adopted.py and the SDK.
      3. The filename stem with copy/export suffixes stripped.

    Important: when a file is dropped directly into Lists/ (not inside a
    subdirectory), parts[i+1] is the filename itself which has an extension.
    We detect this case and fall through to stem-based derivation.
    """
    if override:
        return override

    parts = path.parts
    for i, part in enumerate(parts):
        if part == "Lists" and i + 1 < len(parts):
            subdir = parts[i + 1]
            # Only use subdir as canonical name if it looks like a directory
            # (no extension) and has no copy artifact in the name
            subdir_path = Path(subdir)
            if subdir_path.suffix == "" and not NAME_SUFFIX_RE.search(subdir):
                return subdir

    # File is directly under Lists/ or the subdir has a copy artifact.
    # Derive canonical name from the filename stem, stripping copy suffixes.
    return NAME_SUFFIX_RE.sub("", path.stem).strip()


# ─────────────────────────────────────────────────────────────────────────────
# Output path
# ─────────────────────────────────────────────────────────────────────────────

def resolve_output_path(input_path: Path, out_dir: Optional[Path]) -> Path:
    """
    Determine where to write the normalised file.

    Default (no --out): write in place, overwriting the input file.
    --out <dir>:        write to that directory, keeping the filename.
    --out <file>:       write to that exact path.
    """
    if out_dir is None:
        return input_path  # in place

    if out_dir.suffix:  # looks like a file path, not a directory
        out_dir.parent.mkdir(parents=True, exist_ok=True)
        return out_dir

    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / input_path.name


# ─────────────────────────────────────────────────────────────────────────────
# Per-file processing
# ─────────────────────────────────────────────────────────────────────────────

def process_file(
    path: Path,
    override_name: Optional[str],
    out_dir: Optional[Path],
    dry_run: bool,
) -> tuple[bool, bool]:
    """
    Normalise a single file.

    Returns (was_processed, had_changes).
      was_processed: True if the file was a known type and attempt was made
      had_changes:   True if any normalisation changes were applied or would be
    """
    # ── Gate 1: hard exclusions ───────────────────────────────────────────────
    skip, reason = should_skip(path)
    if skip:
        # These are infrastructure or unsupported files — skip without processing.
        # We print nothing here because these are expected skips (pack_metadata,
        # xsoar_config, IncidentFields, etc.). Unknown extensions that came from
        # git diff but landed in a processable directory are handled below.
        return False, False

    # ── Gate 2: must be under a Packs/ directory ──────────────────────────────
    pack_id = pack_from_path(path)
    if not pack_id:
        print(WARN(f"  ⚠  {path.name}: not under Packs/ — skipping"))
        return False, False

    # ── Gate 3: content type from directory location ──────────────────────────
    content_type = content_type_from_path(path)

    if content_type is None:
        # File is under Packs/ but the directory + extension combination is not
        # something we normalise directly (e.g. .yml in Lists/, or .json in
        # Playbooks/). Before saying "no action needed", check whether the file
        # content reveals it was placed in the wrong directory entirely.
        mislocation_error = check_mislocation(path)
        if mislocation_error:
            print(ERR(mislocation_error))
            return True, True   # treat as "needs action" so summary shows failure
        # Genuinely not a type we handle — e.g. a YAML in IncidentFields/
        print(WARN(
            f"  ⚠  {path.name}: in {content_dir_from_path(path) or 'unknown'} "
            f"directory — not normalised by this tool (no action needed)"
        ))
        return False, False

    if content_type == "script":
        # Scripts need manual review: the YAML has inline Python that must be
        # split into a separate .py file. This is a future normaliser step.
        print(WARN(
            f"  ⚠  SCRIPT  {path}\n"
            f"     Scripts require manual split (YAML + .py). Review separately."
        ))
        return False, False

    # ── Gate 4: read file content ─────────────────────────────────────────────
    # Read the file now so all subsequent gates can inspect the content.
    # Catches empty files and binary data before normalization attempts either.
    try:
        raw_bytes = path.read_bytes()
    except Exception as e:
        print(ERR(f"  ✗  {path.name}: cannot read file — {e}"))
        return True, False

    # Empty file — nothing to normalise, and feeding it to the normalisers
    # produces silent partial results.
    if not raw_bytes.strip():
        print(ERR(
            f"  ✗  {path.name}: file is empty.\n"
            f"     Export again from the XSIAM tenant and re-upload."
        ))
        return True, True

    # Binary file — a .yml or .json that contains binary data (e.g. a PNG or
    # zip accidentally given a YAML extension). The normalisers will produce
    # garbage or throw exceptions. Catch it here by checking for null bytes,
    # which never appear in valid UTF-8 YAML or JSON.
    if b"\x00" in raw_bytes[:4096]:
        print(ERR(
            f"  ✗  {path.name}: file appears to be binary, not a text export.\n"
            f"     Verify you exported the correct content from XSIAM."
        ))
        return True, True

    # Decode to text. CRLF line endings are normalised to LF here so that
    # all downstream regex patterns work consistently regardless of OS.
    try:
        file_text = raw_bytes.decode("utf-8", errors="strict").replace("\r\n", "\n")
    except UnicodeDecodeError:
        print(ERR(
            f"  ✗  {path.name}: file is not valid UTF-8.\n"
            f"     Verify you exported the correct content from XSIAM."
        ))
        return True, True

    # ── Gate 5: cross-check content type against directory ────────────────────
    # Now that we have the file text, verify the content matches the directory.
    # This catches the case where path says "playbook" but content says "script"
    # — a script YAML dropped in Playbooks/ because the contributor confused
    # the two. The Gate 3 mislocation check only fires when content_type is None
    # (wrong extension for directory); this gate fires when extension is correct
    # but content type disagrees with directory.
    actual_type = content_type_from_content(path)
    if actual_type is not None and actual_type != content_type:
        expected_dir = EXPECTED_DIR.get(actual_type, f"{actual_type}/")
        print(ERR(
            f"  ✗  MISLOCATION: {path.name}\n"
            f"     This file is a {actual_type.upper()} but was placed in "
            f"{content_dir_from_path(path)}/. \n"
            f"     Move it to: Packs/{pack_id}/{expected_dir}\n"
            f"     Then run normalize again."
        ))
        return True, True

    # ── Gate 6: playbook must have a name field ───────────────────────────────
    # A playbook with no name field cannot be canonically identified or renamed.
    # The SDK will also reject it (BA101). Flag it early rather than producing
    # a partially normalised file with a missing identity.
    if content_type == "playbook":
        if not re.search(r"^name\s*:", file_text, re.MULTILINE):
            print(ERR(
                f"  ✗  {path.name}: playbook has no 'name:' field.\n"
                f"     The XSIAM export may be incomplete. Export again and re-upload."
            ))
            return True, True

    # ── Derive pack display name ───────────────────────────────────────────────
    pack_name = PACK_NAMES.get(pack_id, pack_id)

    # Cross-check packName in the file against the path-derived pack ID.
    # The path always wins — this is informational only.
    if content_type == "playbook":

        packname_m = re.search(r"[ \t]*packName\s*:\s*(.+)$", file_text, re.MULTILINE)
        if packname_m:
            claimed_name = packname_m.group(1).strip().strip("'\"")
            claimed_id   = PACK_NAME_TO_ID.get(claimed_name.lower())
            if claimed_id and claimed_id != pack_id:
                print(WARN(
                    f"  ⚠  {path.name}: packName '{claimed_name}' maps to "
                    f"'{claimed_id}' but file is in '{pack_id}'. "
                    f"Using path-derived pack ID."
                ))

    # ── Print file header ──────────────────────────────────────────────────────
    print(f"\n  {INFO(content_type.upper())}  {DIM(str(path))}")
    print(f"    pack: {INFO(pack_id)}  ({pack_name})")

    # ── Playbook ───────────────────────────────────────────────────────────────
    if content_type == "playbook":
        normalised, changes = normalize_playbook(
            file_text, pack_id, pack_name, override_name
        )

        if not changes:
            print(OK("    ✓ already clean"))
            return True, False

        prefix = "(dry-run) " if dry_run else ""
        for c in changes:
            print(f"    {prefix}{OK('●')} {c}")

        if not dry_run:
            # Derive the canonical filename from the canonical name field.
            # The canonical name is spaces → underscores + .yml extension.
            # Example: 'SOC Email Exposure Evaluation_V3' → SOC_Email_Exposure_Evaluation_V3.yml
            name_m = re.search(r"^name\s*:\s*(.+)$", normalised, re.MULTILINE)
            if name_m:
                canon_name     = name_m.group(1).strip().strip("'\"")
                canon_filename = canon_name.replace(" ", "_") + ".yml"
                canon_path     = path.parent / canon_filename
            else:
                canon_path = path  # fallback: write in place

            if out_dir is not None:
                # --out override: user chose the destination explicitly
                out_path = resolve_output_path(path, out_dir)
            else:
                out_path = canon_path

            out_path.write_text(normalised, encoding="utf-8")
            print(f"    {OK('→')} {out_path}")

            # If the input file has a different name than the canonical output,
            # remove the input file so we don't leave a duplicate with the same
            # internal name and id — two files with matching identity fields
            # will cause the SDK upload to fail or produce undefined behaviour.
            if path.resolve() != out_path.resolve():
                path.unlink()
                print(f"    {OK('✗')} removed {path.name} (replaced by canonical filename)")

        return True, True

    # ── List JSON ──────────────────────────────────────────────────────────────
    if content_type == "list":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            print(ERR(f"    ✗ JSON parse error — {e}"))
            return True, False

        canon = list_canonical_name(path, override_name)
        descriptor, changes, data_out = normalize_list(data, canon)

        if not changes:
            print(OK("    ✓ already clean"))
            return True, False

        prefix = "(dry-run) " if dry_run else ""
        for c in changes:
            print(f"    {prefix}{OK('●')} {c}")

        if not dry_run:
            # Determine the target directory.
            # Repo structure: Lists/<ListName>/<ListName>.json + <ListName>_data.json
            # If the file is already inside a correctly-named subdirectory, use it.
            # If the file is at the Lists/ level or has a different name, create
            # the subdirectory and write both files there.
            if out_dir is not None:
                target_dir = Path(out_dir) / canon
            else:
                # Check if we are already inside Lists/<canon>/
                lists_parent = path.parent
                if lists_parent.name == canon:
                    # Already in the right subdirectory
                    target_dir = lists_parent
                else:
                    # At Lists/ level or wrong directory — create canonical subdir
                    # Walk up to find the Lists/ directory
                    p = path.parent
                    while p != p.parent and p.name != "Lists":
                        p = p.parent
                    target_dir = p / canon

            target_dir.mkdir(parents=True, exist_ok=True)

            # Write the descriptor file: <ListName>.json
            desc_path = target_dir / f"{canon}.json"
            desc_path.write_text(
                json.dumps(descriptor, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            print(f"    {OK('→')} {desc_path}  (descriptor)")

            # Write the data file: <ListName>_data.json
            data_path = target_dir / f"{canon}_data.json"
            data_path.write_text(
                json.dumps(data_out, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            print(f"    {OK('→')} {data_path}  (data)")

            # Remove the original file if it is in a different location or has a
            # different name — prevents stale files with duplicate identity
            if path.resolve() != desc_path.resolve() and path.resolve() != data_path.resolve():
                path.unlink()
                print(f"    {OK('✗')} removed {path.name} (replaced by canonical files)")

        return True, True

    return False, False


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Normalise XSIAM UI export artifacts in contributed pack content. "
            "By default processes only files changed on the current branch "
            "(git diff origin/main). Use --input to target a specific file."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--input", "-i", default=None,
        help=(
            "Specific file or pack directory to process. "
            "When omitted, uses git diff to find changed files."
        ),
    )
    parser.add_argument(
        "--base", default="origin/main",
        help="Git base ref for diff (default: origin/main)",
    )
    parser.add_argument(
        "--name", default=None,
        help="Override canonical name (default: auto-strip suffix from name field)",
    )
    parser.add_argument(
        "--out", "-o", default=None,
        help="Output file or directory (default: in place, overwrites input)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would change without writing any files",
    )
    args = parser.parse_args()

    input_path = Path(args.input).resolve() if args.input else None
    out_dir    = Path(args.out).resolve()   if args.out   else None

    if input_path and not input_path.exists():
        print(ERR(f"✗ not found: {input_path}"))
        sys.exit(1)

    # ── Header ────────────────────────────────────────────────────────────────
    print()
    print("━" * 62)
    print("  normalize_contribution.py")
    if input_path:
        print(f"  scope : {INFO(str(input_path))}")
    else:
        print(f"  scope : {INFO(f'git diff {args.base}')}")
    if args.dry_run:
        print(f"  mode  : {WARN('dry-run — no files written')}")
    else:
        print(f"  mode  : {OK('fix — files written in place')}")
    print("━" * 62)

    # ── Collect files ─────────────────────────────────────────────────────────
    files = collect_files(input_path, args.base)

    if not files:
        print(WARN("\n  No changed files found under Packs/."))
        print(DIM(
            "  If you expected changes, run 'git fetch origin' and try again,\n"
            "  or use --input <file> to target a specific file."
        ))
        sys.exit(0)

    print(f"\n  {len(files)} file(s) in scope\n")

    # ── Process ───────────────────────────────────────────────────────────────
    total_processed = 0
    total_changed   = 0

    for f in files:
        processed, changed = process_file(f, args.name, out_dir, args.dry_run)
        if processed:
            total_processed += 1
        if changed:
            total_changed += 1

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("━" * 62)
    if total_processed == 0:
        print(WARN("  No processable files found (playbooks or lists)."))
    elif total_changed == 0:
        print(OK(f"  ✓ {total_processed} file(s) checked — all already clean"))
    elif args.dry_run:
        print(WARN(
            f"  {total_changed} of {total_processed} file(s) need normalisation "
            f"(dry-run — nothing written)"
        ))
        sys.exit(1)  # non-zero exit so CI treats this as a gate failure
    else:
        print(OK(f"  ✓ {total_changed} of {total_processed} file(s) normalised"))
    print("━" * 62)
    print()


if __name__ == "__main__":
    main()
