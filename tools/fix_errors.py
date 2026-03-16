#!/usr/bin/env python3
"""
fix_errors.py
-------------

Automates fixing demisto-sdk validation and parsing errors.

Design goals:
- Can run from ANY subdirectory (e.g., 'tools/')
- Auto-detect repo root (prefer git top-level; fallback to walking up until Packs/ exists)
- Resolve paths based ONLY on the path extracted from SDK output

CRITICAL SAFETY CHANGE (2026-01):
- NEVER re-serialize YAML for content items that may contain embedded Python (e.g. Script YMLs),
  because YAML dumping can alter indentation inside block scalars (script: |-), breaking Python.
- Therefore, BA101 and BA106 YAML fixes are TEXTUAL ONLY (surgical line edits).

CRITICAL SAFETY CHANGE (2026-03):
- BA102 (demisto-sdk format) is SKIPPED for Script YAMLs that contain embedded Python.
  Running `demisto-sdk format` on these files rewrites the script: |- block and can corrupt
  indentation, breaking the Python. A manual fix instruction is printed instead.

ADDED (2026-03):
- Pre-flight scan for pydantic ValidationError blocks (List/content item descriptor missing
  required fields). These errors occur before SDK error lines are emitted so cannot be
  auto-fixed. A clear manual fix instruction is printed instead.
- Pre-flight scan of all Lists/**/*.json files for missing required descriptor fields,
  giving specific file paths rather than a general warning.
"""
import argparse
import json
import os
import re
import subprocess

# --- Optional YAML libs (kept for potential future use; NOT used to rewrite YAML) -------
try:
    from ruamel.yaml import YAML  # noqa: F401
    _HAVE_RUAMEL = True
except Exception:
    _HAVE_RUAMEL = False

try:
    import yaml as pyyaml  # noqa: F401
    _HAVE_PYYAML = True
except Exception:
    _HAVE_PYYAML = False

# --- Parsing helpers ---------------------------------------------------------

# Strip ANSI color codes that may appear in demisto-sdk output
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def de_ansi(s: str) -> str:
    return ANSI_RE.sub('', s).strip()


# NEW AGGRESSIVE REGEXES (Note the leading '.*?' to ignore progress bar noise)

# 1. Parsing Error (NoneType in Dashboard/Layout)
# Grabs the path segment starting exactly at 'Packs/'
PARSING_ERROR_RE = re.compile(
    r".*?(?P<path>Packs/[^:]+):\s*'NoneType' object is not iterable",
    re.IGNORECASE
)

# 2. Layout Group Error (e.g., "alert")
LAYOUT_GROUP_RE = re.compile(
    r'.*?(?P<path>Packs/[^:]+):\s*Layout:.*?Unknown group "alert"',
    re.IGNORECASE
)

# 3. Layout Plural Group Error (e.g., "incidents")
LAYOUT_PLURAL_GROUP_RE = re.compile(
    r'.*?(?P<path>Packs/[^:]+):\s*Layout:.*?Unknown group "incidents"',
    re.IGNORECASE
)

# Standard error regexes remain largely anchored to line start for clean messages
BA106_RE = re.compile(
    r'^(?P<path>[^:]+):\s*\[BA106\].*?need at least (?P<min>\d+\.\d+\.\d+)',
    re.IGNORECASE
)

# Hardened BA101 matcher for the current demisto-sdk output format
BA101_RE = re.compile(
    r'^(?P<path>[^:]+):\s*\[BA101\]\s*-\s*The name attribute\s*\(currently\s*(?P<name>.+?)\)\s*should be identical to its.*?id.*?\((?P<id>[^)]+)\)',
    re.IGNORECASE
)

PA128_RE = re.compile(
    r'^(?P<pack>Packs/[A-Za-z0-9._\-]+):\s*\[PA128\]',
    re.IGNORECASE
)

BA102_RE = re.compile(
    r'^(?P<path>[^:]+):\s*\[BA102\]',
    re.IGNORECASE
)

SEMVER_NUM_RE = re.compile(r'\d+')

# Pydantic ValidationError block — spans multiple lines, caught in pre-flight
PYDANTIC_BLOCK_RE = re.compile(
    r'pydantic[^\n]*ValidationError:\s*\d+\s*validation errors? for Pack\n'
    r'(?P<fields>(?:contentItems[^\n]+\n(?:[ \t]+[^\n]+\n)*)+)',
    re.IGNORECASE,
)

# Detects embedded Python in a YAML file — signals BA102 must not auto-format
SCRIPT_YAML_RE = re.compile(
    r'^\s*(script\s*:\s*\|[-]?|type\s*:\s*python)',
    re.IGNORECASE | re.MULTILINE,
    )

# Required fields for List descriptor JSON files
LIST_DESCRIPTOR_REQUIRED = ('id', 'name', 'display_name', 'type')


def parse_semver(v: str):
    if not v or not isinstance(v, str):
        return (0, 0, 0)
    parts = SEMVER_NUM_RE.findall(v)
    nums = [int(x) for x in parts[:3]]
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])


def max_version(a: str, b: str) -> str:
    return a if parse_semver(a) >= parse_semver(b) else b


def detect_repo_root(start_dir: str) -> str:
    """
    Detect repo root robustly:
    1) prefer `git rev-parse --show-toplevel`
    2) otherwise walk up until a `Packs/` directory exists
    """
    start_dir = os.path.abspath(start_dir)

    # 1) git top-level
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True,
        )
        root = (res.stdout or "").strip()
        if root:
            return root
    except Exception:
        pass

    # 2) walk up looking for Packs/
    cur = start_dir
    while True:
        if os.path.isdir(os.path.join(cur, "Packs")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return start_dir
        cur = parent


def resolve_path(repo_root: str, rel_path: str) -> str:
    """
    Resolves the absolute path to the content item, aggressively ensuring the path is valid.
    """
    clean_rel_path = rel_path.strip().rstrip(':').replace('\\', os.sep).lstrip('/')

    # Find the 'Packs/' segment and discard everything before it (handles noisy prefixes).
    if 'Packs' in clean_rel_path:
        clean_rel_path = clean_rel_path[clean_rel_path.index('Packs'):]

    return os.path.normpath(os.path.join(repo_root, clean_rel_path))


def _is_script_yaml(path: str) -> bool:
    """
    Returns True if the file is a YAML that contains embedded Python.
    Used to guard BA102 auto-format from corrupting script: |- blocks.
    """
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return bool(SCRIPT_YAML_RE.search(f.read()))
    except Exception:
        return False


# --- Pre-flight: pydantic ValidationError blocks ----------------------------

def preflight_pydantic_errors(full_text: str) -> int:
    """
    Scans the full SDK output text for pydantic ValidationError blocks.
    These are emitted before any per-file error lines and cannot be auto-fixed.
    Prints a clear manual fix instruction for each block found.
    Returns the count of blocks found.
    """
    count = 0
    for m in PYDANTIC_BLOCK_RE.finditer(full_text):
        count += 1
        fields_block = m.group('fields')
        missing = re.findall(
            r'contentItems.*?->\s*(\w+)\s*\n\s*none is not an allowed value',
            fields_block,
            re.IGNORECASE,
        )
        missing = list(dict.fromkeys(missing)) or ['id', 'name', 'display_name', 'type']

        print(
            "\n"
            "╔══════════════════════════════════════════════════════════════════╗\n"
            "║  MANUAL FIX REQUIRED — List descriptor missing required fields  ║\n"
            "╚══════════════════════════════════════════════════════════════════╝\n"
            f"  Missing field(s): {', '.join(missing)}\n"
            "\n"
            "  This error fires during SDK initialization and does not include a\n"
            "  file path. Check ALL List descriptor .json files (not _data.json)\n"
            "  under your Packs/**/Lists/ directories.\n"
            "\n"
            "  The SDK pydantic model requires ALL four fields to be non-null:\n"
            "    id           — must match the list name exactly\n"
            "    name         — must match the list name exactly\n"
            "    display_name — must match the list name exactly\n"
            "    type         — 'json' or 'plain_text'\n"
            "\n"
            "  Required descriptor format:\n"
            "    {\n"
            '      "id": "YourListName",\n'
            '      "name": "YourListName",\n'
            '      "display_name": "YourListName",\n'
            '      "type": "json",\n'
            '      "version": -1,\n'
            '      "fromVersion": "6.5.0",\n'
            '      "data": "",\n'
            '      "tags": []\n'
            "    }\n"
        )
    return count


# --- Pre-flight: scan Lists/ descriptors for missing fields ------------------

def preflight_list_descriptors(repo_root: str) -> int:
    """
    Walks all Packs/**/Lists/**/*.json files (excluding *_data.json) and checks
    for the four required descriptor fields. Prints specific file paths and
    missing fields so the user knows exactly what to fix.
    Returns the count of files with issues.
    """
    issues = 0
    packs_dir = os.path.join(repo_root, 'Packs')
    if not os.path.isdir(packs_dir):
        return 0

    for dirpath, _dirs, files in os.walk(packs_dir):
        # Only look inside Lists/ subdirectories
        if os.sep + 'Lists' + os.sep not in dirpath + os.sep:
            continue

        for fname in files:
            if not fname.endswith('.json') or fname.endswith('_data.json'):
                continue

            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except Exception:
                continue

            missing = [
                field for field in LIST_DESCRIPTOR_REQUIRED
                if not data.get(field)
            ]

            if missing:
                issues += 1
                rel = os.path.relpath(fpath, repo_root)
                print(
                    f"\n⚠️  List descriptor missing required fields: {rel}\n"
                    f"   Missing: {', '.join(missing)}\n"
                    f"   Add these fields to {fname} — values should match the list name.\n"
                    f"   Example: \"display_name\": \"{data.get('name') or os.path.splitext(fname)[0]}\""
                )

    return issues


# --- Parsing Error Fixer (JSON) ---------------------------------------------

def fix_json_layout_null(path: str, dry_run: bool):
    """
    Fixes JSON objects (like Dashboards) where a mandatory list is set to 'null'.
    """
    if os.path.splitext(path)[1].lower() != '.json':
        return False, f"SKIP (not JSON): {path}"

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.loads(f.read())
    except Exception as e:
        return False, f"SKIP (bad JSON/read error): {path} -> {e}"

    keys_to_check = ['layout', 'content']
    changed = False

    for key in keys_to_check:
        if key in data and data[key] is None:
            data[key] = []
            changed = True

    if changed:
        if not dry_run:
            with open(path, 'w', encoding='utf-8') as wf:
                json.dump(data, wf, indent=2, ensure_ascii=False)
        return True, f"PATCHED: {path} -> Fixed 'null' array fields (e.g., 'layout')"

    return False, f"OK (no change): {path}"


# --- Layout Group Fixer (JSON) -----------------------------------------------

def fix_layout_group_alert(path: str, dry_run: bool):
    """
    Fixes Layout JSON files where 'group' is incorrectly set (e.g., 'alert' or 'incidents').
    Changes known bad values to 'incident'.
    """
    if os.path.splitext(path)[1].lower() != '.json':
        return False, f"SKIP (not JSON): {path}"

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        return False, f"SKIP (bad JSON/read error): {path} -> {e}"

    group_key = (data.get('group') or '').lower()
    bad_groups = {'alert': 'incident', 'incidents': 'incident'}

    if group_key in bad_groups:
        new_value = bad_groups[group_key]
        data['group'] = new_value

        if not dry_run:
            with open(path, 'w', encoding='utf-8') as wf:
                json.dump(data, wf, indent=2, ensure_ascii=False)

        return True, f"PATCHED: {path} -> Changed 'group': '{group_key}' to '{new_value}'"

    return False, f"OK (no change): {path}"


# --- Textual YAML helpers (SAFE: do not reformat YAML) -----------------------

FROMVERSION_LINE_RE = re.compile(r'(?mi)^(?P<indent>\s*)fromversion\s*:\s*(?P<val>[^\n#]+)')
# Top-level id/name lines (fallback only)
ID_LINE_RE = re.compile(r'(?mi)^(?P<indent>\s*)id\s*:\s*(?P<val>[^\n#]+)')
NAME_LINE_RE = re.compile(r'(?mi)^(?P<indent>\s*)name\s*:\s*(?P<val>[^\n#]+)')


def textual_fix_yaml_fromversion(path: str, min_version: str, dry_run: bool):
    """
    SAFE TEXTUAL FIX: adjust/insert fromversion without rewriting YAML structure.
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read()
    except Exception as e:
        return False, f"ERROR (read fail): {path} -> {e}"

    m = FROMVERSION_LINE_RE.search(text)
    if m:
        cur_raw = (m.group('val') or '').strip().strip('"').strip("'")
        if parse_semver(cur_raw) >= parse_semver(min_version):
            return False, f"OK (no change, textual): {path} (fromversion={cur_raw})"
        new_val = max_version(cur_raw or '0.0.0', min_version)
        start, end = m.span('val')
        new_text = text[:start] + new_val + text[end:]
        if not dry_run:
            with open(path, 'w', encoding='utf-8') as wf:
                wf.write(new_text)
        return True, f"UPDATED (textual): {path} -> fromversion={new_val}"

    # Insert near the top (after comments/doc markers)
    lines = text.splitlines(True)
    insert_idx = 0
    while insert_idx < len(lines):
        s = lines[insert_idx].lstrip()
        if s.startswith('---') or s.startswith('#') or s.strip() == '':
            insert_idx += 1
            continue
        break

    insert_line = f"fromversion: {min_version}\n"
    new_lines = lines[:insert_idx] + [insert_line] + lines[insert_idx:]
    if not dry_run:
        with open(path, 'w', encoding='utf-8') as wf:
            wf.write(''.join(new_lines))
    return True, f"INSERTED (textual): {path} -> fromversion={min_version}"


def textual_fix_yaml_id_equals_name(path: str, dry_run: bool):
    """
    SAFE TEXTUAL FIX for BA101:
    - Prefer updating/adding commonfields.id to match name (Script YAMLs)
    - Otherwise update/add top-level id to match name

    This does NOT rewrite YAML; it only replaces/inserts a single line.
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read()
    except Exception as e:
        return False, f"SKIP (read fail): {path} -> {e}"

    m_name = NAME_LINE_RE.search(text)
    if not m_name:
        return False, f"SKIP (no name found, textual): {path}"
    name_val = m_name.group('val').strip()

    # Attempt: update commonfields block id first
    commonfields_block_re = re.compile(
        r'(?ms)^(?P<indent>\s*)commonfields\s*:\s*\n(?P<body>(?:^(?P=indent)[ \t]+.*\n)*)'
    )
    m_cf = commonfields_block_re.search(text)
    if m_cf:
        indent = m_cf.group('indent')
        body = m_cf.group('body') or ""

        id_in_commonfields_re = re.compile(
            r'(?mi)^(?P<i>' + re.escape(indent) + r'[ \t]+)id\s*:\s*(?P<val>[^\n#]+)'
        )

        if id_in_commonfields_re.search(body):
            new_body = id_in_commonfields_re.sub(lambda m: f"{m.group('i')}id: {name_val}", body, count=1)
        else:
            # Insert id at top of the commonfields body
            new_body = f"{indent}  id: {name_val}\n" + body

        new_text = text[:m_cf.start('body')] + new_body + text[m_cf.end('body'):]
        if not dry_run:
            with open(path, 'w', encoding='utf-8') as wf:
                wf.write(new_text)
        return True, f"UPDATED (textual): {path} -> commonfields.id={name_val}"

    # No commonfields block found; fall back to top-level id behavior
    if ID_LINE_RE.search(text):
        new_text = ID_LINE_RE.sub(lambda m: f"{m.group('indent')}id: {name_val}", text, count=1)
    else:
        # Insert an id line right after the name line
        idx = m_name.end()
        new_text = text[:idx] + f"\nid: {name_val}" + text[idx:]

    if not dry_run:
        with open(path, 'w', encoding='utf-8') as wf:
            wf.write(new_text)
    return True, f"UPDATED (textual): {path} -> id={name_val}"


# --- BA106 fixers ------------------------------------------------------------

def fix_yaml_fromversion(path: str, min_version: str, dry_run: bool):
    """
    SAFE: Always textual for YAML to avoid breaking indentation inside script block scalars.
    """
    return textual_fix_yaml_fromversion(path, min_version, dry_run)


def fix_json_fromversion(path: str, min_version: str, dry_run: bool):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return False, f"SKIP (invalid JSON): {path}"
    except Exception as e:
        return False, f"SKIP (read error): {path} -> {e}"

    camel = str(data.get('fromVersion') or '')
    wrong = str(data.get('fromversion') or '')
    effective = camel or ''
    if wrong and parse_semver(wrong) > parse_semver(effective or '0.0.0'):
        effective = wrong

    new_val = max_version(effective or '0.0.0', min_version)

    if effective and parse_semver(effective) >= parse_semver(min_version):
        changed = False
        if 'fromversion' in data and 'fromVersion' not in data:
            data['fromVersion'] = data['fromversion']
            del data['fromversion']
            changed = True
        if changed and not dry_run:
            with open(path, 'w', encoding='utf-8') as wf:
                json.dump(data, wf, indent=2, ensure_ascii=False)
            return True, f"NORMALIZED: {path} -> fromversion→fromVersion={data['fromVersion']}"
        return False, f"OK (no change): {path} (fromVersion={effective})"

    data['fromVersion'] = new_val
    if 'fromversion' in data:
        del data['fromversion']
    if not dry_run:
        with open(path, 'w', encoding='utf-8') as wf:
            json.dump(data, wf, indent=2, ensure_ascii=False)
    return True, f"UPDATED: {path} -> fromVersion={new_val}"


def fix_file_ba106(path: str, min_version: str, dry_run: bool = False):
    ext = os.path.splitext(path)[1].lower()
    if not os.path.exists(path):
        return False, f"SKIP (missing): {path}"
    if ext in ('.yml', '.yaml'):
        return fix_yaml_fromversion(path, min_version, dry_run)
    if ext == '.json':
        return fix_json_fromversion(path, min_version, dry_run)
    return False, f"SKIP (unknown ext): {path}"


# --- BA101 fixers ------------------------------------------------------------

def fix_id_name(path: str, dry_run: bool = False):
    """
    BA101 requires: name == id

    SAFE BEHAVIOR:
    - JSON: structured edit + rewrite is safe
    - YAML: TEXTUAL ONLY (do not dump YAML; can break embedded Python indentation)
    """
    ext = os.path.splitext(path)[1].lower()
    if not os.path.exists(path):
        return False, f"SKIP (missing): {path}"

    if ext == '.json':
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            return False, f"SKIP (bad JSON): {path} -> {e}"

        nm = data.get('name')
        if not nm:
            return False, f"SKIP (no name): {path}"

        cf = data.get('commonfields')
        if isinstance(cf, dict) and 'id' in cf:
            if cf.get('id') == nm:
                return False, f"OK (no change): {path} (commonfields.id=name={nm})"
            if not dry_run:
                cf['id'] = nm
                data['commonfields'] = cf
                with open(path, 'w', encoding='utf-8') as wf:
                    json.dump(data, wf, indent=2, ensure_ascii=False)
            return True, f"UPDATED: {path} -> commonfields.id={nm}"

        if data.get('id') == nm:
            return False, f"OK (no change): {path} (id=name={nm})"
        if not dry_run:
            data['id'] = nm
            with open(path, 'w', encoding='utf-8') as wf:
                json.dump(data, wf, indent=2, ensure_ascii=False)
        return True, f"UPDATED: {path} -> id={nm}"

    if ext in ('.yml', '.yaml'):
        return textual_fix_yaml_id_equals_name(path, dry_run)

    return False, f"SKIP (unsupported ext): {path}"


# --- PA128 (pack required files) --------------------------------------------

def fix_pack_required_files(pack_root: str, dry_run: bool = False):
    created = []
    targets = {
        ".secrets-ignore": "",
        ".pack-ignore": "# Add ignore rules here\n",
        "README.md": f"# {os.path.basename(pack_root)}\n",
    }
    for fname, content in targets.items():
        fpath = os.path.join(pack_root, fname)
        if not os.path.exists(fpath):
            if not dry_run:
                os.makedirs(pack_root, exist_ok=True)
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(content)
            created.append(fname)
    if created:
        return True, f"CREATED in {pack_root}: {', '.join(created)}"
    return False, f"OK (no change): {pack_root} has required files"


# --- BA102 (format) ----------------------------------------------------------

def run_demisto_format(target_path: str, dry_run: bool = False):
    """
    Runs `demisto-sdk format -i <target_path> --assume-yes` to normalize items
    that `validate` won't handle (BA102).

    SAFETY GUARD: Skips Script YAMLs containing embedded Python (script: |- or
    type: python). Running format on these rewrites the script block and can
    corrupt indentation, breaking the Python. A manual fix instruction is printed
    instead.
    """
    if not os.path.exists(target_path):
        return False, f"SKIP (missing): {target_path}"

    ext = os.path.splitext(target_path)[1].lower()
    if ext in ('.yml', '.yaml') and _is_script_yaml(target_path):
        rel = target_path
        return False, (
            f"\n"
            f"╔══════════════════════════════════════════════════════════════════╗\n"
            f"║  MANUAL FIX REQUIRED — BA102 on Script YAML (auto-format skipped) ║\n"
            f"╚══════════════════════════════════════════════════════════════════╝\n"
            f"  File: {rel}\n"
            f"\n"
            f"  This file contains embedded Python (script: |- or type: python).\n"
            f"  Running `demisto-sdk format` on it rewrites the script block and\n"
            f"  can corrupt indentation, breaking the automation.\n"
            f"\n"
            f"  Fix manually by opening the YAML and addressing the BA102 error\n"
            f"  directly (typically a missing or incorrect field value).\n"
            f"  Do NOT run `demisto-sdk format` on this file.\n"
        )

    cmd = ["demisto-sdk", "format", "-i", target_path, "--assume-yes"]
    if dry_run:
        return True, f"WOULD RUN: {' '.join(cmd)}"

    env = os.environ.copy()
    env.setdefault("DEMISTO_SDK_IGNORE_CONTENT_WARNING", "1")

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        if res.returncode == 0:
            tail = res.stdout.strip().splitlines()[-1] if res.stdout else "format completed"
            return True, f"FORMAT OK: {target_path} ({tail})"
        return False, f"FORMAT FAILED ({res.returncode}): {target_path}\n{res.stdout}"
    except FileNotFoundError:
        return False, "ERROR: `demisto-sdk` not found in PATH. Install it or add to PATH."
    except Exception as e:
        return False, f"FORMAT ERROR: {target_path} -> {e}"


# --- Main --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Fix common demisto-sdk errors (Parsing, Layout Group, BA106, BA101, PA128, BA102)."
    )
    ap.add_argument("sdk_output", help="Path to saved SDK validation output (e.g., sdk_errors.txt)")
    ap.add_argument("--repo-root", default=".", help=argparse.SUPPRESS)  # kept for compatibility
    ap.add_argument("--dry-run", action="store_true", help="Show what would change without writing files")
    args = ap.parse_args()

    # Auto-detect repo root; honor explicit --repo-root when user sets it.
    explicit_root = os.path.abspath(args.repo_root) if args.repo_root and args.repo_root != "." else None
    repo_root = explicit_root or detect_repo_root(os.getcwd())

    # Read full SDK output once for pre-flight passes
    with open(args.sdk_output, 'r', encoding='utf-8', errors='ignore') as f:
        full_text = de_ansi(f.read())

    # ── Pre-flight 1: pydantic ValidationError blocks ────────────────────────
    # These fire before per-file error lines and include no file path.
    pydantic_count = preflight_pydantic_errors(full_text)

    # ── Pre-flight 2: walk Lists/ descriptors for missing required fields ────
    # Gives specific file paths so the user knows exactly what to fix.
    list_issue_count = preflight_list_descriptors(repo_root)

    if pydantic_count == 0 and list_issue_count == 0:
        pass  # no pre-flight issues — proceed silently to per-line fixes
    else:
        print(
            f"\n{'─' * 68}\n"
            f"Pre-flight found {pydantic_count} pydantic error block(s) and "
            f"{list_issue_count} list descriptor issue(s).\n"
            f"Fix these manually before re-running the SDK.\n"
            f"{'─' * 68}\n"
        )

    # ── Per-line fixes ────────────────────────────────────────────────────────
    total = 0
    changes = 0

    for line in full_text.splitlines():

        # --- 1. PARSING ERROR FIX (NoneType in Dashboard/Layout) ----------------
        m_parse_err = PARSING_ERROR_RE.search(line)
        if m_parse_err:
            total += 1
            rel_path = m_parse_err.group('path').strip()
            resolved = resolve_path(repo_root, rel_path)

            if not os.path.exists(resolved):
                print(f"SKIP (missing): {rel_path} (Resolved: {resolved})")
                continue

            changed, msg = fix_json_layout_null(resolved, args.dry_run)
            print(msg)
            if changed:
                changes += 1
            continue

        # --- 2. LAYOUT GROUP FIX (Unknown group "alert" / "incidents") ----------
        m_layout_group_alert = LAYOUT_GROUP_RE.search(line)
        m_layout_group_plural = LAYOUT_PLURAL_GROUP_RE.search(line)
        if m_layout_group_alert or m_layout_group_plural:
            m_match = m_layout_group_alert or m_layout_group_plural
            total += 1
            rel_path = m_match.group('path').strip()
            resolved = resolve_path(repo_root, rel_path)

            if not os.path.exists(resolved):
                print(f"SKIP (missing): {rel_path} (Resolved: {resolved})")
                continue

            changed, msg = fix_layout_group_alert(resolved, args.dry_run)
            print(msg)
            if changed:
                changes += 1
            continue

        # --- 3. PA128 (Pack Required Files) ------------------------------------
        m128 = PA128_RE.search(line)
        if m128:
            total += 1
            pack_rel = m128.group('pack').strip()
            resolved = resolve_path(repo_root, pack_rel)

            if not os.path.exists(resolved):
                print(f"SKIP (missing pack): {pack_rel} (Resolved: {resolved})")
                continue

            changed, msg = fix_pack_required_files(resolved, args.dry_run)
            print(msg)
            if changed:
                changes += 1
            continue

        # --- 4. BA101 (ID = Name) ----------------------------------------------
        m101 = BA101_RE.search(line)
        if m101:
            total += 1
            rel_path = m101.group('path').strip()
            resolved = resolve_path(repo_root, rel_path)

            if not os.path.exists(resolved):
                print(f"SKIP (missing): {rel_path} (Resolved: {resolved})")
                continue

            changed, msg = fix_id_name(resolved, args.dry_run)
            print(msg)
            if changed:
                changes += 1
            continue

        # --- 5. BA106 (fromversion) --------------------------------------------
        m106 = BA106_RE.search(line)
        if m106:
            total += 1
            rel_path = m106.group('path').strip()
            resolved = resolve_path(repo_root, rel_path)

            if not os.path.exists(resolved):
                print(f"SKIP (missing): {rel_path} (Resolved: {resolved})")
                continue

            min_ver = m106.group('min').strip()
            changed, msg = fix_file_ba106(resolved, min_ver, args.dry_run)
            print(msg)
            if changed:
                changes += 1
            continue

        # --- 6. BA102 (Run Format — skipped for Script YAMLs) -----------------
        m102 = BA102_RE.search(line)
        if m102:
            total += 1
            rel_path = m102.group('path').strip()
            resolved = resolve_path(repo_root, rel_path)

            if not os.path.exists(resolved):
                print(f"SKIP (missing): {rel_path} (Resolved: {resolved})")
                continue

            changed, msg = run_demisto_format(resolved, args.dry_run)
            print(msg)
            if changed:
                changes += 1
            continue

    print(
        f"\nMatched lines (Parsing/Layout/BA101/BA102/BA106/PA128): {total}. "
        f"Files changed: {changes}. Dry-run: {args.dry_run}"
    )


if __name__ == "__main__":
    main()
