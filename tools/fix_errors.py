#!/usr/bin/env python3
"""
fix_errors.py
-------------

Automates fixing demisto-sdk validation and parsing errors.

Design goals:
- Can run from ANY subdirectory (e.g., 'tools/')
- Auto-detect repo root (prefer git top-level; fallback to walking up until Packs/ exists)
- Resolve paths based ONLY on the path extracted from SDK output
"""
import argparse
import json
import os
import re
import subprocess

# --- Optional YAML libs (ruamel preferred for formatting preservation) -------
try:
    from ruamel.yaml import YAML
    _HAVE_RUAMEL = True
except Exception:
    _HAVE_RUAMEL = False

try:
    import yaml as pyyaml
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
    r'.*?(?P<path>Packs/[^:]+):\s*\'NoneType\' object is not iterable',
    re.IGNORECASE
)

# 2. Layout Group Error (e.g., "alert")
LAYOUT_GROUP_RE = re.compile(
    r'.*?(?P<path>Packs/[^:]+):\s*Layout:.*?Unknown group \"alert\"',
    re.IGNORECASE
)

# 3. Layout Plural Group Error (e.g., "incidents")
LAYOUT_PLURAL_GROUP_RE = re.compile(
    r'.*?(?P<path>Packs/[^:]+):\s*Layout:.*?Unknown group \"incidents\"',
    re.IGNORECASE
)

# Standard error regexes remain largely anchored to line start for clean messages
BA106_RE = re.compile(
    r'^(?P<path>[^:]+):\s*\[BA106\].*?need at least (?P<min>\d+\.\d+\.\d+)',
    re.IGNORECASE
)

# Hardened BA101 matcher for the current demisto-sdk output format you showed
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
            # If it's a real content repo, Packs/ should exist (but not strictly required)
            if os.path.isdir(os.path.join(root, "Packs")):
                return root
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
            # reached filesystem root
            return start_dir
        cur = parent


def resolve_path(repo_root: str, rel_path: str) -> str:
    """
    Resolves the absolute path to the content item, aggressively ensuring the path is valid.
    """
    # 1. Clean up and normalize the path extracted from the error log
    clean_rel_path = rel_path.strip().rstrip(':').replace('\\', os.sep).lstrip('/')

    # 2. Find the 'Packs/' segment and discard everything before it (handles noisy prefixes).
    if 'Packs' in clean_rel_path:
        clean_rel_path = clean_rel_path[clean_rel_path.index('Packs'):]

    # 3. Join it directly to the determined repo_root
    resolved_path = os.path.normpath(os.path.join(repo_root, clean_rel_path))
    return resolved_path


# --- YAML/JSON IO ------------------------------------------------------------

def load_yaml(path):
    if _HAVE_RUAMEL:
        y = YAML()
        y.preserve_quotes = True
        with open(path, 'r', encoding='utf-8') as f:
            data = y.load(f)
        return (data if data is not None else {}), 'ruamel'
    elif _HAVE_PYYAML:
        with open(path, 'r', encoding='utf-8') as f:
            data = pyyaml.safe_load(f)
        return (data if data is not None else {}), 'pyyaml'
    else:
        raise RuntimeError("Need ruamel.yaml or PyYAML to parse YAML files.")


def dump_yaml(path, data, engine):
    if engine == 'ruamel':
        y = YAML()
        y.preserve_quotes = True
        with open(path, 'w', encoding='utf-8') as f:
            y.dump(data, f)
    else:
        with open(path, 'w', encoding='utf-8') as f:
            pyyaml.safe_dump(data, f, sort_keys=False)


# --- Parsing Error Fixer (JSON) ---------------------------------------------

def fix_json_layout_null(path: str, dry_run: bool):
    """
    Fixes JSON objects (like Dashboards) where a mandatory list is set to 'null'.
    """
    if os.path.splitext(path)[1].lower() != '.json':
        return False, f"SKIP (not JSON): {path}"

    try:
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read()
            data = json.loads(text)
    except Exception as e:
        return False, f"SKIP (bad JSON/read error): {path} -> {e}"

    # Target specific keys known to cause this issue if set to null
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

    # Define bad groups and their intended replacement
    bad_groups = {'alert': 'incident', 'incidents': 'incident'}

    if group_key in bad_groups:
        new_value = bad_groups[group_key]
        data['group'] = new_value

        if not dry_run:
            with open(path, 'w', encoding='utf-8') as wf:
                json.dump(data, wf, indent=2, ensure_ascii=False)

        return True, f"PATCHED: {path} -> Changed 'group': '{group_key}' to '{new_value}'"

    return False, f"OK (no change): {path}"


# --- Textual fallback for malformed YAML ------------------------------------

FROMVERSION_LINE_RE = re.compile(r'(?mi)^(?P<indent>\s*)fromversion\s*:\s*(?P<val>[^\n#]+)')
ID_LINE_RE = re.compile(r'(?mi)^(?P<indent>\s*)id\s*:\s*(?P<val>[^\n#]+)')
NAME_LINE_RE = re.compile(r'(?mi)^(?P<indent>\s*)name\s*:\s*(?P<val>[^\n#]+)')


def textual_fix_yaml_fromversion(path: str, min_version: str, dry_run: bool):
    """
    Fallback when YAML parser fails. Tries to upgrade existing 'fromversion:'
    via regex; otherwise inserts a top-level 'fromversion: <min>' near the top.
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read()
    except Exception as e:
        return False, f"ERROR (read fail): {path} -> {e}"

    m = FROMVERSION_LINE_RE.search(text)
    if m:
        cur_raw = (m.group('val') or '').strip().strip('"').strip("'")
        new_val = max_version(cur_raw or '0.0.0', min_version)
        if parse_semver(cur_raw) >= parse_semver(min_version):
            return False, f"OK (no change, textual): {path} (fromversion={cur_raw})"
        start, end = m.span('val')
        new_text = text[:start] + new_val + text[end:]
        if not dry_run:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(new_text)
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
        with open(path, 'w', encoding='utf-8') as f:
            f.write(''.join(new_lines))
    return True, f"INSERTED (textual): {path} -> fromversion={min_version}"


def textual_fix_yaml_id_equals_name(path: str, dry_run: bool):
    """
    Fallback when YAML parser fails.
    For Scripts, the real id is usually under:
      commonfields:
        id: <...>
    This updates that (or inserts it) to match name.
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

    # Try to update "commonfields:\n  id: ..."
    COMMONFIELDS_BLOCK_RE = re.compile(
        r'(?ms)^(?P<indent>\s*)commonfields\s*:\s*\n(?P<body>(?:^(?P=indent)[ \t]+.*\n)*)'
    )
    m_cf = COMMONFIELDS_BLOCK_RE.search(text)
    if m_cf:
        indent = m_cf.group('indent')
        body = m_cf.group('body') or ""
        # Replace id inside the commonfields body
        ID_IN_COMMONFIELDS_RE = re.compile(r'(?mi)^(?P<i>' + re.escape(indent) + r'[ \t]+)id\s*:\s*(?P<val>[^\n#]+)')
        if ID_IN_COMMONFIELDS_RE.search(body):
            new_body = ID_IN_COMMONFIELDS_RE.sub(lambda m: f"{m.group('i')}id: {name_val}", body, count=1)
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
        idx = m_name.end()
        new_text = text[:idx] + f"\nid: {name_val}" + text[idx:]

    if not dry_run:
        with open(path, 'w', encoding='utf-8') as wf:
            wf.write(new_text)
    return True, f"UPDATED (textual): {path} -> id={name_val}"

# --- BA106 fixers ------------------------------------------------------------

def fix_yaml_fromversion(path: str, min_version: str, dry_run: bool):
    # Try structured YAML first; on failure, do textual fallback
    try:
        data, engine = load_yaml(path)
    except Exception:
        return textual_fix_yaml_fromversion(path, min_version, dry_run)

    lower = str(data.get('fromversion') or '')
    camel = str(data.get('fromVersion') or '')
    effective = lower or ''
    if camel and parse_semver(camel) > parse_semver(effective or '0.0.0'):
        effective = camel

    new_val = max_version(effective or '0.0.0', min_version)

    if effective and parse_semver(effective) >= parse_semver(min_version):
        if 'fromVersion' in data and 'fromversion' not in data:
            if not dry_run:
                data['fromversion'] = camel
                del data['fromVersion']
                dump_yaml(path, data, engine)
            return True, f"NORMALIZED: {path} -> fromVersion→fromversion={camel}"
        return False, f"OK (no change): {path} (fromversion={effective})"

    if 'fromVersion' in data:
        data.pop('fromVersion', None)
    data['fromversion'] = new_val
    if not dry_run:
        dump_yaml(path, data, engine)
    return True, f"UPDATED: {path} -> fromversion={new_val}"


def fix_json_fromversion(path: str, min_version: str, dry_run: bool):
    with open(path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return False, f"SKIP (invalid JSON): {path}"

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

    IMPORTANT:
    - For Script YAMLs, the ID is typically `commonfields.id`
    - For other items, it may be top-level `id`
    This fixer updates whichever is present (prefers commonfields.id when available).
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
        if nm is None:
            return False, f"SKIP (no name): {path}"

        # Prefer commonfields.id when present
        cf = data.get('commonfields')
        if isinstance(cf, dict) and 'id' in cf:
            cur = cf.get('id')
            if cur == nm:
                return False, f"OK (no change): {path} (commonfields.id=name={nm})"
            if not dry_run:
                cf['id'] = nm
                data['commonfields'] = cf
                with open(path, 'w', encoding='utf-8') as wf:
                    json.dump(data, wf, indent=2, ensure_ascii=False)
            return True, f"UPDATED: {path} -> commonfields.id={nm}"

        # Fall back to top-level id
        cur = data.get('id')
        if cur == nm:
            return False, f"OK (no change): {path} (id=name={nm})"
        if not dry_run:
            data['id'] = nm
            with open(path, 'w', encoding='utf-8') as wf:
                json.dump(data, wf, indent=2, ensure_ascii=False)
        return True, f"UPDATED: {path} -> id={nm}"

    if ext in ('.yml', '.yaml'):
        try:
            data, engine = load_yaml(path)
            nm = data.get('name')
            if nm is None:
                return False, f"SKIP (no name): {path}"

            # Prefer commonfields.id when present (Script YAMLs)
            cf = data.get('commonfields')
            if isinstance(cf, dict):
                cur = cf.get('id')
                if cur == nm:
                    return False, f"OK (no change): {path} (commonfields.id=name={nm})"
                if not dry_run:
                    cf['id'] = nm
                    data['commonfields'] = cf
                    dump_yaml(path, data, engine)
                return True, f"UPDATED: {path} -> commonfields.id={nm}"

            # Fall back to top-level id
            cur = data.get('id')
            if cur == nm:
                return False, f"OK (no change): {path} (id=name={nm})"
            if not dry_run:
                data['id'] = nm
                dump_yaml(path, data, engine)
            return True, f"UPDATED: {path} -> id={nm}"

        except Exception:
            return textual_fix_yaml_id_equals_name(path, dry_run)

    return False, f"SKIP (unsupported ext): {path}"

# --- PA128 (pack required files) --------------------------------------------

def fix_pack_required_files(pack_root: str, dry_run: bool = False):
    created = []
    targets = {
        ".secrets-ignore": "",
        ".pack-ignore": "# Add ignore rules here\n",
        "README.md.md": f"# {os.path.basename(pack_root)}\n"
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
    """
    if not os.path.exists(target_path):
        return False, f"SKIP (missing): {target_path}"

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
    ap.add_argument("--repo-root", default=".", help=argparse.SUPPRESS)  # kept for compatibility; ignored unless user sets it
    ap.add_argument("--dry-run", action="store_true", help="Show what would change without writing files")
    args = ap.parse_args()

    # Auto-detect repo root (fixes the 'run from tools/' problem)
    # If user explicitly passes --repo-root, honor it.
    explicit_root = os.path.abspath(args.repo_root) if args.repo_root and args.repo_root != "." else None
    repo_root = explicit_root or detect_repo_root(os.getcwd())

    total = 0
    changes = 0

    with open(args.sdk_output, 'r', encoding='utf-8', errors='ignore') as f:
        for raw in f:
            line = de_ansi(raw)

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

            # --- 6. BA102 (Run Format) ---------------------------------------------
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

            # ignore other lines

    print(f"\nMatched lines (Parsing/Layout/BA101/BA102/BA106/PA128): {total}. Files changed: {changes}. Dry-run: {args.dry_run}")


if __name__ == "__main__":
    main()
