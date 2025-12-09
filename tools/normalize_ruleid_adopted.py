#!/usr/bin/env python3
"""
normalize_ruleid_adopted.py

Behavior:
- Set rule_id: 0 on correlation rules under any CorrelationRules directory (.yml/.json)
- Ensure fromversion: 6.10.0 on YAML correlation rules and fromVersion: "6.10.0" on JSON correlation rules
- Ensure adopted: true for playbooks under Content/Playbooks
- For JSON/YAML scripts, ensure fromVersion/fromversion is 6.10.0
- Remove Builtin/BuiltIn from pack_metadata.json dependencies if found.
- For JSON files under any Lists/* directory, set "id" and "name" to the
  directory name (e.g. Lists/SOCArtifacts/SOCArtifacts.json -> id/name: "SOCArtifacts")
- For JSON files under any Scripts/* directory, set "id" and "name" to the
  directory name (e.g. Scripts/MyScript/MyScript.json -> id/name: "MyScript")
- For YAML files under any Scripts/* directory, set id and
  top-level name to the directory name.
- Ensure the pack root has .pack-ignore, .secrets-ignore, and README.md.

Usage:
  # Local (fix mode)
  python3 normalize_ruleid_adopted.py --root Packs/soc-optimization --fix

  # CI / check-only mode (exit 1 if changes would be needed)
  python3 normalize_ruleid_adopted.py --root Packs/soc-optimization
"""

import argparse
import json
import os
import re
from typing import Any, Tuple

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _load_json(path: str) -> Tuple[Any, bool]:
    if not os.path.exists(path):
        return {}, False
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), True
    except Exception as e:
        print(f"[WARN] Failed to parse {path}: {e}")
        return {}, False


def _dump_json(path: str, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _find_file(root: str, filename: str) -> str:
    for dirpath, _, filenames in os.walk(root):
        if filename in filenames:
            return os.path.join(dirpath, filename)
    return ""


def _norm(path: str) -> str:
    return path.replace("\\", "/").lower()

# ------------------------------------------------------------
# Required pack files creation
# ------------------------------------------------------------

def ensure_pack_required_files(root: str, dry_run: bool) -> bool:
    """
    Ensure the pack root contains:
      - .pack-ignore
      - .secrets-ignore
      - README.md

    Returns True if any file was (or would be) created.
    """
    required_files = {
        ".pack-ignore":
            "[file_ignore_list]\n.git\n.git/*\nimages\nimages/*\ndocumentation\ndocumentation/*\n",
        ".secrets-ignore":
            "# secrets-ignore\n",
        "README.md":
            "# Pack README\nThis pack was auto-generated and normalized.\n",
    }

    changed = False

    for fname, default_content in required_files.items():
        fpath = os.path.join(root, fname)
        if not os.path.exists(fpath):
            print(f"[INFO] Creating missing required pack file: {fpath}")
            changed = True
            if not dry_run:
                try:
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(default_content)
                except Exception as e:
                    print(f"[WARN] Failed to write {fpath}: {e}")

    return changed

# ------------------------------------------------------------
# Path matching
# ------------------------------------------------------------

def _is_playbook(path: str) -> bool:
    low = _norm(path)
    return "/content/playbooks/" in low and (low.endswith(".yml") or low.endswith(".yaml"))


def _is_corr_rule(path: str) -> bool:
    """
    Treat any file under a CorrelationRules directory as a correlation rule.
    Works for:
      Packs/<pack>/CorrelationRules/*.yml
      Packs/<pack>/Content/CorrelationRules/*.json
    """
    low = _norm(path)
    if "/correlationrules/" not in low:
        return False
    return low.endswith(".yml") or low.endswith(".yaml") or low.endswith(".json")


def _is_list_json(path: str) -> bool:
    """
    Returns True if this is a JSON file under a Lists/* directory.
    Example: Packs/.../Lists/SOCArtifacts/SOCArtifacts.json
    """
    low = _norm(path)
    return "/lists/" in low and low.endswith(".json")


def _is_script_json(path: str) -> bool:
    """
    Returns True if this is a JSON file under a Scripts/* directory.
    Example: Packs/.../Scripts/MyScript/MyScript.json
    """
    low = _norm(path)
    return "/scripts/" in low and low.endswith(".json")


def _is_script_yaml(path: str) -> bool:
    """
    Returns True if this is a YAML file under a Scripts/* directory.
    Example: Packs/.../Scripts/MyScript/MyScript.yml
    """
    low = _norm(path)
    return "/scripts/" in low and (low.endswith(".yml") or low.endswith(".yaml"))

# ------------------------------------------------------------
# YAML transforms (correlation rules, playbooks, scripts)
# ------------------------------------------------------------

def _ensure_adopted_in_yaml(text: str) -> Tuple[str, bool]:
    # Only add adopted: true if not already set
    if re.search(r'^\s*adopted\s*:\s*true\b', text, flags=re.I | re.M):
        return text, False

    lines = text.splitlines()
    insert_at = None

    for i, line in enumerate(lines):
        if line.strip() and not line.strip().startswith("#"):
            insert_at = i
            break

    if insert_at is None:
        lines.append("adopted: true")
    else:
        lines.insert(insert_at, "adopted: true")

    new_text = "\n".join(lines)
    if not new_text.endswith("\n"):
        new_text += "\n"

    return new_text, True


def _set_rule_id_yaml(text: str) -> Tuple[str, bool]:
    """
    Ensure rule_id: 0, but be idempotent so check-only runs don't keep
    reporting changes once files are normalized.
    """
    # Already exactly rule_id: 0 ?
    if re.search(r'^\s*rule_id\s*:\s*0\s*$', text, flags=re.M):
        return text, False

    # rule_id exists but not 0 -> set to 0
    if re.search(r'^\s*rule_id\s*:', text, flags=re.M):
        new_text, n = re.subn(
            r'(^\s*rule_id\s*:\s*).*$',  # full rule_id line
            r'\g<1>0',
            text,
            flags=re.M,
        )
        return new_text, n > 0

    # No rule_id at all -> insert at top
    return "rule_id: 0\n" + text, True



def _ensure_fromversion_yaml(text: str, version: str = "6.10.0") -> Tuple[str, bool]:
    """
    Ensure fromversion: <version> exists and is set correctly in YAML.
    Used for correlation rules and scripts.
    """
    # Already correct?
    if re.search(rf'^\s*fromversion\s*:\s*{re.escape(version)}\s*$', text, flags=re.M):
        return text, False

    # fromversion exists but wrong -> fix it
    if re.search(r'^\s*fromversion\s*:', text, flags=re.M):
        new_text, n = re.subn(
            r'^(\s*fromversion\s*:\s*).*$',
            r'\g<1>' + version,
            text,
            flags=re.M,
            )
        return new_text, n > 0

    # No fromversion -> insert near top (after comments)
    lines = text.splitlines()
    insert_at = None
    for i, line in enumerate(lines):
        if line.strip() and not line.strip().startswith("#"):
            insert_at = i
            break

    line_to_insert = f"fromversion: {version}"
    if insert_at is None:
        lines.append(line_to_insert)
    else:
        lines.insert(insert_at, line_to_insert)

    new_text = "\n".join(lines)
    if not new_text.endswith("\n"):
        new_text += "\n"

    return new_text, True

# ------------------------------------------------------------
# Correlation rule & playbook normalize logic
# ------------------------------------------------------------

def normalize_ruleid_and_adopted(root: str, dry_run: bool) -> bool:
    changed_any = False

    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            low = _norm(fp)

            # Only YAML/JSON
            if not (low.endswith(".json") or low.endswith(".yml") or low.endswith(".yaml")):
                continue

            is_playbook = _is_playbook(fp)
            is_corr = _is_corr_rule(fp)

            # Nothing to do?
            if not is_playbook and not is_corr:
                continue

            try:
                # JSON correlation rules
                if low.endswith(".json"):
                    if not is_corr:
                        continue

                    obj, ok = _load_json(fp)
                    if not ok or not isinstance(obj, dict):
                        continue

                    changed = False

                    # rule_id: 0
                    if obj.get("rule_id") != 0:
                        obj["rule_id"] = 0
                        changed = True

                    # fromVersion: "6.10.0"
                    if obj.get("fromVersion") != "6.10.0":
                        obj["fromVersion"] = "6.10.0"
                        changed = True

                    if changed:
                        print(f"[INFO] Normalize JSON correlation rule: {fp}")
                        changed_any = True
                        if not dry_run:
                            _dump_json(fp, obj)

                # YAML playbooks & correlation rules
                else:
                    try:
                        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                            text = f.read()
                    except Exception as e:
                        print(f"[WARN] Failed to read YAML {fp}: {e}")
                        continue

                    changed = False

                    if is_corr:
                        text, c = _set_rule_id_yaml(text)
                        changed |= c

                        text, c = _ensure_fromversion_yaml(text, version="6.10.0")
                        changed |= c

                    if is_playbook:
                        text, c = _ensure_adopted_in_yaml(text)
                        changed |= c

                    if changed:
                        print(f"[INFO] Normalize YAML: {fp}")
                        changed_any = True
                        if not dry_run:
                            try:
                                with open(fp, "w", encoding="utf-8") as f:
                                    f.write(text)
                            except Exception as e:
                                print(f"[WARN] Failed to write YAML {fp}: {e}")

            except Exception as e:
                print(f"[WARN] Failed {fp}: {e}")

    return changed_any

# ------------------------------------------------------------
# Lists JSON normalize logic
# ------------------------------------------------------------

def normalize_lists(root: str, dry_run: bool) -> bool:
    """
    For any JSON file under a Lists/* directory, ensure that
    "id" and "name" match the directory name.
    """
    changed_any = False

    for dirpath, _, filenames in os.walk(root):
        if "/lists/" not in _norm(dirpath):
            continue

        dir_name = os.path.basename(dirpath)
        if not dir_name:
            continue

        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            if not _is_list_json(fp):
                continue

            data, ok = _load_json(fp)
            if not ok or not isinstance(data, dict):
                continue

            changed = False
            if data.get("id") != dir_name:
                data["id"] = dir_name
                changed = True
            if data.get("name") != dir_name:
                data["name"] = dir_name
                changed = True

            if changed:
                print(f"[INFO] Normalize List JSON (id/name -> {dir_name}): {fp}")
                changed_any = True
                if not dry_run:
                    _dump_json(fp, data)

    return changed_any

# ------------------------------------------------------------
# Scripts JSON normalize logic
# ------------------------------------------------------------

def normalize_scripts_json(root: str, dry_run: bool) -> bool:
    """
    For any JSON file under a Scripts/* directory, ensure that
      - "id" and "name" match the directory name
      - "fromVersion" is 6.10.0
    """
    changed_any = False

    for dirpath, _, filenames in os.walk(root):
        if "/scripts/" not in _norm(dirpath):
            continue

        dir_name = os.path.basename(dirpath)
        if not dir_name:
            continue

        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            if not _is_script_json(fp):
                continue

            data, ok = _load_json(fp)
            if not ok or not isinstance(data, dict):
                continue

            changed = False
            if data.get("id") != dir_name:
                data["id"] = dir_name
                changed = True
            if data.get("name") != dir_name:
                data["name"] = dir_name
                changed = True

            # Ensure fromVersion
            if data.get("fromVersion") != "6.10.0":
                data["fromVersion"] = "6.10.0"
                changed = True

            if changed:
                print(
                    f"[INFO] Normalize Script JSON (id/name/fromVersion -> "
                    f"{dir_name}/6.10.0): {fp}"
                )
                changed_any = True
                if not dry_run:
                    _dump_json(fp, data)

    return changed_any

# ------------------------------------------------------------
# Scripts YAML normalize logic
# ------------------------------------------------------------

def normalize_scripts_yaml(root: str, dry_run: bool) -> bool:
    """
    For any YAML file under a Scripts/* directory, ensure that:
      - id == directory name
      - top-level name == directory name
      - fromversion: 6.10.0

    Only logs/rewrites when something actually changes.
    """
    changed_any = False

    for dirpath, _, filenames in os.walk(root):
        if "/scripts/" not in _norm(dirpath):
            continue

        dir_name = os.path.basename(dirpath)
        if not dir_name:
            continue

        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            if not _is_script_yaml(fp):
                continue

            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception as e:
                print(f"[WARN] Failed to read script YAML {fp}: {e}")
                continue

            changed = False

            # Check if id already matches
            id_ok = re.search(
                rf'^\s*id\s*:\s*{re.escape(dir_name)}\s*$',
                text,
                flags=re.M,
            ) is not None

            # Check if name already matches
            name_ok = re.search(
                rf'^name\s*:\s*{re.escape(dir_name)}\s*$',
                text,
                flags=re.M,
            ) is not None

            # Only rewrite id if it's not already correct
            if not id_ok:
                new_text, n1 = re.subn(
                    r'^(\s*id\s*:\s*).*$',
                    r'\1' + dir_name,
                    text,
                    count=1,
                    flags=re.M,
                    )
                if n1 > 0:
                    changed = True
                    text = new_text

            # Only rewrite name if it's not already correct
            if not name_ok:
                new_text, n2 = re.subn(
                    r'^name\s*:\s*.*$',
                    'name: ' + dir_name,
                    text,
                    count=1,
                    flags=re.M,
                    )
                if n2 > 0:
                    changed = True
                    text = new_text

            # Ensure fromversion: 6.10.0
            text, c = _ensure_fromversion_yaml(text, version="6.10.0")
            changed |= c

            if changed:
                print(
                    f"[INFO] Normalize Script YAML (id/name/fromversion -> "
                    f"{dir_name}/6.10.0): {fp}"
                )
                changed_any = True
                if not dry_run:
                    try:
                        with open(fp, "w", encoding="utf-8") as f:
                            f.write(text)
                    except Exception as e:
                        print(f"[WARN] Failed to write script YAML {fp}: {e}")

    return changed_any

# ------------------------------------------------------------
# Pack metadata cleanup
# ------------------------------------------------------------

def clean_pack_metadata(root: str, fix: bool) -> bool:
    """
    Remove Builtin/BuiltIn from pack_metadata.json dependencies if present.

    Returns True if such a dependency existed (and would be/was removed).
    """
    path = _find_file(root, "pack_metadata.json")
    if not path:
        print("[WARN] pack_metadata.json not found")
        return False

    data, ok = _load_json(path)
    if not ok:
        return False

    deps = data.get("dependencies") or {}
    had_builtin = "Builtin" in deps or "BuiltIn" in deps

    if had_builtin:
        if fix:
            deps.pop("Builtin", None)
            deps.pop("BuiltIn", None)
            data["dependencies"] = deps
            _dump_json(path, data)
            print(f"[INFO] Removed Builtin from {path}")
        else:
            print(f"[WARN] Builtin dependency found in {path}")

    return had_builtin

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", help="Pack root path")
    ap.add_argument("--fix", action="store_true", help="Apply changes instead of check-only")
    args = ap.parse_args()

    dry_run = not args.fix

    changed_anything = False

    changed_anything |= ensure_pack_required_files(args.root, dry_run=dry_run)
    changed_anything |= normalize_ruleid_and_adopted(args.root, dry_run=dry_run)
    changed_anything |= normalize_lists(args.root, dry_run=dry_run)
    changed_anything |= normalize_scripts_json(args.root, dry_run=dry_run)
    changed_anything |= normalize_scripts_yaml(args.root, dry_run=dry_run)
    changed_anything |= clean_pack_metadata(args.root, fix=args.fix)

    if dry_run and changed_anything:
        print(
            "❌ normalize_ruleid_adopted.py: changes are required. "
            "Run with --fix locally and commit the updates."
        )
        raise SystemExit(1)

    print("✅ Completed normalize_ruleid_adopted.py")


if __name__ == "__main__":
    main()
