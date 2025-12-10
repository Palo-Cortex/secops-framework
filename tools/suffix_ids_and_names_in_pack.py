#!/usr/bin/env python3
"""
suffix_ids_and_names_in_pack.py

Add a suffix to IDs (e.g. "_V3") and names (e.g. " V3") for playbooks, scripts,
and lists in a single XSOAR/XSIAM content pack, and update references inside
that pack.

What it does for a given pack:

- Playbooks (Playbooks/*.yml):
  * Finds top-level `id` field.
  * If it doesn't already end with the ID suffix, renames it: id -> id + id_suffix.
  * After ID changes, walks the file again and ensures top-level `name:` ends
    with name_suffix (e.g. " V3"). If not, appends it.

- Scripts (Scripts/*.yml):
  * Looks for `commonfields.id`.
  * If it doesn't already end with the ID suffix, renames it.
  * Then ensures top-level `name:` ends with name_suffix.

- Lists (Lists/*):
  * Treats list ID as the base folder name (e.g. Lists/SOCOptimizationConfig/...).
  * If base doesn't already end with the ID suffix, renames folder and
    .json / _data.json files to base + id_suffix.
  * E.g. Lists/SOCOptimizationConfig -> Lists/SOCOptimizationConfig_V3

- After building an old_id -> new_id mapping for all objects, it:
  * Walks all files under the pack
  * For each file, replaces *literal* old_id with new_id in the file text
    (updating playbookId/scriptName/listName, demisto.getList("<old>"), etc.)

Usage (from repo root):

  DRY RUN (no modifications):

    python tools/suffix_ids_and_names_in_pack.py \
      --pack Packs/soc-optimization-unified \
      --id-suffix "_V3" \
      --name-suffix " V3" \
      --dry-run

  APPLY changes:

    python tools/suffix_ids_and_names_in_pack.py \
      --pack Packs/soc-optimization-unified \
      --id-suffix "_V3" \
      --name-suffix " V3"

NOTE:
  - This operates only in the given pack directory.
  - It does not touch other packs like Packs/soc-optimization (legacy).
  - Always run with --dry-run first and commit before applying.
"""

import argparse
import os
import sys
from typing import Dict, List, Tuple


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def find_playbook_ids(pack_root: str, id_suffix: str) -> Dict[str, str]:
    """
    Scan Playbooks/*.yml for top-level 'id:' and build old_id -> new_id mapping.
    """
    mapping: Dict[str, str] = {}
    pb_root = os.path.join(pack_root, "Playbooks")
    if not os.path.isdir(pb_root):
        return mapping

    for dirpath, _, filenames in os.walk(pb_root):
        for filename in filenames:
            if not filename.lower().endswith((".yml", ".yaml")):
                continue
            full_path = os.path.join(dirpath, filename)
            text = read_text(full_path)
            old_id = None
            for line in text.splitlines():
                stripped = line.lstrip()
                if stripped.startswith("id:"):
                    # id: some value
                    val = stripped[len("id:"):].strip()
                    # strip surrounding quotes if any
                    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                        val = val[1:-1]
                    old_id = val
                    break
            if not old_id:
                continue
            if old_id.endswith(id_suffix):
                # already suffixed
                continue
            new_id = old_id + id_suffix
            mapping[old_id] = new_id
    return mapping


def find_script_ids(pack_root: str, id_suffix: str) -> Dict[str, str]:
    """
    Scan Scripts/*.yml for 'commonfields:' followed by 'id:' and build mapping.
    If that fails, fall back to first top-level 'id:'.
    """
    mapping: Dict[str, str] = {}
    sc_root = os.path.join(pack_root, "Scripts")
    if not os.path.isdir(sc_root):
        return mapping

    for dirpath, _, filenames in os.walk(sc_root):
        for filename in filenames:
            if not filename.lower().endswith((".yml", ".yaml")):
                continue
            full_path = os.path.join(dirpath, filename)
            text = read_text(full_path)
            lines = text.splitlines()

            old_id = None
            in_commonfields = False
            for line in lines:
                stripped = line.lstrip()
                if stripped.startswith("commonfields:"):
                    in_commonfields = True
                    continue
                if in_commonfields:
                    # we expect something like: id: SomeScript
                    if stripped.startswith("id:"):
                        val = stripped[len("id:"):].strip()
                        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                            val = val[1:-1]
                        old_id = val
                        break
                    # if we hit another top-level key, stop looking in commonfields
                    if not line.startswith(" ") and not line.startswith("\t"):
                        in_commonfields = False

            # fallback: first top-level id
            if not old_id:
                for line in lines:
                    stripped = line.lstrip()
                    if stripped.startswith("id:"):
                        val = stripped[len("id:"):].strip()
                        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                            val = val[1:-1]
                        old_id = val
                        break

            if not old_id:
                continue
            if old_id.endswith(id_suffix):
                continue
            new_id = old_id + id_suffix
            mapping[old_id] = new_id
    return mapping


def find_list_ids(pack_root: str, id_suffix: str) -> Dict[str, str]:
    """
    For lists, treat each subdirectory of Lists/ as a list ID, based on folder name.

    E.g.
      Lists/SOCOptimizationConfig/...
      -> list id "SOCOptimizationConfig"
      -> new id "SOCOptimizationConfig_V3"
    """
    mapping: Dict[str, str] = {}
    lists_root = os.path.join(pack_root, "Lists")
    if not os.path.isdir(lists_root):
        return mapping

    for entry in os.listdir(lists_root):
        full_path = os.path.join(lists_root, entry)
        if not os.path.isdir(full_path):
            continue
        old_id = entry
        if old_id.endswith(id_suffix):
            continue
        new_id = old_id + id_suffix
        mapping[old_id] = new_id
    return mapping


def rename_list_dirs_and_files(pack_root: str, list_mapping: Dict[str, str], dry_run: bool = False) -> None:
    """
    Rename list directories and their primary JSON files to new IDs.

    E.g.
      Lists/SOCOptimizationConfig -> Lists/SOCOptimizationConfig_V3
      Lists/SOCOptimizationConfig/SOCOptimizationConfig.json -> Lists/SOCOptimizationConfig_V3/SOCOptimizationConfig_V3.json
      Lists/SOCOptimizationConfig/SOCOptimizationConfig_data.json -> Lists/SOCOptimizationConfig_V3/SOCOptimizationConfig_V3_data.json
    """
    lists_root = os.path.join(pack_root, "Lists")
    if not os.path.isdir(lists_root):
        return

    for old_id, new_id in list_mapping.items():
        old_dir = os.path.join(lists_root, old_id)
        if not os.path.isdir(old_dir):
            continue
        new_dir = os.path.join(lists_root, new_id)

        print(f"[Lists] Renaming directory: {old_dir} -> {new_dir}")
        if not dry_run:
            os.rename(old_dir, new_dir)

        # rename files inside the new dir
        for filename in os.listdir(new_dir):
            full_old = os.path.join(new_dir, filename)
            if not os.path.isfile(full_old):
                continue
            # change base name occurrences
            new_filename = filename.replace(old_id, new_id)
            full_new = os.path.join(new_dir, new_filename)
            if full_new == full_old:
                continue
            print(f"[Lists]   Renaming file: {full_old} -> {full_new}")
            if not dry_run:
                os.rename(full_old, full_new)


def apply_text_replacements(pack_root: str, id_mapping: Dict[str, str], dry_run: bool = False) -> None:
    """
    Walk all files in pack_root and replace literal old_id with new_id in file text.

    This updates:
      - id: <old>
      - playbookId/scriptName/listName references
      - demisto.getList("<old>") calls
      - etc.
    """
    # Sort mapping by descending length of old_id to avoid partial overlaps
    replacements: List[Tuple[str, str]] = sorted(
        id_mapping.items(), key=lambda kv: len(kv[0]), reverse=True
    )

    for dirpath, _, filenames in os.walk(pack_root):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)

            # Skip obviously binary-ish stuff
            _, ext = os.path.splitext(filename)
            if ext.lower() not in (".yml", ".yaml", ".json", ".md", ".txt", ".xif", ".ini", ".cfg", ".conf", ""):
                continue

            text = read_text(full_path)
            original_text = text

            for old_id, new_id in replacements:
                if old_id in text:
                    text = text.replace(old_id, new_id)

            if text != original_text:
                print(f"[Text] Updated references in: {full_path}")
                if not dry_run:
                    write_text(full_path, text)


def ensure_name_suffix_in_file(path: str, name_suffix: str) -> bool:
    """
    Ensure the first top-level 'name:' in the file ends with name_suffix.

    Returns True if the file was modified.
    """
    text = read_text(path)
    lines = text.splitlines()
    modified = False

    for i, line in enumerate(lines):
        stripped = line.lstrip()
        # crude heuristic: first "name:" we see, we treat as top-level name
        if stripped.startswith("name:"):
            indent_len = len(line) - len(stripped)
            indent = line[:indent_len]
            val = stripped[len("name:"):].strip()
            if not val:
                break

            # capture quotes if any
            quote_char = ""
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                quote_char = val[0]
                val_inner = val[1:-1]
            else:
                val_inner = val

            # don't double-suffix if already ends with it
            if val_inner.endswith(name_suffix):
                break

            new_val_inner = val_inner + name_suffix
            if quote_char:
                new_val = f"{quote_char}{new_val_inner}{quote_char}"
            else:
                new_val = new_val_inner

            new_line = f"{indent}name: {new_val}"
            lines[i] = new_line
            modified = True
            break

    if modified:
        new_text = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
        write_text(path, new_text)
    return modified


def ensure_name_suffixes(pack_root: str, name_suffix: str, dry_run: bool = False) -> None:
    """
    For all playbook and script YAML files in the pack, ensure their top-level
    name field ends with name_suffix.
    """
    for subdir in ("Playbooks", "Scripts"):
        root = os.path.join(pack_root, subdir)
        if not os.path.isdir(root):
            continue

        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                if not filename.lower().endswith((".yml", ".yaml")):
                    continue
                full_path = os.path.join(dirpath, filename)
                if dry_run:
                    # simulate
                    before = read_text(full_path)
                    lines = before.splitlines()
                    changed = False
                    for line in lines:
                        stripped = line.lstrip()
                        if stripped.startswith("name:"):
                            val = stripped[len("name:"):].strip()
                            if not val:
                                break
                            # strip quotes
                            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                                val_inner = val[1:-1]
                            else:
                                val_inner = val
                            if not val_inner.endswith(name_suffix):
                                changed = True
                            break
                    if changed:
                        print(f"[Names] Would update name in: {full_path}")
                else:
                    if ensure_name_suffix_in_file(full_path, name_suffix):
                        print(f"[Names] Updated name in: {full_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Suffix playbook/script/list IDs in a pack and update references and names."
    )
    parser.add_argument(
        "--pack",
        required=True,
        help="Path to the pack directory (e.g. Packs/soc-optimization-unified).",
    )
    parser.add_argument(
        "--id-suffix",
        required=True,
        help='Suffix to append to IDs (e.g. "_V3").',
    )
    parser.add_argument(
        "--name-suffix",
        required=True,
        help='Suffix to append to names (e.g. " V3").',
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="If set, only prints what would be changed without modifying files.",
    )
    args = parser.parse_args()

    pack_root = args.pack
    id_suffix = args.id_suffix
    name_suffix = args.name_suffix
    dry_run = args.dry_run

    if not os.path.isdir(pack_root):
        print(f"ERROR: pack directory not found: {pack_root}", file=sys.stderr)
        sys.exit(1)

    print(f"Pack root: {pack_root}")
    print(f"ID suffix: {id_suffix}")
    print(f"Name suffix: {name_suffix}")
    print(f"Dry run: {dry_run}")
    print()

    # 1. Gather ID mappings
    pb_mapping = find_playbook_ids(pack_root, id_suffix)
    sc_mapping = find_script_ids(pack_root, id_suffix)
    list_mapping = find_list_ids(pack_root, id_suffix)

    print("Playbook ID changes:")
    if not pb_mapping:
        print("  (none)")
    else:
        for old, new in pb_mapping.items():
            print(f"  {old!r} -> {new!r}")

    print("\nScript ID changes:")
    if not sc_mapping:
        print("  (none)")
    else:
        for old, new in sc_mapping.items():
            print(f"  {old!r} -> {new!r}")

    print("\nList ID changes:")
    if not list_mapping:
        print("  (none)")
    else:
        for old, new in list_mapping.items():
            print(f"  {old!r} -> {new!r}")

    if dry_run:
        # Also simulate name changes
        print("\nSimulating name suffix updates...")
        ensure_name_suffixes(pack_root, name_suffix, dry_run=True)
        print("\nDry run complete. No files were modified.")
        return

    # 2. Rename list directories/files first (so paths match new IDs)
    if list_mapping:
        rename_list_dirs_and_files(pack_root, list_mapping, dry_run=dry_run)

    # 3. Build combined mapping for text replacements
    id_mapping: Dict[str, str] = {}
    id_mapping.update(pb_mapping)
    id_mapping.update(sc_mapping)
    id_mapping.update(list_mapping)

    # 4. Apply text replacements across all files in the pack
    if id_mapping:
        print("\nApplying ID text replacements across pack...")
        apply_text_replacements(pack_root, id_mapping, dry_run=dry_run)
    else:
        print("\nNo ID changes to apply.")

    # 5. Ensure names end with the name suffix
    print("\nEnsuring playbook/script names end with name suffix...")
    ensure_name_suffixes(pack_root, name_suffix, dry_run=dry_run)

    print("\nDone.")


if __name__ == "__main__":
    main()
