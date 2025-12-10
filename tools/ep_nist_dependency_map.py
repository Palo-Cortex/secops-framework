#!/usr/bin/env python3
"""
ep_nist_dependency_map.py

Goal:
  Starting from a single "entry" playbook (e.g. EP IR NIST (800-61)),
  build a dependency graph and answer 3 questions for a given root pack:

  1) What *local* content in the root pack is required?
     - playbooks
     - scripts / automations
     - lists

  2) What *local* content in the root pack is NOT required
     (i.e., not reachable from the entry playbook)?

  3) What *external* content (in other packs) is referenced?
     - playbooks
     - scripts
     - lists

Exception lists:
  - LOCAL exceptions: local objects that you do NOT want to show as "NOT NEEDED"
    (e.g., standalone tools you want to keep for other flows).
  - EXTERNAL exceptions: common built-in commands or scripts you don't want
    to see in the external dependency list (e.g. Builtin|||*, generic utilities).

Usage (from repo root):

  python tools/ep_nist_dependency_map.py \
      --root-pack Packs/soc-optimization \
      --entry-name "EP IR NIST (800-61)" \
      --other-pack Packs/soc-common-playbooks
"""

import argparse
import os
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

try:
    import yaml  # PyYAML
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


# ----------------- EXCEPTION LISTS ----------------- #
# You can freely edit/add to these.

# Local content exceptions:
# These are IDs or names of playbooks/scripts/lists INSIDE the root pack
# that you don't want flagged as "NOT NEEDED (UNREACHABLE)" even if they
# aren't used by EP IR NIST.
EXCEPTION_LOCAL_PLAYBOOK_IDS = {
    "SOC Comms Email",
    "SOC Comms IM",
    "SOC Comms Ticketing"
}

EXCEPTION_LOCAL_SCRIPT_IDS = {
    "removeSOCFramework",
    "setValueTags",
    "ShadowModeRouter"
}

EXCEPTION_LOCAL_LIST_IDS = {
    "SOCProductCategoryMap",
    "SOCOptimizationConfig",
    "SOCFrameworkActions",
    "SOCVendorCapabilities",
    "SOCExecutionList",
    "SOCArtifacts"
}


# External script/command exceptions:
# These are script/command names that should NOT be listed as external deps.
EXCEPTION_EXTERNAL_SCRIPT_REFS: Set[str] = {
    # Common built-ins / generic things you don't care about:
    "Builtin|||setIncident",
    "Builtin|||setContext",
    "Builtin|||DeleteContext",
    "Builtin|||createNewIncident",
    "Builtin|||setIncident",
    "Builtin|||setContext",
    "Builtin|||closeInvestigation",
    "Print",
    "Set",
    "SetAndHandleEmpty",
    "DBotFindSimilarAlerts",
    "|||ip",
    "DeleteContext",
    "GetAlertTasks",
    "GetTime",
    "SearchAlertsV2",
    "|||core-api-post",
    "|||xql-post-to-dataset"
    # Add others as needed
}

# If True, *any* script name starting with "Builtin|||" will be ignored
# in external dependency reporting.
IGNORE_ALL_BUILTIN_COMMANDS: bool = True


# ----------------- BASIC TYPES & HELPERS ----------------- #

TEXT_EXTENSIONS = (
    ".yml", ".yaml", ".json", ".py", ".xif",
    ".md", ".txt", ".ini", ".cfg", ".conf"
)


@dataclass
class ObjectDef:
    type: str   # 'playbook', 'script', 'list'
    id: str
    name: str
    path: str
    pack: str   # pack folder this object came from (e.g. Packs/soc-common-playbooks)


@dataclass
class ExternalRef:
    ref_type: str       # 'playbook' / 'script' / 'list'
    value: str          # referenced id or name
    file: str           # where it was referenced
    context: str        # brief hint
    resolved_pack: str  # which other pack (if found), else "UNKNOWN"


def is_text_file(path: str) -> bool:
    _, ext = os.path.splitext(path)
    return ext.lower() in TEXT_EXTENSIONS


def load_yaml(path: str):
    """Best-effort YAML loader that won't die on XSOAR tags."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        sys.stderr.write(f"WARNING: Failed to parse YAML: {path}: {e}\n")
        return {}


def walk_files(root: str) -> List[str]:
    files: List[str] = []
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            files.append(os.path.join(dirpath, filename))
    return files


def build_file_text_cache(files: List[str]) -> Dict[str, str]:
    cache: Dict[str, str] = {}
    for path in files:
        if not is_text_file(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                cache[path] = f.read()
        except OSError:
            pass
    return cache


def list_is_referenced_anywhere(obj: ObjectDef, file_text: Dict[str, str]) -> bool:
    """
    Check if a list's id or name appears anywhere else in the repo
    (scripts, other packs, etc.), excluding its own definition file.
    """
    for path, text in file_text.items():
        if os.path.abspath(path) == os.path.abspath(obj.path):
            continue
        if obj.id in text or obj.name in text:
            return True
    return False


def resolve_in_index(value: str, objs: Dict[str, ObjectDef]) -> Optional[ObjectDef]:
    """Try resolve by id first, then by name."""
    if value in objs:
        return objs[value]
    for o in objs.values():
        if o.name == value:
            return o
    return None


# ----------------- DISCOVERY IN ONE PACK ----------------- #

def discover_playbooks(pack_root: str) -> Dict[str, ObjectDef]:
    res: Dict[str, ObjectDef] = {}
    pb_root = os.path.join(pack_root, "Playbooks")
    if not os.path.isdir(pb_root):
        return res

    for dirpath, _, filenames in os.walk(pb_root):
        for filename in filenames:
            if not filename.lower().endswith((".yml", ".yaml")):
                continue
            full_path = os.path.join(dirpath, filename)
            data = load_yaml(full_path)
            if not isinstance(data, dict):
                continue
            # Heuristic: playbook has 'tasks' dict and 'id'
            if "tasks" not in data or not isinstance(data["tasks"], dict):
                continue
            pb_id = data.get("id")
            pb_name = data.get("name") or pb_id
            if not pb_id:
                continue
            if pb_id in res:
                sys.stderr.write(
                    f"WARNING: duplicate playbook id {pb_id!r} in {full_path} "
                    f"(already {res[pb_id].path})\n"
                )
            res[pb_id] = ObjectDef("playbook", pb_id, pb_name, full_path, pack_root)
    return res


def discover_scripts(pack_root: str) -> Dict[str, ObjectDef]:
    res: Dict[str, ObjectDef] = {}
    root = os.path.join(pack_root, "Scripts")
    if not os.path.isdir(root):
        return res

    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            if not filename.lower().endswith((".yml", "..yaml")):
                continue
            full_path = os.path.join(dirpath, filename)
            data = load_yaml(full_path)
            if not isinstance(data, dict):
                continue
            common = data.get("commonfields") or {}
            sid = common.get("id")
            sname = data.get("name") or sid
            if not sid:
                continue
            if sid in res:
                sys.stderr.write(
                    f"WARNING: duplicate script id {sid!r} in {full_path} "
                    f"(already {res[sid].path})\n"
                )
            res[sid] = ObjectDef("script", sid, sname, full_path, pack_root)
    return res


def discover_lists(pack_root: str) -> Dict[str, ObjectDef]:
    """
    Discover XSOAR lists in a pack.

    In content packs, lists are usually stored as:
      - Lists/<name>.json
      - Lists/<name>_data.json
      - Optionally YAML definitions with a 'name' field.

    We treat both JSON files (base + _data) as the same logical list with id=name.
    """
    res: Dict[str, ObjectDef] = {}
    root = os.path.join(pack_root, "Lists")
    if not os.path.isdir(root):
        return res

    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            fname, ext = os.path.splitext(filename)

            # Normalize base name:
            #   SOCFrameworkConfig.json          -> SOCFrameworkConfig
            #   SOCFrameworkConfig_data.json     -> SOCFrameworkConfig
            base = fname
            if base.endswith("_data"):
                base = base[:-5]  # strip "_data"

            if ext.lower() not in (".json", ".yml", ".yaml"):
                continue

            list_id = base
            list_name = base

            # If we already recorded this logical list, skip
            if list_id in res:
                continue

            # If it's YAML and has a 'name', prefer that
            if ext.lower() in (".yml", ".yaml"):
                data = load_yaml(full_path)
                if isinstance(data, dict):
                    list_name = data.get("name") or list_name
                    list_id = list_name

            res[list_id] = ObjectDef("list", list_id, list_name, full_path, pack_root)

    return res


def index_pack(pack_root: str):
    return (
        discover_playbooks(pack_root),
        discover_scripts(pack_root),
        discover_lists(pack_root),
    )


# ----------------- DEPENDENCY CRAWL (MULTI-ROOT) ----------------- #

def crawl_dependencies(
        root_playbooks: List[ObjectDef],
        local_pbs: Dict[str, ObjectDef],
        local_scripts: Dict[str, ObjectDef],
        local_lists: Dict[str, ObjectDef],
        external_indexes: List[Tuple[str, Dict[str, ObjectDef], Dict[str, ObjectDef], Dict[str, ObjectDef]]],
) -> Tuple[Set[str], Set[str], Set[str], List[ExternalRef]]:
    """
    BFS from one or more root playbooks, following:
      - sub-playbook references
      - script references
      - list references (via typical scriptarguments: listName, list_name, list, lists, listNames)

    Returns:
      reachable_local_pbs, reachable_local_scripts, reachable_local_lists, external_refs
    """
    # Start from all roots
    reachable_pbs: Set[str] = {pb.id for pb in root_playbooks}
    reachable_scripts: Set[str] = set()
    reachable_lists: Set[str] = set()
    external_refs: List[ExternalRef] = []

    queue: List[str] = list(reachable_pbs)

    while queue:
        current_id = queue.pop(0)
        pb = local_pbs.get(current_id)
        if not pb:
            continue

        data = load_yaml(pb.path)
        tasks = data.get("tasks") or {}
        if not isinstance(tasks, dict):
            continue

        for tid, task in tasks.items():
            if not isinstance(task, dict):
                continue
            t = task.get("task") or {}

            # --- sub-playbook ---
            sub_pb_id = t.get("playbookId") or t.get("playbook_id")
            sub_pb_name = t.get("playbookName") or t.get("playbook")

            if isinstance(sub_pb_id, str) or isinstance(sub_pb_name, str):
                ref_val = sub_pb_id if isinstance(sub_pb_id, str) else sub_pb_name

                resolved_local = resolve_in_index(ref_val, local_pbs)
                if resolved_local:
                    if resolved_local.id not in reachable_pbs:
                        reachable_pbs.add(resolved_local.id)
                        queue.append(resolved_local.id)
                else:
                    resolved_pack = "UNKNOWN"
                    for pack_root, ext_pbs, _, _ in external_indexes:
                        if resolve_in_index(ref_val, ext_pbs):
                            resolved_pack = pack_root
                            break
                    external_refs.append(
                        ExternalRef(
                            ref_type="playbook",
                            value=ref_val,
                            file=pb.path,
                            context=f"task {tid} playbook",
                            resolved_pack=resolved_pack,
                        )
                    )

            # --- script / automation ---
            script_ref = (
                    t.get("scriptName")
                    or t.get("script")
                    or t.get("scriptId")
                    or t.get("script_id")
            )
            if isinstance(script_ref, str):
                # Skip exceptions for external scripts/commands
                if IGNORE_ALL_BUILTIN_COMMANDS and script_ref.startswith("Builtin|||"):
                    pass  # ignore builtin
                elif script_ref in EXCEPTION_EXTERNAL_SCRIPT_REFS:
                    pass  # ignore explicitly whitelisted
                else:
                    resolved_local = resolve_in_index(script_ref, local_scripts)
                    if resolved_local:
                        reachable_scripts.add(resolved_local.id)
                    else:
                        resolved_pack = "UNKNOWN"
                        for pack_root, _, ext_scripts, _ in external_indexes:
                            if resolve_in_index(script_ref, ext_scripts):
                                resolved_pack = pack_root
                                break
                        external_refs.append(
                            ExternalRef(
                                ref_type="script",
                                value=script_ref,
                                file=pb.path,
                                context=f"task {tid} script",
                                resolved_pack=resolved_pack,
                            )
                        )

            # --- lists via scriptarguments ---
            args = task.get("scriptarguments") or {}
            if isinstance(args, dict):
                for arg_name, arg_val in args.items():
                    arg_key = arg_name.lower()
                    # common list arg names
                    if arg_key not in ("listname", "list_name", "list", "lists", "listnames"):
                        continue

                    val = None
                    if isinstance(arg_val, dict):
                        val = arg_val.get("simple")
                    elif isinstance(arg_val, str):
                        val = arg_val
                    if not isinstance(val, str):
                        continue

                    resolved_local = resolve_in_index(val, local_lists)
                    if resolved_local:
                        reachable_lists.add(resolved_local.id)
                    else:
                        resolved_pack = "UNKNOWN"
                        for pack_root, _, _, ext_lists in external_indexes:
                            if resolve_in_index(val, ext_lists):
                                resolved_pack = pack_root
                                break
                        external_refs.append(
                            ExternalRef(
                                ref_type="list",
                                value=val,
                                file=pb.path,
                                context=f"task {tid} arg {arg_name}",
                                resolved_pack=resolved_pack,
                            )
                        )

    return reachable_pbs, reachable_scripts, reachable_lists, external_refs


# ----------------- MAIN ----------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Build dependency map for one or more root playbooks and show what to keep or drop."
    )
    parser.add_argument(
        "--root-pack",
        required=True,
        help="Root pack containing the playbooks (e.g. Packs/soc-optimization-unified).",
    )
    parser.add_argument(
        "--root-playbook-id",
        action="append",
        default=[],
        help="Playbook ID to use as an entry root (can specify multiple).",
    )
    parser.add_argument(
        "--root-playbook-name",
        action="append",
        default=[],
        help="Playbook name to use as an entry root (can specify multiple).",
    )
    parser.add_argument(
        "--other-pack",
        action="append",
        default=[],
        help="Other pack(s) to scan for external dependencies (e.g. Packs/soc-common-playbooks). Can be used multiple times.",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repo root for global text search (default: current directory).",
    )
    args = parser.parse_args()

    root_pack = args.root_pack
    if not os.path.isdir(root_pack):
        sys.stderr.write(f"ERROR: root pack not found: {root_pack}\n")
        sys.exit(1)

    # Index root pack
    print(f"Indexing root pack: {root_pack}")
    local_pbs, local_scripts, local_lists = index_pack(root_pack)
    print(f"  Playbooks: {len(local_pbs)}")
    print(f"  Scripts:   {len(local_scripts)}")
    print(f"  Lists:     {len(local_lists)}")

    # Index external packs
    external_indexes: List[Tuple[str, Dict[str, ObjectDef], Dict[str, ObjectDef], Dict[str, ObjectDef]]] = []
    for p in args.other_pack:
        if not os.path.isdir(p):
            sys.stderr.write(f"WARNING: other pack not found: {p}\n")
            continue
        print(f"Indexing external pack: {p}")
        pbs, scs, lsts = index_pack(p)
        print(f"  Playbooks: {len(pbs)}, Scripts: {len(scs)}, Lists: {len(lsts)}")
        external_indexes.append((p, pbs, scs, lsts))

    # --------------------------------------------
    # Resolve ALL root playbooks (multi-root BFS)
    # --------------------------------------------
    root_playbooks: List[ObjectDef] = []

    # First, resolve by ID
    for rid in args.root_playbook_id:
        if rid not in local_pbs:
            sys.stderr.write(f"ERROR: root playbook id {rid!r} not found in root pack\n")
            sys.exit(1)
        root_playbooks.append(local_pbs[rid])

    # Then resolve by name
    for rname in args.root_playbook_name:
        found = None
        for pb in local_pbs.values():
            if pb.name == rname:
                found = pb
                break
        if not found:
            sys.stderr.write(f"ERROR: root playbook name {rname!r} not found in root pack\n")
            sys.exit(1)
        root_playbooks.append(found)

    if not root_playbooks:
        sys.stderr.write("ERROR: no root playbooks specified. Use --root-playbook-id or --root-playbook-name.\n")
        sys.exit(1)

    print("\nRoot playbooks:")
    for r in root_playbooks:
        print(f"  - {r.id} :: {r.name}")

    # Crawl dependencies from all roots
    reachable_pbs, reachable_scripts, reachable_lists, external_refs = crawl_dependencies(
        root_playbooks,
        local_pbs,
        local_scripts,
        local_lists,
        external_indexes,
    )

    # ---------- reporting helpers ---------- #
    def print_objs(title: str, ids: Set[str], index: Dict[str, ObjectDef]):
        print(f"\n=== {title} ({len(ids)}) ===")
        if not ids:
            print("None")
            return
        for oid in sorted(ids):
            o = index[oid]
            print(f"- {o.id} :: {o.name}")
            print(f"  {o.path}")

    # Local objects to KEEP (reachable)
    print_objs("LOCAL PLAYBOOKS TO KEEP", reachable_pbs, local_pbs)
    print_objs("LOCAL SCRIPTS TO KEEP", reachable_scripts, local_scripts)
    print_objs("LOCAL LISTS TO KEEP", reachable_lists, local_lists)

    # Local objects NOT needed (unreachable), with exceptions applied
    all_pb_ids = set(local_pbs.keys())
    all_script_ids = set(local_scripts.keys())
    all_list_ids = set(local_lists.keys())

    unused_pbs = all_pb_ids - reachable_pbs - EXCEPTION_LOCAL_PLAYBOOK_IDS
    unused_scripts = all_script_ids - reachable_scripts - EXCEPTION_LOCAL_SCRIPT_IDS
    unused_lists = all_list_ids - reachable_lists - EXCEPTION_LOCAL_LIST_IDS

    # Second-pass: for lists, see if they are referenced anywhere in repo text
    repo_root = args.repo_root
    print(f"\nScanning repo root for list references: {repo_root}")
    all_files = walk_files(repo_root)
    file_text = build_file_text_cache(all_files)

    really_unused_lists: Set[str] = set()
    for lid in unused_lists:
        obj = local_lists[lid]
        if list_is_referenced_anywhere(obj, file_text):
            # It's used somewhere (maybe in a script), so don't treat as unused
            continue
        really_unused_lists.add(lid)

    unused_lists = really_unused_lists

    print_objs("LOCAL PLAYBOOKS NOT NEEDED (UNREACHABLE, EXCEPTIONS REMOVED)", unused_pbs, local_pbs)
    print_objs("LOCAL SCRIPTS NOT NEEDED (UNREACHABLE, EXCEPTIONS REMOVED)", unused_scripts, local_scripts)
    print_objs("LOCAL LISTS NOT NEEDED (UNREACHABLE, EXCEPTIONS + TEXT SEARCH APPLIED)", unused_lists, local_lists)

    # External dependencies
    print(f"\n=== EXTERNAL DEPENDENCIES ({len(external_refs)}) ===")
    if not external_refs:
        print("None 🎉")
        return

    by_key: Dict[Tuple[str, str], List[ExternalRef]] = {}
    for e in external_refs:
        key = (e.ref_type, e.resolved_pack)
        by_key.setdefault(key, []).append(e)

    for (rt, pack_name), refs in sorted(by_key.items(), key=lambda x: (x[0][0], x[0][1] or "")):
        print(f"\n-- {rt} in {pack_name} ({len(refs)}) --")
        for r in sorted(refs, key=lambda x: (x.value, x.file)):
            print(f"- {r.value}")
            print(f"  referenced in: {r.file}")
            print(f"  context:       {r.context}")


if __name__ == "__main__":
    main()