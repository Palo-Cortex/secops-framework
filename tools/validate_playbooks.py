#!/usr/bin/env python3
"""
XSIAM / XSOAR SOC Framework — Playbook Integrity Validator
==========================================================
Checks:
  1. Integration references  — every brand/integration used in a task
                               must exist as a configured instance in
                               xsoar_config.json
  2. Orphaned playbooks      — playbooks in the PRIMARY pack that are
                               never called (from any pack) AND are not
                               declared entry points or library exports
  3. Missing lists           — GetList / SetList calls whose list name
                               is not present in xsoar_config.json
  4. Sub-playbook chains     — full recursive dependency graph across
                               all packs; detects missing refs + cycles

Auto-discovery:
  Dependent packs are resolved automatically from xsoar_config.json
  "custom_packs".  No need for --packs in most cases.

  xsoar_config.json shape for auto-discovery:
  {
    "custom_packs": [
      { "id": "soc-framework-nist-ir" },
      { "id": "soc-framework-phishing", "path": "../../other-repo/Packs/..." }
    ],
    "exported_playbooks": [
      "Foundation - Upon Trigger V3"
    ]
  }

  "custom_packs[].id"   — resolved as <packs_root>/<id>  (sibling pack dir)
  "custom_packs[].path" — explicit override path (absolute or relative to
                           xsoar_config.json)
  "exported_playbooks"  — playbooks intentionally provided as a dependency
                           for other packs.  Not orphaned; not an error.

Usage:
  python validate_playbooks.py --root Packs/soc-optimization-unified

  All dependent packs are loaded automatically from custom_packs in
  xsoar_config.json.  Override or extend with --packs if needed.

  --root      Primary pack path (default: current directory)
  --packs     Extra pack paths (supplement auto-discovered deps)
  --no-auto   Disable auto-discovery from custom_packs
  --config    xsoar_config.json path (default: <root>/xsoar_config.json)
  --strict    Exit 1 on warnings as well as errors
  --json      Emit machine-readable JSON (for CI artifact upload)
  --verbose   Include INFO-level findings in output
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("ERROR: PyYAML not installed.  Run: pip install pyyaml")

# ─── ANSI colours ─────────────────────────────────────────────────────────────
_USE_COLOR = sys.stdout.isatty()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

RED    = lambda t: _c("31;1", t)
YELLOW = lambda t: _c("33;1", t)
GREEN  = lambda t: _c("32;1", t)
CYAN   = lambda t: _c("36",   t)
DIM    = lambda t: _c("2",    t)
BOLD   = lambda t: _c("1",    t)

# ─── CONSTANTS ────────────────────────────────────────────────────────────────

# Playbooks whose names start with any of these prefixes are treated as entry
# points — they are standalone runners and will NOT trigger the orphan warning.
#
#   EP_   — explicit entry-point convention
#   JOB - — scheduled job playbooks; run by the platform scheduler,
#            never called as a sub-playbook by another playbook
ENTRY_POINT_PREFIXES = (
    "EP_", "ep_",
    "JOB -", "JOB-", "job -", "job-",
)

LIST_SCRIPT_NAMES = {
    "GetList", "getList",
    "SetList", "setList",
    "AppendToList", "appendToList",
    "RemoveFromList",
}

# Platform-native brands — never need a configured instance in xsoar_config.json
#   Builtin / BuiltIn — closeInvestigation, setIncident, PrintErrorEntry, etc.
SHADOW_BRANDS = {
    "Builtin", "BuiltIn", "builtin",
    "Scripts", "scripts",
    "", None,
}

# Add brand strings here to suppress integration-ref errors for specific brands
OPTIONAL_BRANDS: set = set()


# ─── FILE UTILITIES ───────────────────────────────────────────────────────────
def load_yaml(path):
    with Path(path).open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def load_json(path):
    with Path(path).open(encoding="utf-8") as f:
        return json.load(f)

def find_yamls(root):
    hits = []
    for p in Path(root).rglob("*.yml"):
        if any(part.startswith(".") for part in p.parts):
            continue
        if "node_modules" in p.parts:
            continue
        hits.append(p)
    return hits

def is_playbook(data):
    return isinstance(data.get("tasks"), dict)

def playbook_name(data, path):
    return data.get("name") or data.get("id") or Path(path).stem

def is_entry_point(pb_name, data):
    if data.get("entrypoint", False):
        return True
    return any(pb_name.startswith(pfx) for pfx in ENTRY_POINT_PREFIXES)


# ─── TASK PARSING ─────────────────────────────────────────────────────────────
def iter_tasks(data):
    for _id, task_obj in (data.get("tasks") or {}).items():
        if isinstance(task_obj, dict):
            yield _id, task_obj.get("task", task_obj)

def extract_brands(data):
    brands = set()
    for _, task in iter_tasks(data):
        brand = task.get("brand") or task.get("integration") or ""
        if brand and brand not in SHADOW_BRANDS:
            brands.add(brand)
    return brands

def extract_sub_playbooks(data):
    subs = set()
    for _, task in iter_tasks(data):
        if task.get("type") == "playbook":
            name = task.get("playbookName") or task.get("playbookId") or ""
            if name:
                subs.add(name)
    return subs

def extract_list_refs(data):
    lists = set()
    for _, task in iter_tasks(data):
        script = task.get("scriptName") or task.get("script") or ""
        if script in LIST_SCRIPT_NAMES:
            args = task.get("scriptArguments") or task.get("arguments") or {}
            if isinstance(args, dict):
                list_name = (
                        args.get("listName") or args.get("list_name")
                        or args.get("name") or args.get("key") or ""
                )
                if isinstance(list_name, dict):
                    list_name = list_name.get("simple", "")
                if list_name:
                    lists.add(str(list_name))
    return lists


# ─── PACK LOADING ─────────────────────────────────────────────────────────────
def load_pack(root, playbooks, playbook_pack, pack_label, primary=False):
    """
    Scan root for playbook YAMLs and merge into playbooks dict.
    Returns (added, skipped_duplicates).
    """
    root = Path(root)
    added = skipped = 0
    for path in find_yamls(root):
        try:
            data = load_yaml(path)
        except Exception as e:
            print(YELLOW(f"  ⚠  Could not parse {path}: {e}"))
            continue
        if not is_playbook(data):
            continue
        name = playbook_name(data, path)
        if name in playbooks:
            if primary:
                existing = playbook_pack.get(name, "?")
                print(YELLOW(f"  ⚠  Duplicate name '{name}' — already in "
                             f"'{existing}', ignoring copy in '{pack_label}'"))
            skipped += 1
        else:
            playbooks[name] = data
            playbook_pack[name] = pack_label
            added += 1
    return added, skipped


# ─── CONFIG PARSING ───────────────────────────────────────────────────────────
def parse_xsoar_config(config_path):
    """
    Returns (configured_brands, configured_lists, dep_pack_paths, exported_playbooks).

    custom_packs resolution order:
      1. entry has "path" key  → use that (relative to config file dir)
      2. entry has "id"  key  → look for <packs_root>/<id>
         packs_root = config_path.parent.parent  (i.e. repo_root/Packs)
    """
    config_path = Path(config_path)
    if not config_path.exists():
        return set(), set(), [], set()

    raw = load_json(config_path)
    config_dir = config_path.parent
    packs_root  = config_dir.parent   # e.g. secops-framework/Packs/<primary>/../

    # ── integrations ────────────────────────────────────────────────────────
    configured_brands = set()
    for entry in (raw.get("integrations") or []):
        if isinstance(entry, dict):
            brand = entry.get("brand") or entry.get("name") or ""
            if brand:
                configured_brands.add(brand)
        elif isinstance(entry, str):
            configured_brands.add(entry)

    # ── lists ────────────────────────────────────────────────────────────────
    configured_lists = set()
    lists_raw = raw.get("lists", [])
    if isinstance(lists_raw, list):
        for entry in lists_raw:
            name = (entry.get("name") or entry.get("listName") or "") \
                if isinstance(entry, dict) else str(entry)
            if name:
                configured_lists.add(name)
    elif isinstance(lists_raw, dict):
        configured_lists.update(lists_raw.keys())

    # ── custom_packs → dep paths ─────────────────────────────────────────────
    dep_paths = []
    for entry in (raw.get("custom_packs") or []):
        if not isinstance(entry, dict):
            continue
        if "path" in entry:
            # Explicit path — resolve relative to config file location
            candidate = (config_dir / entry["path"]).resolve()
        elif "id" in entry:
            # ID-based: look for <repo>/Packs/<id>
            candidate = (packs_root / entry["id"]).resolve()
        else:
            continue

        if candidate.is_dir():
            dep_paths.append(candidate)
        else:
            print(YELLOW(f"  ⚠  custom_packs entry '{entry}' → "
                         f"'{candidate}' not found, skipping"))

    # ── exported_playbooks ───────────────────────────────────────────────────
    # Playbooks this pack intentionally exposes for other packs to call.
    # They are NOT orphans — they are library exports.
    exported = set(raw.get("exported_playbooks") or [])

    return configured_brands, configured_lists, dep_paths, exported


# ─── CYCLE DETECTION (Tarjan SCC) ────────────────────────────────────────────
def find_cycles(graph):
    idx_ctr = [0]
    stack, lowlink, index, on_stack, sccs = [], {}, {}, {}, []

    def visit(v):
        index[v] = lowlink[v] = idx_ctr[0]; idx_ctr[0] += 1
        stack.append(v); on_stack[v] = True
        for w in graph.get(v, set()):
            if w not in index:
                visit(w)
                lowlink[v] = min(lowlink[v], lowlink.get(w, lowlink[v]))
            elif on_stack.get(w):
                lowlink[v] = min(lowlink[v], index[w])
        if lowlink[v] == index[v]:
            scc = []
            while True:
                w = stack.pop(); on_stack[w] = False; scc.append(w)
                if w == v: break
            if len(scc) > 1:
                sccs.append(scc)

    for v in list(graph):
        if v not in index:
            visit(v)
    return sccs


# ─── REPORT ───────────────────────────────────────────────────────────────────
class Report:
    def __init__(self):
        self.errors = []; self.warnings = []; self.infos = []

    def error(self, check, pb, detail, extra=None):
        self.errors.append({"level":"ERROR","check":check,
                            "playbook":pb,"detail":detail,"extra":extra})

    def warn(self, check, pb, detail, extra=None):
        self.warnings.append({"level":"WARN","check":check,
                              "playbook":pb,"detail":detail,"extra":extra})

    def info(self, check, pb, detail):
        self.infos.append({"level":"INFO","check":check,
                           "playbook":pb,"detail":detail})

    def print_summary(self, verbose=False):
        items = self.errors + self.warnings + (self.infos if verbose else [])
        by_check = defaultdict(list)
        for i in items: by_check[i["check"]].append(i)

        for check in ["INTEGRATION_REFS","ORPHANED_PLAYBOOKS",
                      "MISSING_LISTS","SUB_PLAYBOOK_CHAIN","CYCLE_DETECTION"]:
            bucket = by_check.get(check, [])
            if not bucket:
                print(GREEN(f"  ✓  {check}") + DIM(" — no issues")); continue
            has_err = any(i["level"] == "ERROR" for i in bucket)
            has_warn= any(i["level"] == "WARN"  for i in bucket)
            label = (RED("✗  ERROR") if has_err
                     else YELLOW("⚠  WARN") if has_warn else CYAN("ℹ  INFO"))
            print(f"  {label}  {BOLD(check)}")
            for i in bucket:
                col = RED if i["level"]=="ERROR" else \
                    YELLOW if i["level"]=="WARN" else CYAN
                print(f"        {col('●')} {DIM(i['playbook'])}  →  {i['detail']}")

    def to_json(self):
        return json.dumps({
            "summary":{"errors":len(self.errors),"warnings":len(self.warnings)},
            "findings": self.errors + self.warnings + self.infos,
        }, indent=2)


# ─── CHECKS ───────────────────────────────────────────────────────────────────
def check_integration_refs(primary_pbs, configured_brands, report):
    config_lower = {b.lower(): b for b in configured_brands}
    for pb_name, data in primary_pbs.items():
        for brand in extract_brands(data):
            if brand in SHADOW_BRANDS or brand in OPTIONAL_BRANDS:
                continue
            if brand in configured_brands:
                continue
            if brand.lower() in config_lower:
                report.warn("INTEGRATION_REFS", pb_name,
                            f"Brand '{brand}' matched case-insensitively to "
                            f"'{config_lower[brand.lower()]}' — check capitalisation")
            else:
                report.error("INTEGRATION_REFS", pb_name,
                             f"Brand '{brand}' not found in xsoar_config.json",
                             {"brand": brand})


def check_orphaned_playbooks(primary_pbs, all_pbs, pb_pack,
                             primary_label, exported_playbooks, report):
    """
    Orphan classification:
      ENTRY POINT  — EP_ / JOB - prefix, or  entrypoint: true  → skip silently
      EXPORTED     — listed in xsoar_config.json exported_playbooks
                     → INFO only (intentional library export)
      CALLED       — referenced by any playbook in any pack → OK
      ORPHAN       — none of the above → WARN
    """
    called_by = defaultdict(list)
    for caller, data in all_pbs.items():
        for sub in extract_sub_playbooks(data):
            called_by[sub].append(caller)

    for pb_name, data in primary_pbs.items():
        if is_entry_point(pb_name, data):
            continue

        callers = called_by.get(pb_name, [])

        if pb_name in exported_playbooks:
            # Intentional library export — show as INFO so it's visible but
            # not a warning.  If something also calls it, that's fine too.
            cross = [c for c in callers
                     if pb_pack.get(c, primary_label) != primary_label]
            if cross:
                report.info("ORPHANED_PLAYBOOKS", pb_name,
                            f"Exported library playbook — called cross-pack from: "
                            + ", ".join(cross[:3])
                            + ("…" if len(cross) > 3 else ""))
            else:
                report.info("ORPHANED_PLAYBOOKS", pb_name,
                            "Exported library playbook — available to dependent packs")
            continue

        if not callers:
            report.warn("ORPHANED_PLAYBOOKS", pb_name,
                        "Not referenced by any playbook in any pack, "
                        "not an entry point, and not in exported_playbooks")
        else:
            cross = [c for c in callers
                     if pb_pack.get(c, primary_label) != primary_label]
            if cross:
                report.info("ORPHANED_PLAYBOOKS", pb_name,
                            "Called cross-pack from: "
                            + ", ".join(cross[:3])
                            + ("…" if len(cross) > 3 else ""))


def check_missing_lists(primary_pbs, configured_lists, report):
    if not configured_lists:
        report.info("MISSING_LISTS", "(global)",
                    "No lists in xsoar_config.json — skipping list validation")
        return
    for pb_name, data in primary_pbs.items():
        for list_name in extract_list_refs(data):
            if list_name not in configured_lists:
                report.error("MISSING_LISTS", pb_name,
                             f"List '{list_name}' not defined in xsoar_config.json",
                             {"list": list_name})


def check_sub_playbook_chains(primary_pbs, all_pbs, pb_pack,
                              primary_label, report):
    all_names = set(all_pbs.keys())
    graph = {}

    for pb_name, data in primary_pbs.items():
        subs = extract_sub_playbooks(data)
        graph[pb_name] = subs
        for sub in subs:
            if sub not in all_names:
                report.error("SUB_PLAYBOOK_CHAIN", pb_name,
                             f"Calls '{sub}' — not found in any pack",
                             {"missing_sub": sub})
            else:
                sub_pack = pb_pack.get(sub, primary_label)
                if sub_pack != primary_label:
                    report.info("SUB_PLAYBOOK_CHAIN", pb_name,
                                f"'{sub}' resolved from pack '{sub_pack}' ✓")
            if sub not in graph:
                graph[sub] = set()

    for pb_name, data in all_pbs.items():
        if pb_name not in graph:
            graph[pb_name] = extract_sub_playbooks(data)

    for cycle in find_cycles(graph):
        cycle_str = " → ".join(cycle) + f" → {cycle[0]}"
        anchor = next((n for n in cycle if n in primary_pbs), cycle[0])
        report.error("CYCLE_DETECTION", anchor,
                     f"Circular dependency: {cycle_str}", {"cycle": cycle})


# ─── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="XSIAM SOC Framework — Playbook Integrity Validator",
    )
    parser.add_argument("--root", default=".",
                        help="Primary pack root (checks run against this pack)")
    parser.add_argument("--packs", nargs="*", default=[], metavar="PATH",
                        help="Extra pack dirs (supplements auto-discovered deps)")
    parser.add_argument("--no-auto", action="store_true",
                        help="Disable auto-discovery of deps from custom_packs")
    parser.add_argument("--config", default=None,
                        help="xsoar_config.json path "
                             "(default: <root>/xsoar_config.json)")
    parser.add_argument("--strict",  action="store_true",
                        help="Treat warnings as errors")
    parser.add_argument("--json",    action="store_true",
                        help="Machine-readable JSON output")
    parser.add_argument("--verbose", action="store_true",
                        help="Show INFO-level findings")
    args = parser.parse_args()

    root          = Path(args.root).resolve()
    config_path   = Path(args.config).resolve() if args.config \
        else root / "xsoar_config.json"
    primary_label = root.name

    # ── Header ───────────────────────────────────────────────────────────────
    if not args.json:
        print()
        print(BOLD("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
        print(BOLD("  XSIAM SOC Framework — Playbook Integrity Validator"))
        print(BOLD("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
        print(f"  Primary pack : {CYAN(str(root))}")
        print(f"  Config       : {CYAN(str(config_path))}")
        print()

    # ── Load config (needed before pack loading for dep resolution) ───────────
    configured_brands, configured_lists, auto_dep_paths, exported_playbooks = \
        parse_xsoar_config(config_path)

    # ── Resolve dependency packs ──────────────────────────────────────────────
    # Priority: auto-discovered from custom_packs  +  explicit --packs flags
    dep_paths = []
    if not args.no_auto:
        dep_paths.extend(auto_dep_paths)

    for extra in (args.packs or []):
        p = Path(extra).resolve()
        if p not in dep_paths:
            dep_paths.append(p)

    # ── Load primary pack ─────────────────────────────────────────────────────
    all_pbs  = {}   # name → data  (ALL packs)
    pb_pack  = {}   # name → pack label

    primary_added, _ = load_pack(root, all_pbs, pb_pack,
                                 primary_label, primary=True)
    if not args.json:
        print(f"  [{BOLD(primary_label)}]  {primary_added} playbooks  "
              f"{DIM('(primary)')}")

    # ── Load dependency packs ─────────────────────────────────────────────────
    for dep_root in dep_paths:
        dep_label = dep_root.name
        added, skipped = load_pack(dep_root, all_pbs, pb_pack,
                                   dep_label, primary=False)
        if not args.json:
            skip_str = f"  ({skipped} name collision(s) skipped)" if skipped else ""
            src = DIM("auto") if dep_root in auto_dep_paths else DIM("--packs")
            print(f"  [{BOLD(dep_label)}]  {added} playbooks  {src}{skip_str}")

    primary_pbs = {n: d for n, d in all_pbs.items()
                   if pb_pack.get(n) == primary_label}

    if not args.json:
        extra_count = len(all_pbs) - len(primary_pbs)
        cross = f"  (+{extra_count} from dependency packs)" if extra_count else ""
        print(f"\n  Total in scope : {BOLD(str(len(all_pbs)))}{cross}")

        # Show config summary
        print()
        status = GREEN("loaded") if config_path.exists() else RED("NOT FOUND")
        print(f"  xsoar_config.json : {status}")
        if config_path.exists():
            print(f"  Brands       : {len(configured_brands)}"
                  f"  |  Lists : {len(configured_lists)}"
                  f"  |  Deps  : {len(dep_paths)}"
                  f"  |  Exported playbooks : {len(exported_playbooks)}")
        if exported_playbooks:
            for ep in sorted(exported_playbooks):
                print(f"    {DIM('export')} {ep}")
        print()
        print(BOLD("  Running checks…\n"))

    # ── Run checks ────────────────────────────────────────────────────────────
    report = Report()
    check_integration_refs(primary_pbs, configured_brands, report)
    check_orphaned_playbooks(primary_pbs, all_pbs, pb_pack,
                             primary_label, exported_playbooks, report)
    check_missing_lists(primary_pbs, configured_lists, report)
    check_sub_playbook_chains(primary_pbs, all_pbs, pb_pack,
                              primary_label, report)

    # ── Output ────────────────────────────────────────────────────────────────
    if args.json:
        print(report.to_json())
    else:
        report.print_summary(verbose=args.verbose)
        print()
        e, w = len(report.errors), len(report.warnings)
        if e == 0 and w == 0:
            print(GREEN("  ✓  All checks passed — playbooks look healthy!"))
        else:
            print(f"  {RED(str(e))} error(s)  |  {YELLOW(str(w))} warning(s)")
        print()
        print(BOLD("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))

    if report.errors:
        sys.exit(1)
    if args.strict and report.warnings:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
