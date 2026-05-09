"""
SOCNormalizeFromList
====================
Data-driven SOC Framework normalizer. Reads SOCFrameworkNormalizeMap_V3 and
applies the per-category contract — mappings, stamps, mirrors — replacing the
~70 hardcoded SetAndHandleEmpty tasks in each Foundation_-_Normalize_<Cat>_V3
playbook.

PHASES (run in order):
  1. mappings — issue.<source> → SOCFramework.<target>  (skip empty sources)
  2. stamps   — literal_value → SOCFramework.<target>   (always write,
                 even empty strings — these are explicit initializers)
                 Branched stamps (multiple values for one target) require the
                 normalization_source arg to disambiguate.
  3. mirrors  — SOCFramework.<source> → SOCFramework.<target>  (reads from
                 in-script accumulator so values written in phase 1 are
                 visible)

ARGS
  category              required — endpoint | email | identity (or future)
  list_name             optional — defaults to SOCFrameworkNormalizeMap_V3
  normalization_source  optional — used to filter branched stamps
                                   (e.g. 'email' vs 'mail_listener')

OUTPUTS
  SOCFramework.<target> writes per the list contract
  SOCFramework.NormalizeFromList — execution summary (counts)

CONTRACT VS BEHAVIOR
  This script reads the list as ground truth. To change normalization behavior,
  edit schemas/soc-framework/soc-optimization-unified/SOCFrameworkNormalizeMap_V3.yaml
  and regenerate the list — never edit the script for per-field changes.
"""

CONSTANT_PACK_VERSION = '3.7.24'
demisto.debug(f'pack id = soc-optimization-unified, pack version = {CONSTANT_PACK_VERSION}')

import json
import re
from collections import defaultdict


# ---------------------------------------------------------------------------
# Source-expression parsing
# ---------------------------------------------------------------------------

_INDEX_RE = re.compile(r'^(.+?)\.\[(\d+)\]$')


def read_source(custom_fields, expr):
    """
    Resolve an issue_field expression against a flat custom-fields dict.

    Supports two forms (matching the playbook YAML it replaces):
      - 'fieldname'          → custom_fields['fieldname']
      - 'fieldname.[N]'      → custom_fields['fieldname'][N] (XSOAR DT array index)

    Returns None if the field is missing or the index is out of range.
    """
    m = _INDEX_RE.match(expr)
    if m:
        name, idx = m.group(1), int(m.group(2))
        val = custom_fields.get(name)
        if isinstance(val, list) and 0 <= idx < len(val):
            return val[idx]
        return None
    return custom_fields.get(expr)


def is_empty(val):
    """Match SetAndHandleEmpty semantics — skip writes for these values."""
    return val is None or val == "" or val == [] or val == {}


# ---------------------------------------------------------------------------
# List loading
# ---------------------------------------------------------------------------

def load_list_section(list_name, category):
    """Load SOCFrameworkNormalizeMap_V3 and return a per-category section.

    Supports two list shapes — same script works against either:

      v1 (legacy nested):
          {"endpoint": {"mappings": [...], "stamps": [...], "mirrors": [...]},
           "email":    {...}, ...}

      v2 (flat with role tags — current shape post-refactor):
          {"roles": {...}, "source_origins": {...},
           "categories": {"endpoint": {...}, "email": {...}, ...},
           "mappings":   [{"category": "endpoint", ...}, ...],
           "stamps":     [{"category": "endpoint", ...}, ...],
           "mirrors":    [{"category": "email",    ...}, ...]}

    Returns a dict shaped {"mappings": [...], "stamps": [...], "mirrors": [...]}
    containing only rows for the requested category. The downstream apply_*
    functions consume that shape unchanged.
    """
    res = demisto.executeCommand("getList", {"listName": list_name})
    if not res:
        raise ValueError(f"getList returned no result for {list_name}")

    contents = res[0].get("Contents")
    if not contents:
        raise ValueError(f"List {list_name} has no contents")

    # XSIAM/XSOAR may return either a string (JSON) or a parsed dict
    if isinstance(contents, str):
        # Surface the typical "Item not found" sentinel rather than parsing junk
        if "not found" in contents.lower():
            raise ValueError(f"List {list_name} not found on tenant")
        try:
            data = json.loads(contents)
        except json.JSONDecodeError as e:
            raise ValueError(f"List {list_name} is not valid JSON: {e}")
    else:
        data = contents

    cat_lc = category.lower()

    # ── v2 (flat) detection: top-level mappings/stamps/mirrors are arrays ──
    if (isinstance(data.get("mappings"), list)
            and isinstance(data.get("stamps"), list)
            and isinstance(data.get("mirrors"), list)):
        # Validate against the categories block when present so a typo'd
        # category arg gets a useful error instead of silently filtering to []
        categories_block = data.get("categories")
        if isinstance(categories_block, dict) and categories_block:
            known = {k.lower() for k in categories_block.keys()}
            if cat_lc not in known:
                available = sorted(categories_block.keys())
                raise ValueError(
                    f"category {category!r} not in {list_name}; available: {available}"
                )
        elif isinstance(categories_block, list) and categories_block:
            known = {str(k).lower() for k in categories_block}
            if cat_lc not in known:
                available = sorted(categories_block)
                raise ValueError(
                    f"category {category!r} not in {list_name}; available: {available}"
                )

        return {
            "mappings": [r for r in data["mappings"]
                         if (r.get("category") or "").lower() == cat_lc],
            "stamps":   [r for r in data["stamps"]
                         if (r.get("category") or "").lower() == cat_lc],
            "mirrors":  [r for r in data["mirrors"]
                         if (r.get("category") or "").lower() == cat_lc],
        }

    # ── v1 (legacy nested): data[category] is the section dict ──
    if category not in data:
        # Filter to dict-valued keys to surface only real category sections,
        # not metadata like 'id' / 'name'
        available = sorted(k for k, v in data.items() if isinstance(v, dict))
        raise ValueError(f"category {category!r} not in {list_name}; available: {available}")

    return data[category]


# ---------------------------------------------------------------------------
# Phase application — pure functions for testability
# ---------------------------------------------------------------------------

def apply_mappings(section, custom_fields, writes, skipped):
    for m in section.get("mappings", []) or []:
        target, source = m["target"], m["issue_field"]
        val = read_source(custom_fields, source)
        if is_empty(val):
            skipped["empty"].append({"target": target, "source": source})
            continue
        writes[target] = val


def apply_stamps(section, normalization_source, writes, skipped):
    """
    Stamps always write (even empty strings — explicit initializers).
    Branched stamps (>1 value for same target) require normalization_source
    to disambiguate; skip silently if no filter provided to avoid arbitrary
    choice.
    """
    grouped = defaultdict(list)
    for s in section.get("stamps", []) or []:
        grouped[s["target"]].append(s["value"])

    for target, values in grouped.items():
        if len(values) == 1:
            writes[target] = values[0]
            continue
        # Branched
        if normalization_source and normalization_source in values:
            writes[target] = normalization_source
        else:
            skipped["filtered"].append({
                "target": target,
                "reason": f"branched stamp requires normalization_source arg in {values}",
            })


def apply_mirrors(section, writes, skipped):
    """Mirrors run AFTER mappings + stamps so they can copy what was just written."""
    for mi in section.get("mirrors", []) or []:
        src, target = mi["source"], mi["target"]
        val = writes.get(src)
        if is_empty(val):
            skipped["empty"].append({"target": target, "source": f"SOCFramework.{src} (mirror)"})
            continue
        writes[target] = val


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    args = demisto.args() or {}
    category = (args.get("category") or "").strip()
    if not category:
        return_error("SOCNormalizeFromList: 'category' arg is required")

    list_name = (args.get("list_name") or "SOCFrameworkNormalizeMap_V3").strip()
    normalization_source = (args.get("normalization_source") or "").strip() or None

    demisto.debug(f"SOCNormalizeFromList: category={category} list={list_name} "
                  f"normalization_source={normalization_source}")

    try:
        section = load_list_section(list_name, category)
    except ValueError as e:
        return_error(f"SOCNormalizeFromList: {e}")
        return

    incident = demisto.incident() or {}
    custom_fields = incident.get("CustomFields") or {}

    writes = {}
    skipped = {"empty": [], "filtered": []}

    apply_mappings(section, custom_fields, writes, skipped)
    apply_stamps(section, normalization_source, writes, skipped)
    apply_mirrors(section, writes, skipped)

    # Atomic apply — setContext per key (in-process; persisted on script return)
    for target, value in writes.items():
        demisto.setContext(f"SOCFramework.{target}", value)

    summary = {
        "category": category,
        "list_name": list_name,
        "normalization_source": normalization_source,
        "writes_applied": len(writes),
        "skipped_empty_count": len(skipped["empty"]),
        "skipped_filtered_count": len(skipped["filtered"]),
        "skipped_empty": skipped["empty"],
        "skipped_filtered": skipped["filtered"],
    }

    readable = (
        f"### SOCNormalizeFromList — {category}\n"
        f"- writes applied: **{len(writes)}**\n"
        f"- skipped (empty source): {len(skipped['empty'])}\n"
        f"- skipped (filtered/branched): {len(skipped['filtered'])}\n"
        f"- list: `{list_name}`"
    )

    return_results(CommandResults(
        readable_output=readable,
        outputs_prefix="SOCFramework.NormalizeFromList",
        outputs=summary,
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
