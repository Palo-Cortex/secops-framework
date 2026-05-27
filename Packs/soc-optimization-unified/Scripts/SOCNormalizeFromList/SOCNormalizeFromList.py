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
  category              required — product category within the lifecycle's contract
                                   (endpoint | email | identity | network | cloud |
                                   generic | posture_* | future). Empty or unknown
                                   falls back to the 'generic' section. Case-insensitive.
  lifecycle             optional — lifecycle token (default 'nist_ir'). Selects WHICH
                                   contract list to read, by naming convention:
                                       SOCFrameworkNormalizeMap_<LIFECYCLE.upper()>
                                   e.g. nist_ir -> SOCFrameworkNormalizeMap_NIST_IR.
                                   This is the plug-and-play hook: a new lifecycle ships
                                   its own list under that name in its own pack, and this
                                   script finds it with no change to the engine.
  list_name             optional — explicit override of the resolved list name.
  normalization_source  optional — used to filter branched stamps
                                   (e.g. 'email' vs 'mail_listener')

LIST SHAPE (per-lifecycle — current)
  { lifecycle: <name>, categories: { <cat>: {mappings:[...], stamps:[...], mirrors:[...]} } }
  Legacy flat (v2) and nested (v1) shapes are still read for transition safety.

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

    def _bands(section):
        """Return only the apply_* bands from a category section."""
        return {b: (section.get(b) or []) for b in ("mappings", "stamps", "mirrors")}

    # ── per-lifecycle (current): categories[<cat>] is a dict holding the bands ──
    cats = data.get("categories")
    if isinstance(cats, dict) and cats and all(isinstance(v, dict) for v in cats.values()) \
            and any(("mappings" in v or "stamps" in v or "mirrors" in v) for v in cats.values()):
        known = {k.lower(): k for k in cats.keys()}
        fellback = False
        if cat_lc not in known:
            if "generic" in known:
                demisto.debug(f"SOCNormalizeFromList: no '{category}' section in {list_name}; "
                              f"falling back to 'generic'.")
                cat_lc = "generic"
                fellback = True
            else:
                raise ValueError(
                    f"category {category!r} not in {list_name} and no 'generic' fallback; "
                    f"available: {sorted(cats.keys())}"
                )
        return _bands(cats[known[cat_lc]]), cat_lc, fellback

    # ── v2 (legacy flat): top-level mappings/stamps/mirrors arrays, category-tagged ──
    if (isinstance(data.get("mappings"), list)
            and isinstance(data.get("stamps"), list)
            and isinstance(data.get("mirrors"), list)):
        categories_block = data.get("categories")
        known = set()
        if isinstance(categories_block, dict):
            known = {k.lower() for k in categories_block.keys()}
        elif isinstance(categories_block, list):
            known = {str(k).lower() for k in categories_block}
        fellback = False
        if known and cat_lc not in known:
            if "generic" in known:
                demisto.debug(f"SOCNormalizeFromList: no '{category}' in {list_name}; "
                              f"falling back to 'generic'.")
                cat_lc = "generic"
                fellback = True
            else:
                raise ValueError(
                    f"category {category!r} not in {list_name}; available: {sorted(known)}"
                )
        section = {
            "mappings": [r for r in data["mappings"] if (r.get("category") or "").lower() == cat_lc],
            "stamps":   [r for r in data["stamps"]   if (r.get("category") or "").lower() == cat_lc],
            "mirrors":  [r for r in data["mirrors"]  if (r.get("category") or "").lower() == cat_lc],
        }
        return section, cat_lc, fellback

    # ── v1 (legacy nested): data[category] is the section dict ──
    fellback = False
    if category not in data:
        if isinstance(data.get("generic"), dict):
            demisto.debug(f"SOCNormalizeFromList: no '{category}' in {list_name}; falling back to 'generic'.")
            category = "generic"
            fellback = True
        else:
            available = sorted(k for k, v in data.items() if isinstance(v, dict))
            raise ValueError(f"category {category!r} not in {list_name}; available: {available}")
    return _bands(data[category]), category, fellback


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
        demisto.debug("SOCNormalizeFromList: empty 'category'; defaulting to 'generic'")
        category = "generic"

    lifecycle = (args.get("lifecycle") or "nist_ir").strip() or "nist_ir"
    # Resolve the contract list by lifecycle naming convention unless explicitly overridden.
    list_name = (args.get("list_name") or "").strip() \
        or f"SOCFrameworkNormalizeMap_{lifecycle.upper()}"
    normalization_source = (args.get("normalization_source") or "").strip() or None

    demisto.debug(f"SOCNormalizeFromList: lifecycle={lifecycle} category={category} "
                  f"list={list_name} normalization_source={normalization_source}")

    try:
        section, effective_category, fellback = load_list_section(list_name, category)
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

    # Dedup field projection — Foundation - Dedup consumes these via inputs (the
    # consumer stays dumb: it just uses what this pass already resolved). Identity
    # rows are tagged dedup_key: true with a dedup_match hint (text|json) selecting
    # the DBotFindSimilarAlerts bucket. This is per (lifecycle, category) by
    # construction, since `section` is the already-resolved category section.
    dedup_text, dedup_json = [], []
    for m in section.get("mappings", []) or []:
        if not m.get("dedup_key"):
            continue
        fld = m.get("issue_field")
        if not fld:
            continue
        # DBotFindSimilarAlerts compares bare alert field names; normalize's
        # array accessors (e.g. 'username.[0]') aren't valid there.
        idx = fld.find(".[")
        if idx >= 0:
            fld = fld[:idx]
        if (m.get("dedup_match") or "text").strip().lower() == "json":
            dedup_json.append(fld)
        else:
            dedup_text.append(fld)
    # Emit context only when the contract carries dedup tags. When untagged,
    # leave context unset so the consumer's playbook input default (list-backed
    # baseline from SOCOptimizationConfig_V3.Dedup.fields) fires — single source
    # of truth for defaults, no Python-side configuration.
    if dedup_text or dedup_json:
        # order-preserving dedupe (schema may have multiple rows touching the
        # same alert field; DBot only needs each field once)
        dedup_text = list(dict.fromkeys(dedup_text))
        dedup_json = list(dict.fromkeys(dedup_json))
        demisto.setContext("SOCFramework.Dedup.SimilarTextField", ",".join(dedup_text))
        demisto.setContext("SOCFramework.Dedup.SimilarJsonField", ",".join(dedup_json))

    summary = {
        "lifecycle": lifecycle,
        "category": category,
        "effective_category": effective_category,
        "fellback_to_generic": fellback,
        "list_name": list_name,
        "normalization_source": normalization_source,
        "writes_applied": len(writes),
        "skipped_empty_count": len(skipped["empty"]),
        "skipped_filtered_count": len(skipped["filtered"]),
        "skipped_empty": skipped["empty"],
        "skipped_filtered": skipped["filtered"],
    }

    fb = "  _(fell back to generic)_" if fellback else ""
    readable = (
        f"### SOCNormalizeFromList — {lifecycle} / {effective_category}{fb}\n"
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
