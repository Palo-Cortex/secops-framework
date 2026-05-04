"""
SOCInitializePhaseContext
=========================
NIST IR phase initializer. Reads SOCFrameworkPhaseContract_V3 and writes
empty/typed initial values for every key the given phase will produce —
top-level orchestrator writes plus per-category writes for the category
identified in SOCFramework.Product.category.

Pre-initializing the contract surface gives the next phase a stable,
predictable read shape: every declared key exists with its init value
(empty string, 0, false, [], {}) before sub-playbooks start populating.
A test harness can then distinguish "key absent" (orchestrator failure)
from "key present at init value" (sub-playbook didn't populate).

ARGS
  phase  required  analysis | containment | eradication | recovery

READS (from incident context)
  SOCFramework.Product.category — drives which writes_by_category rows
                                  get initialized

OUTPUTS
  Initialized SOCFramework.* targets per the contract
  SOCFramework.NISTIRInit — execution summary

SAFETY
  Never overwrites an existing non-empty value. If a key already has data
  (from a prior run, a re-execution, or the orchestrator was re-entered),
  init leaves it alone. Only absent or empty keys get the init value.
"""

CONSTANT_PACK_VERSION = '1.0.0'
demisto.debug(f'pack id = soc-framework-nist-ir, pack version = {CONSTANT_PACK_VERSION}')

import json


LIST_NAME = "SOCFrameworkPhaseContract_V3"


# ---------------------------------------------------------------------------
# List loading
# ---------------------------------------------------------------------------

def load_phase_section(phase):
    """Load the contract list and return (writes_for_phase, writes_by_category_for_phase)."""
    res = demisto.executeCommand("getList", {"listName": LIST_NAME})
    if not res:
        raise ValueError(f"getList returned no result for {LIST_NAME}")

    contents = res[0].get("Contents")
    if not contents:
        raise ValueError(f"List {LIST_NAME} has no contents")

    if isinstance(contents, str):
        if "not found" in contents.lower():
            raise ValueError(f"List {LIST_NAME} not found on tenant")
        try:
            data = json.loads(contents)
        except json.JSONDecodeError as e:
            raise ValueError(f"List {LIST_NAME} is not valid JSON: {e}")
    else:
        data = contents

    writes_by_phase = data.get("writes_by_phase", {}) or {}
    writes_by_cat   = data.get("writes_by_category_by_phase", {}) or {}

    if phase not in writes_by_phase:
        available = sorted(writes_by_phase.keys())
        raise ValueError(f"phase {phase!r} not in {LIST_NAME}.writes_by_phase; available: {available}")

    return writes_by_phase[phase], writes_by_cat.get(phase, [])


# ---------------------------------------------------------------------------
# Init application
# ---------------------------------------------------------------------------

def is_empty(val):
    """Match SetAndHandleEmpty semantics — these values count as 'no data'."""
    return val is None or val == "" or val == [] or val == {}


# ---------------------------------------------------------------------------
# Type / init inference (defensive — only used when list row is missing them)
# ---------------------------------------------------------------------------
# A list emitted before the schema's type/init fields existed will have rows
# with neither field populated. Rather than writing None for every key, infer
# a sensible default from the target's leaf name. Schema-declared values
# always take precedence; this only fills the gap.

_TYPE_DEFAULTS = {
    "string":  "",
    "number":  0,
    "boolean": False,
    "array":   [],
    "object":  {},
}

_BOOLEAN_LEAVES = {
    "required", "attempted", "success", "ioc_enriched", "monitoring_required",
    "restore_required", "escalate_to_reimage", "reimage_required",
    "account_restored",
}

_ARRAY_LEAVES = {
    "story", "isolated_hosts", "disabled_users", "files_removed",
    "persistence_removed", "credentials_reset", "tokens_revoked",
    "added_hashes", "final", "quarantinedfilesfromendpoints",
    "source_verdict",
}


def infer_type(target):
    """Pick a reasonable type when the schema row didn't supply one."""
    tail = target.split(".")[-1].lower()
    if tail.endswith("_recommended") or tail.endswith("_required") or tail in _BOOLEAN_LEAVES:
        return "boolean"
    if tail.endswith("_count") or tail.endswith("_score") or tail == "global_hash_prevalence_count":
        return "number"
    if tail in _ARRAY_LEAVES:
        return "array"
    if tail == "execution":
        return "object"
    return "string"


def resolve_init(row):
    """Return (effective_type, effective_init) honoring explicit row values
    and falling back to type-based defaults."""
    target = row.get("target", "")
    declared_type = row.get("type")
    declared_init = row.get("init")

    eff_type = declared_type if declared_type else infer_type(target)
    if "init" in row and declared_init is not None:
        return eff_type, declared_init
    return eff_type, _TYPE_DEFAULTS.get(eff_type, "")


def get_existing(target):
    """Return the current value at SOCFramework.* dotted path or None if absent.

    Uses demisto.dt to walk the context. Empty / missing both return None.
    """
    val = demisto.dt(demisto.context(), target)
    return val


def collect_init_rows(writes, writes_by_cat, routed_category):
    """
    Build the de-duplicated list of (target, type, init) rows to apply.

    - All top-level writes for the phase
    - writes_by_category rows where category matches the routed category
    - Dedup by target (writes wins if duplicate, since it's the orchestrator
      contract and authoritative)
    """
    seen = set()
    rows = []
    for w in writes:
        if w["target"] in seen:
            continue
        seen.add(w["target"])
        rows.append(w)

    if routed_category:
        for w in writes_by_cat:
            if w.get("category") != routed_category:
                continue
            if w["target"] in seen:
                continue
            seen.add(w["target"])
            rows.append(w)

    return rows


def apply_inits(rows):
    """For each row: if target is empty/absent, set it to init value. Skip otherwise.

    Uses resolve_init() to default missing type/init fields — defensive against
    older list payloads that don't yet carry these fields.
    """
    initialized = []
    skipped_existing = []
    for r in rows:
        target = r["target"]
        eff_type, init_val = resolve_init(r)
        existing = get_existing(target)
        if not is_empty(existing):
            skipped_existing.append({"target": target, "existing_value_type": type(existing).__name__})
            continue
        demisto.setContext(target, init_val)
        initialized.append({"target": target, "type": eff_type, "init": init_val})
    return initialized, skipped_existing


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    args = demisto.args() or {}
    phase = (args.get("phase") or "").strip().lower()
    if not phase:
        return_error("SOCInitializePhaseContext: 'phase' arg is required")
        return

    # Routed category from incident context
    routed_category = demisto.dt(demisto.context(), "SOCFramework.Product.category")
    if isinstance(routed_category, str):
        routed_category = routed_category.lower()
    else:
        routed_category = None

    demisto.debug(f"SOCInitializePhaseContext: phase={phase} routed_category={routed_category}")

    try:
        writes, writes_by_cat = load_phase_section(phase)
    except ValueError as e:
        return_error(f"SOCInitializePhaseContext: {e}")
        return

    rows = collect_init_rows(writes, writes_by_cat, routed_category)
    initialized, skipped_existing = apply_inits(rows)

    readable = (
        f"### SOCInitializePhaseContext — {phase}\n"
        f"- routed category: **{routed_category or '(none)'}**\n"
        f"- contract rows considered: **{len(rows)}**\n"
        f"- initialized (was empty/absent): **{len(initialized)}**\n"
        f"- skipped (already populated): **{len(skipped_existing)}**\n"
        f"- list: `{LIST_NAME}`"
    )

    # Warroom note only — no outputs persisted to context. The init script
    # is plumbing, not a data producer. Detailed run info stays in the
    # warroom for debug; nothing survives into case context to clutter
    # downstream readers.
    return_results(CommandResults(readable_output=readable))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
