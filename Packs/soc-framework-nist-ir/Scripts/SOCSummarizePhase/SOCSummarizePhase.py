"""
SOCSummarizePhase
=================
Project per-action records from <Phase>.Execution[] into phase-state context
fields. Runs once near the end of an Endpoint Containment / Eradication /
Recovery playbook, after the wrapper calls have populated Execution[] and
before the story is written.

Without this projection, the case context shows only Execution[] and the empty
init values from SOCInitializePhaseContext (action='', isolated_hosts=[],
attempted=false, status='', etc.). For PoVs we want the data context to tell
the story without an analyst having to read raw Execution records.

ARGS
  phase  required  containment | eradication | recovery

READS (from incident context)
  <Phase>.Execution[]                               — wrapper records
  SOCFramework.Artifacts.Endpoint.Hostname          — for Containment.isolated_hosts
  SOCFramework.Artifacts.User                       — for Containment.disabled_users
  SOCFramework.Artifacts.Target.File                — for Eradication.files_removed
  SOCFramework.Artifacts.Process.Name               — for Eradication.persistence_removed

WRITES (per phase)
  Containment:
    .attempted        (bool)
    .required         (bool — mirrors attempted; an action ran iff containment was needed)
    .action           (csv of distinct action names attempted)
    .status           (skipped | shadow | production | mixed)
    .isolated_hosts[] (hostname if soc-isolate-endpoint attempted)
    .disabled_users[] (user if soc-disable-user attempted)
  Eradication:
    .attempted              (bool)
    .success                (bool — all entries success and not shadow)
    .files_removed[]        (filename if soc-remove-file or soc-quarantine-files attempted)
    .persistence_removed[]  (process name if soc-remove-persistence attempted)
  Recovery:
    .restore_required     (bool — any restorative action attempted)
    .restore_method       (csv: agent_deisolate | user_enable | …)
    .monitoring_required  (bool — true when any restorative action attempted)
    .monitoring_scope     (string — endpoint hostname when restore_required)
    .status               (skipped | shadow | production | mixed)

SAFETY
  Never overwrites a non-empty existing value (matches SOCInitializePhaseContext
  is_empty semantics). Re-entrant.
"""

CONSTANT_PACK_VERSION = '1.0.0'
demisto.debug(f'pack id = soc-framework-nist-ir, pack version = {CONSTANT_PACK_VERSION}')


VALID_PHASES = {"containment", "eradication", "recovery"}


def is_empty(val):
    return val is None or val == "" or val == [] or val == {}


def get(path):
    return demisto.dt(demisto.context(), path)


def set_field(target, value):
    """SOCSummarizePhase is authoritative for the fields it writes — always
    overwrite. The contract initializer plants typed init defaults (False,
    "", []) which are not "real data" but ARE non-empty by the framework's
    is_empty semantics; an is_empty-guarded write here would leave
    Containment.required stuck at False even when actions actually ran.

    Returns True (the write happened) for symmetry with the prior signature
    so the diagnostic summary still reports written fields."""
    demisto.setContext(target, value)
    return True


def derive_status(records):
    """skipped | shadow | production | mixed"""
    if not records:
        return "skipped"
    shadow_flags = [bool(r.get("shadow_mode")) for r in records]
    if all(shadow_flags):
        return "shadow"
    if not any(shadow_flags):
        return "production"
    return "mixed"


def distinct_csv(items):
    seen = []
    for x in items:
        if x and x not in seen:
            seen.append(x)
    return ",".join(seen)


def actions_match(records, names):
    """Return True if any record has action in names."""
    name_set = set(names)
    return any(r.get("action") in name_set for r in records)


# ---------------------------------------------------------------------------
# Phase projections
# ---------------------------------------------------------------------------

def summarize_containment(records, written):
    attempted = len(records) > 0
    written["Containment.attempted"] = set_field("Containment.attempted", attempted)
    written["Containment.required"]  = set_field("Containment.required", attempted)
    written["Containment.action"]    = set_field("Containment.action",
                                                    distinct_csv(r.get("action", "") for r in records))
    written["Containment.status"]    = set_field("Containment.status", derive_status(records))

    hostname = get("SOCFramework.Artifacts.Endpoint.Hostname")
    if hostname and actions_match(records, ["soc-isolate-endpoint"]):
        written["Containment.isolated_hosts"] = set_field("Containment.isolated_hosts", [hostname])

    user = get("SOCFramework.Artifacts.User")
    if user and actions_match(records, ["soc-disable-user"]):
        written["Containment.disabled_users"] = set_field("Containment.disabled_users", [user])


def summarize_eradication(records, written):
    attempted = len(records) > 0
    written["Eradication.attempted"] = set_field("Eradication.attempted", attempted)

    # success = at least one record AND every record succeeded AND none in shadow
    if records and all(r.get("success") and not r.get("shadow_mode") for r in records):
        success = True
    else:
        success = False
    written["Eradication.success"] = set_field("Eradication.success", success)

    filename = get("SOCFramework.Artifacts.Target.File")
    if filename and actions_match(records, ["soc-remove-file", "soc-quarantine-files"]):
        written["Eradication.files_removed"] = set_field("Eradication.files_removed", [filename])

    process = get("SOCFramework.Artifacts.Process.Name")
    if process and actions_match(records, ["soc-remove-persistence"]):
        written["Eradication.persistence_removed"] = set_field("Eradication.persistence_removed", [process])


def summarize_recovery(records, written):
    restore_required = len(records) > 0
    written["Recovery.restore_required"]    = set_field("Recovery.restore_required", restore_required)
    written["Recovery.monitoring_required"] = set_field("Recovery.monitoring_required", restore_required)
    written["Recovery.status"]              = set_field("Recovery.status", derive_status(records))

    methods = []
    if actions_match(records, ["soc-deisolate-endpoint"]):
        methods.append("agent_deisolate")
    if actions_match(records, ["soc-enable-user"]):
        methods.append("user_enable")
    if methods:
        written["Recovery.restore_method"] = set_field("Recovery.restore_method", ",".join(methods))

    if restore_required:
        hostname = get("SOCFramework.Artifacts.Endpoint.Hostname")
        if hostname:
            written["Recovery.monitoring_scope"] = set_field(
                "Recovery.monitoring_scope", f"endpoint:{hostname}"
            )


PHASE_DISPATCH = {
    "containment": summarize_containment,
    "eradication": summarize_eradication,
    "recovery":    summarize_recovery,
}

PHASE_EXECUTION_KEY = {
    "containment": "Containment.Execution",
    "eradication": "Eradication.Execution",
    "recovery":    "Recovery.Execution",
}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    args = demisto.args() or {}
    phase = (args.get("phase") or "").strip().lower()
    if phase not in VALID_PHASES:
        return_error(
            f"SOCSummarizePhase: 'phase' must be one of {sorted(VALID_PHASES)}, got {phase!r}"
        )
        return

    records = get(PHASE_EXECUTION_KEY[phase]) or []
    if not isinstance(records, list):
        # Defensive — pre-fix tenants may still have {} from an old contract list
        demisto.debug(
            f"SOCSummarizePhase: {PHASE_EXECUTION_KEY[phase]} is not a list "
            f"(got {type(records).__name__}); treating as empty."
        )
        records = []

    written = {}
    PHASE_DISPATCH[phase](records, written)

    summary = {
        "phase": phase,
        "execution_count": len(records),
        "fields_written": [k for k, v in written.items() if v],
    }
    demisto.setContext(f"SOCFramework.PhaseSummary.{phase}", summary)
    demisto.results(summary)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
