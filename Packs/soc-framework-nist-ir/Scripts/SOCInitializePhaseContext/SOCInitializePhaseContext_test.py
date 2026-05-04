"""
SOCInitializePhaseContext_test
==============================
Standalone tests for the pure helpers + end-to-end against the real
SOCFrameworkPhaseContract_V3 list payload.

Runs without XSIAM / demisto-sdk by stubbing demisto.* in builtins.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


# Stub demisto + result helpers
class _Demisto:
    def __init__(self):
        self._context = {}
        self._args = {}
        self._set_calls = []
    def debug(self, *a, **kw): pass
    def args(self): return self._args
    def context(self): return self._context
    def setContext(self, key, value):
        self._set_calls.append((key, value))
        # Walk dotted path and set
        parts = key.split(".")
        cur = self._context
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = value
    def dt(self, ctx, path):
        if not path:
            return None
        cur = ctx
        for p in path.split("."):
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return None
        return cur
    def executeCommand(self, *a, **kw):
        return [{"Contents": "{}"}]


demisto = _Demisto()
def return_error(msg): raise RuntimeError(msg)
def return_results(x): pass
class CommandResults:
    def __init__(self, **kw): self.kw = kw

import builtins
builtins.demisto = demisto
builtins.return_error = return_error
builtins.return_results = return_results
builtins.CommandResults = CommandResults

sys.path.insert(0, str(Path(__file__).parent))
from SOCInitializePhaseContext import (
    is_empty, get_existing, collect_init_rows, apply_inits,
)

PASS, FAIL = "✓", "✗"
fails = []

def check(label, got, want):
    ok = got == want
    print(f"  {PASS if ok else FAIL} {label}")
    if not ok:
        fails.append((label, got, want))


# --- is_empty ---
print("is_empty:")
check("None", is_empty(None), True)
check("empty str", is_empty(""), True)
check("empty list", is_empty([]), True)
check("empty dict", is_empty({}), True)
check("zero", is_empty(0), False)
check("False", is_empty(False), False)
check("populated", is_empty("x"), False)


# --- collect_init_rows ---
print("collect_init_rows:")
writes = [
    {"target": "Analysis.verdict",    "type": "string",  "init": ""},
    {"target": "Analysis.confidence", "type": "string",  "init": ""},
]
writes_by_cat = [
    {"category": "endpoint", "target": "Analysis.case_score",      "type": "number",  "init": 0},
    {"category": "endpoint", "target": "Analysis.verdict",         "type": "string",  "init": ""},  # dup target
    {"category": "email",    "target": "Analysis.Email.signal_type", "type": "string", "init": ""},
]
rows = collect_init_rows(writes, writes_by_cat, "endpoint")
targets = [r["target"] for r in rows]
check("includes top-level writes", "Analysis.verdict" in targets, True)
check("includes routed category writes", "Analysis.case_score" in targets, True)
check("excludes non-routed category writes", "Analysis.Email.signal_type" not in targets, True)
check("dedupes target across writes/writes_by_category", targets.count("Analysis.verdict"), 1)

rows_email = collect_init_rows(writes, writes_by_cat, "email")
targets_email = [r["target"] for r in rows_email]
check("email route includes Email-specific keys", "Analysis.Email.signal_type" in targets_email, True)
check("email route excludes endpoint case_score", "Analysis.case_score" not in targets_email, True)

# No category routed
rows_nocat = collect_init_rows(writes, writes_by_cat, None)
check("no category routed → only top-level writes", len(rows_nocat), 2)


# --- apply_inits + safety ---
print("apply_inits (safety: never overwrite populated):")
demisto._context = {}
demisto._set_calls = []
init_rows = [
    {"target": "Analysis.verdict",        "type": "string",  "init": ""},
    {"target": "Analysis.case_score",     "type": "number",  "init": 0},
    {"target": "Analysis.story",          "type": "array",   "init": []},
    {"target": "Analysis.response_recommended", "type": "boolean", "init": False},
]
initialized, skipped = apply_inits(init_rows)
check("all 4 rows initialized when context empty", len(initialized), 4)
check("none skipped", len(skipped), 0)
check("Analysis.verdict set to ''", demisto.dt(demisto._context, "Analysis.verdict"), "")
check("Analysis.case_score set to 0", demisto.dt(demisto._context, "Analysis.case_score"), 0)
check("Analysis.story set to []", demisto.dt(demisto._context, "Analysis.story"), [])
check("Analysis.response_recommended set to False", demisto.dt(demisto._context, "Analysis.response_recommended"), False)

# Re-run — should skip everything (already initialized to non-empty would be the test;
# but init values themselves are 'empty' per is_empty, so they re-init. The real
# safety case is when sub-playbooks have populated values.)
demisto._context = {"Analysis": {"verdict": "malicious", "case_score": 87, "story": ["already populated"]}}
initialized, skipped = apply_inits(init_rows)
check("populated string preserved", len(skipped), 3)  # verdict, case_score, story
check("only response_recommended got initialized", initialized[0]["target"], "Analysis.response_recommended")
check("verdict not overwritten", demisto.dt(demisto._context, "Analysis.verdict"), "malicious")
check("case_score not overwritten", demisto.dt(demisto._context, "Analysis.case_score"), 87)


# --- defensive defaults for legacy/malformed rows ---
print("defensive defaults (rows missing type/init):")
from SOCInitializePhaseContext import resolve_init, infer_type

# Type inference
check("infer_type story → array", infer_type("Analysis.story"), "array")
check("infer_type Containment.story → array", infer_type("Containment.story"), "array")
check("infer_type case_score → number", infer_type("Analysis.case_score"), "number")
check("infer_type response_recommended → boolean", infer_type("Analysis.response_recommended"), "boolean")
check("infer_type verdict → string", infer_type("Analysis.verdict"), "string")
check("infer_type Execution → object", infer_type("Containment.Execution"), "object")
check("infer_type Blocklist.Final → array", infer_type("Blocklist.Final"), "array")

# Resolve init: missing both fields
ty, iv = resolve_init({"target": "Analysis.story"})
check("resolve_init missing both → array []", (ty, iv), ("array", []))

ty, iv = resolve_init({"target": "Analysis.case_score"})
check("resolve_init missing both → number 0", (ty, iv), ("number", 0))

ty, iv = resolve_init({"target": "Containment.story"})
check("resolve_init Containment.story → array []", (ty, iv), ("array", []))

# Resolve init: explicit values override
ty, iv = resolve_init({"target": "X", "type": "string", "init": "hello"})
check("resolve_init explicit values honored", (ty, iv), ("string", "hello"))

# Resolve init: type explicit, init missing
ty, iv = resolve_init({"target": "X", "type": "boolean"})
check("resolve_init type only → default by type", (ty, iv), ("boolean", False))

# Apply with rows lacking type/init (simulates legacy on-tenant list)
print("apply_inits with legacy rows (no type/init fields):")
demisto._context = {}
demisto._set_calls = []
legacy_rows = [
    {"target": "Containment.action"},          # no type/init at all
    {"target": "Containment.story"},
    {"target": "Containment.required"},
    {"target": "Containment.disabled_users"},
]
initialized, _ = apply_inits(legacy_rows)
check("legacy Containment.action → '' not None", demisto.dt(demisto._context, "Containment.action"), "")
check("legacy Containment.story → [] not None", demisto.dt(demisto._context, "Containment.story"), [])
check("legacy Containment.required → False not None", demisto.dt(demisto._context, "Containment.required"), False)
check("legacy Containment.disabled_users → [] not None", demisto.dt(demisto._context, "Containment.disabled_users"), [])


# --- END-TO-END against real SOCFrameworkPhaseContract_V3_data.json ---
print("end-to-end (real list payload):")
LIST_PATH = Path(__file__).parents[2] / "Lists" / "SOCFrameworkPhaseContract_V3" / "SOCFrameworkPhaseContract_V3_data.json"
list_data = json.loads(LIST_PATH.read_text())

# Endpoint-routed analysis init
demisto._context = {"SOCFramework": {"Product": {"category": "Endpoint"}}}
phase_writes = list_data["writes_by_phase"]["analysis"]
phase_cat    = list_data["writes_by_category_by_phase"]["analysis"]
rows = collect_init_rows(phase_writes, phase_cat, "endpoint")
initialized, skipped = apply_inits(rows)
check("E2E endpoint analysis: many rows initialized", len(initialized) >= 20, True)
check("E2E endpoint analysis: Analysis.verdict initialized to ''", demisto.dt(demisto._context, "Analysis.verdict"), "")
check("E2E endpoint analysis: Analysis.story initialized to []", demisto.dt(demisto._context, "Analysis.story"), [])
check("E2E endpoint analysis: Analysis.response_recommended initialized to False", demisto.dt(demisto._context, "Analysis.response_recommended"), False)
check("E2E endpoint analysis: Analysis.case_score initialized to 0", demisto.dt(demisto._context, "Analysis.case_score"), 0)
# Email-specific keys should NOT be present (endpoint route)
check("E2E endpoint analysis: Analysis.Email.signal_type NOT initialized (wrong route)",
      demisto.dt(demisto._context, "Analysis.Email.signal_type"), None)

# Email-routed analysis init
demisto._context = {"SOCFramework": {"Product": {"category": "Email"}}}
rows = collect_init_rows(phase_writes, phase_cat, "email")
initialized, skipped = apply_inits(rows)
check("E2E email analysis: Analysis.verdict initialized", demisto.dt(demisto._context, "Analysis.verdict"), "")
check("E2E email analysis: Analysis.Email.signal_type initialized", demisto.dt(demisto._context, "Analysis.Email.signal_type"), "")
check("E2E email analysis: Analysis.case_score IS initialized (universal top-level write)",
      demisto.dt(demisto._context, "Analysis.case_score"), 0)

# Identity-routed containment with cross-namespace writes
demisto._context = {"SOCFramework": {"Product": {"category": "Identity"}}}
phase_writes = list_data["writes_by_phase"]["containment"]
phase_cat    = list_data["writes_by_category_by_phase"]["containment"]
rows = collect_init_rows(phase_writes, phase_cat, "identity")
initialized, skipped = apply_inits(rows)
check("E2E identity containment: Blocklist.Final initialized to []",
      demisto.dt(demisto._context, "Blocklist.Final"), [])
check("E2E identity containment: Core.Isolation.endpoint_id initialized",
      demisto.dt(demisto._context, "Core.Isolation.endpoint_id"), "")


# --- Summary ---
print()
if fails:
    print(f"{FAIL} {len(fails)} test(s) failed:")
    for label, got, want in fails:
        print(f"    {label}: got={got!r} want={want!r}")
    sys.exit(1)
print(f"{PASS} all tests passed")
