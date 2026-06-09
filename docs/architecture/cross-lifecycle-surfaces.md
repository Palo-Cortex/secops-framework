# Cross-Lifecycle Surfaces — Audit

> **Purpose.** Catalog every dependency between the shared SOC Framework
> (`soc-optimization-unified`) and a lifecycle pack
> (`soc-framework-<lifecycle>`), tiered by **blast radius**. A surface's tier is
> the answer to one question: *if this changes, how many lifecycles break?*
>
> The audit serves three downstream uses:
>
> 1. **Scaffolder scope.** `scaffold_lifecycle.py` stamps everything in Tier 4
>    from schemas; it never touches Tiers 1–3.
> 2. **Change-review discipline.** Any PR touching Tier 1 or Tier 2 must
>    explicitly acknowledge cross-lifecycle impact in its description.
> 3. **Known-violation triage.** Surfaces currently in the wrong tier (e.g.,
>    Tier-4 concerns hardcoded into Tier-1 engines) are called out as fixes
>    required before the second lifecycle (posture) lands.

---

## Tier 1 — Shared Engines

> **Changing any of these breaks all lifecycles simultaneously.** Highest
> blast radius. Every change requires regression testing against every shipped
> lifecycle.

### Currently shipped

| Component | Type | Location |
|---|---|---|
| `SOCNormalizeFromList` | Script | `soc-optimization-unified/Scripts/` |
| `SOCEnrichFromList` | Script | `soc-optimization-unified/Scripts/` (shipped this session) |
| `SOCFrameworkPhaseWriter` | Script | `soc-optimization-unified/Scripts/` |
| `SOCCommandWrapper` | Script | `soc-optimization-unified/Scripts/` |
| `Foundation_-_Normalize_Artifacts_V3` | Playbook | `soc-optimization-unified/Playbooks/` |
| `Foundation_-_Enrichment_V3` | Playbook | `soc-optimization-unified/Playbooks/` (thin dispatcher, shipped this session) |
| `Foundation_-_Upon_Trigger_V3` | Playbook | `soc-optimization-unified/Playbooks/` |
| `Foundation_-_Dedup_V3` | Playbook | `soc-optimization-unified/Playbooks/` (query fields need parameterization — see V2) |

### Required before second lifecycle (posture)

| Component | Status | Why required |
|---|---|---|
| `SOCDedupFromList` | **Not built** | Schema-driven dedup engine. Foundation_-_Dedup_V3 exists; what's missing is per-lifecycle query-field resolution so posture can use asset+finding keys instead of IR's hostname+signal keys. |

### Stability commitments

- Engines resolve lifecycle-specific contracts by **naming convention only**
  (`SOCFramework<Type>Map_<LIFECYCLE>` or `SOCFramework<Type>Contract_<LIFECYCLE>`).
  Engines never embed lifecycle names.
- Adding a lifecycle is **additive content** — zero edits to anything in Tier 1.
- Removing or renaming an engine requires a documented migration path for all
  shipped lifecycles.

---

## Tier 2 — Shared Contracts

> **Changing any of these requires lockstep updates across every lifecycle
> pack.** Lower blast radius than Tier 1 (engines don't need rebuilding) but
> still propagates to every lifecycle's content.

### Namespace structure

- `SOCFramework.Artifacts.<Domain>.<Field>` — vendor-agnostic artifact contract.
  Domains: `Endpoint`, `Process`, `Target`, `Network`, `Source`, `Email`,
  `Identity`, `MITRE`, `User`. Posture will add `AttackSurface`. Agentic will
  add `Agent`.
  - **Adding a new domain or a new field within a domain = Tier 4 (per-lifecycle
    schema work).** Lifecycle's NormalizeMap declares the new path; no engine
    or framework change needed.
  - **Removing or renaming an existing domain key = breaking,** requires
    migration of every lifecycle plus a deprecation cycle (LEGACY ALIASES band
    in NormalizeMap).
- `SOCFramework.<Category>.<leaf>` — legacy flat read surface. Frozen; new
  playbooks read from `Artifacts.*`.
- `SOCFramework.lifecycle` — context key resolving the active lifecycle. EP
  playbooks stamp this as their first task (NIST IR already does this; every
  new EP must do the same — scaffolder enforces). Universal Command derives
  dataset and HTTP Collector instance from this by convention (see V1).
- `SOCFramework.Product.category` — drives Universal Command routing.

### Enrichment lane keys

The four lane keys (`ip`, `file`, `domain`, `url`) are **framework primitives**
because they map to built-in reputation commands of the same names.

| Change type | Tier | Notes |
|---|---|---|
| Adding artifact paths to an existing lane | **Tier 4** | Lifecycle schema work only. Add a row to `lanes.ip` (or any lane) in your EnrichmentMap. Safe, additive, zero framework impact. |
| Adding a new lane key (e.g., `email`, hash family split) | **Tier 1 + Tier 2** | Engine extension + every lifecycle's schema can opt in. Rare. |
| Removing a lane key | **Tier 1 + Tier 2 + every lifecycle** | Don't. |

**Bottom line for lifecycle teams:** extending enrichment within a lane is
freely additive. The "major change" case is only when the framework grows a
new reputation primitive — and we'd only do that if XSIAM adds a new built-in
reputation command.

### Naming conventions

| Artifact | Pattern | Example |
|---|---|---|
| Pack | `soc-framework-<lifecycle-id>` | `soc-framework-nist-ir` |
| Schema | `SOCFramework<Type><Map\|Contract>_<LIFECYCLE>.yaml` | `SOCFrameworkNormalizeMap_NIST_IR.yaml` |
| List (generated) | `SOCFramework<Type><Map\|Contract>_<LIFECYCLE>` | `SOCFrameworkEnrichmentMap_NIST_IR` |
| Entry Point playbook | `EP_<Lifecycle>_V3` | `EP_IR_NIST (800-61)_V3` |
| Lifecycle controller | `SOC_<Lifecycle>_V3` | `SOC_NIST_IR_V3` (proposed: `SOC_Posture_V3`) |
| Phase playbook | `SOC_<Category>_<Phase>_V3` | `SOC_Identity_Containment_V3` |
| Dataset | `xsiam_socfw_<lifecycle>_execution_raw` | `xsiam_socfw_ir_execution_raw`, `xsiam_socfw_posture_execution_raw` |
| HTTP Collector instance | `socfw_<lifecycle>_execution` | `socfw_ir_execution`, `socfw_posture_execution` |

**Note.** New lifecycles do **not** use the `_V3` suffix on lifecycle-specific
schemas. The `_V3` suffix is a versioning artifact from the v2→v3 migration of
NIST IR and is being phased out for clarity.

### xsoar_config dependency shape

The lifecycle pack's `xsoar_config.json` declares **everything that needs RBAC
isolation** as pack-install-time artifacts (same pattern soc-opt uses today):

- HTTP Collector instance — per-lifecycle XQL System HTTP Collector
  (keyless — XSIAM-internal auth via the integration instance, no API key
  needed)
- Dataset name — referenced in the HTTP Collector config (auto-created via
  collector seeding)
- Dashboards — lifecycle-scoped, RBAC-tagged
- Vendor integration instances scoped to this lifecycle

The pack is the unit of RBAC bundling. A bundle installer creates everything
atomically; RBAC role assignment is a single admin step on top.

Cross-pack URL refs (`xsoar_config.json` pointing at another pack's release
ZIP) lag releases by one cycle. Acceptable; fix in tiny follow-up PRs.

### Stability commitments

- New domain in `Artifacts.*` namespace = additive, safe.
- Removing or renaming existing keys = breaking, requires migration.
- New required column in any Tier-3 registry = breaking for every lifecycle
  consuming that list.

---

## Tier 3 — Shared Registries

> **Additive changes are safe. Removals or schema changes can break
> lifecycles silently.** Lists customer-tunable; framework consumes via
> schema-validated reads.

| List | Purpose | Lifecycle handling |
|---|---|---|
| `SOCFrameworkActions_V3` | Action registry (Shadow Mode SoT, action metadata) | **Shared.** Actions are vendor/category-typed, not lifecycle-typed. Posture-specific actions add as new rows. |
| `SOCActionTimeMap_V3` | Active time source for metrics | **Shared with lifecycle tagging.** Add a `lifecycle` column so per-lifecycle MTT* dashboards can filter cleanly. One-time additive column change before posture lands. |
| `SOCProductCategoryMap_V3` | Category routing per source/vendor | **Shared.** Each posture category gets its own row (`posture_patch`, `posture_vuln`, `posture_exposure`) defining category and response. Rows don't cross lifecycles. |

### Stability commitments

- Adding a row = safe.
- Removing or renaming a row used by a lifecycle = breaking for that lifecycle.
- Changing a row's schema (e.g., adding a required column) = breaking for all
  lifecycles consuming that list. The `SOCActionTimeMap_V3` lifecycle column is
  a one-time absorbed-now breaking change.

### RBAC scope note

XSIAM's RBAC has two distinct scopes worth distinguishing:

- **Dataset RBAC** — hard isolation. Per-lifecycle datasets are mandatory
  (see V1).
- **List RBAC** — separate system, per-list. Shared lists at Tier 3 are
  consumed by framework engines at engine-privilege level (not exposed to
  analyst-visibility paths), so dataset RBAC isolation isn't compromised by
  keeping these lists shared.

**Decision:** keep Tier 3 lists shared by default. Revisit per-lifecycle
splits only if a customer surfaces a list-RBAC requirement (e.g., analyst
team A must not see list governing team B's actions).

---

## Tier 4 — Per-Lifecycle Surfaces

> **Safe to evolve in isolation.** A lifecycle's pack is sovereign over these
> surfaces. The scaffolder stamps all of them from schemas + parameters; the
> human authors schema content and phase playbook content.

### Four schemas per lifecycle (canonical set)

| Schema | Drives | Engine |
|---|---|---|
| `SOCFrameworkNormalizeMap_<LIFECYCLE>` | Raw issue fields → `SOCFramework.Artifacts.*` | `SOCNormalizeFromList` |
| `SOCFrameworkEnrichmentMap_<LIFECYCLE>` | `Artifacts.*` paths → reputation lookups | `SOCEnrichFromList` |
| `SOCFrameworkDedupContract_<LIFECYCLE>` | Key fields + window + duplicate action | `SOCDedupFromList` *(to build)* |
| `SOCFrameworkPhaseContract_<LIFECYCLE>` | Phase flow + writer behavior | `SOCFrameworkPhaseWriter` |

### Lifecycle-scoped routing

- `SOCExecutionList_<LIFECYCLE>` — per-lifecycle branch routing (each
  lifecycle's Workflow playbooks land here). Engines resolve by convention,
  same pattern as the four schemas.

### Pack contents (scaffolder output)

```
Packs/soc-framework-<lifecycle>/
├── pack_metadata.json              (marketplaces:[marketplacev2], supportedModules)
├── xsoar_config.json               (HTTP Collector instance + dataset + dashboard refs)
├── ReleaseNotes/1_0_0.md
├── Lists/
│   ├── SOCFrameworkNormalizeMap_<L>/        (generated from schema)
│   ├── SOCFrameworkEnrichmentMap_<L>/       (generated from schema)
│   ├── SOCFrameworkDedupContract_<L>/       (generated from schema)
│   ├── SOCFrameworkPhaseContract_<L>/       (generated from schema)
│   └── SOCExecutionList_<L>/                (stub; rows added as Workflows ship)
├── Layouts/                                  (per-lifecycle custom layouts)
├── Playbooks/
│   ├── EP_<Lifecycle>_V3.yml                (stub: stamp lifecycle ctx + dataset, call Foundations, dispatch)
│   └── SOC_<Phase>_V3.yml × N               (stubs: start → SOCFrameworkPhaseWriter → done)
├── Dashboards/                               (lifecycle-scoped, RBAC-tagged)
└── (other lifecycle content authored by human)

schemas/soc-framework/<lifecycle-id>/
├── SOCFrameworkNormalizeMap_<L>.yaml
├── SOCFrameworkEnrichmentMap_<L>.yaml
├── SOCFrameworkDedupContract_<L>.yaml
└── SOCFrameworkPhaseContract_<L>.yaml

docs/<lifecycle-id>/
└── overview.md
```

### Additional per-lifecycle surfaces (future)

- **Custom Fields** — when a lifecycle needs incident fields outside the
  shared schema (e.g., posture-specific `cve_id`, `cvss_base`).
- **Vendor integration instances** — vendor instances scoped to a lifecycle,
  declared in xsoar_config.json.

### Authored by human (NOT scaffolded)

- Schema content (the four YAMLs — scaffolder reads them as spec)
- Phase playbook bodies (the actual Workflow logic per phase)
- Any Action playbooks specific to the lifecycle's domain
- Custom layouts and field definitions

---

## Items to Decide / Known Violations

### V1 — Dataset name hardcoded (RBAC requires per-lifecycle isolation)

**Driver.** XSIAM RBAC scopes to dataset. Different teams owning IR
remediation vs. posture remediation need different visibility, which requires
different datasets. This isn't a preference — it's how RBAC works in XSIAM.

**Current state.** `SOCCommandWrapper` writes execution records to a
hardcoded dataset name (`xsiam_socfw_ir_execution_raw`). If posture lifecycle
runs unchanged, it would write into NIST IR's dataset and break both the data
model and the RBAC boundary.

**Fix path** (Universal Command is the natural adapter — same way it abstracts
vendor commands):

1. `SOCCommandWrapper` reads `SOCFramework.lifecycle` (already stamped by every
   EP) and derives both names by convention:
   - `using = f"socfw_{lifecycle}_execution"` (HTTP Collector instance to write
     through)
   - The HTTP Collector instance config (declared in xsoar_config.json) already
     contains the per-lifecycle dataset name, so the wrapper doesn't even need
     to know it explicitly.
2. No new context key is needed. Existing `SOCFramework.lifecycle` is sufficient.
   Backward-compat fallback: if `lifecycle` is empty, default to `ir` (matches
   today's behavior).
3. Lifecycle pack's `xsoar_config.json` declares the XQL System HTTP Collector
   instance with the lifecycle's dataset name (keyless — XSIAM-internal auth
   via the integration instance, no API key needed). Pack install creates the
   instance and seeds the dataset.
4. Dashboards UNION across per-lifecycle datasets where cross-lifecycle
   metrics are needed; otherwise filter to the relevant dataset.

**Required before:** posture lifecycle ships.

### V2 — Dedup query fields hardcoded (was always intended to be per-lifecycle)

**Driver.** Dedup keys differ fundamentally per lifecycle:

| Lifecycle | Dedup keys | Time window |
|---|---|---|
| NIST IR | hostname + signal type + MITRE technique | Hours |
| Posture | asset ID + finding ID (CVE / config rule) | Long or absent (same misconfig is the same issue regardless of when re-detected) |
| VM | asset ID + CVE | Long |

**Current state.** `Foundation_-_Dedup_V3` does the heavy lifting (query,
link as child, deterministic self-close). The query field set is
effectively IR-shaped. Per-lifecycle dedup keys are the design intent that
wasn't implemented from the start.

**Fix path:**

1. Define `SOCFrameworkDedupContract_<LIFECYCLE>` schema: key fields (which
   artifact paths key uniqueness), time window, duplicate action (suppress /
   merge / count).
2. Build `SOCDedupFromList` engine consuming the contract.
3. Migrate `Foundation_-_Dedup_V3` to read query fields from the contract.

**Required before:** posture lifecycle ships (otherwise posture inherits
IR-shaped dedup logic that doesn't fit its data model).

### V3 — PhaseContract naming convention

**Current state.** NIST IR ships `SOCFrameworkPhaseContract_V3.yaml`. The
other three schemas use `_NIST_IR` suffix.

**Decision (confirmed):** Rename existing NIST IR to
`SOCFrameworkPhaseContract_NIST_IR.yaml`. New lifecycles use
`SOCFrameworkPhaseContract_<LIFECYCLE>.yaml`. New lifecycles do not use the
`_V3` suffix at all.

**Side migration:** Trivial rename, do as part of the dedup/dataset work.

### V4 — Lifecycle context stamping in EP

**What it is.** Every EP playbook's first task stamps a context key
`SOCFramework.lifecycle = "<lifecycle-id>"` (e.g., `"nist_ir"`, `"posture"`).
That stamp is what the framework engines read to find the right schemas —
`SOCNormalizeFromList` resolves `SOCFrameworkNormalizeMap_<lifecycle.upper()>`,
`SOCEnrichFromList` does the same for EnrichmentMap, Universal Command uses
it to derive the dataset/instance name (per V1).

**Current state.** NIST IR's EP already stamps it. Works today.

**Decision.** The scaffolder's EP stub must include this stamp as its first
task for every new lifecycle. Codify in the scaffolder template so the
pattern can't be forgotten when adding a new lifecycle.

**Required before:** every new lifecycle.

### V5 — Skill OS analogy section

**Current state.** Skill OS analogy table treats
`xsiam_socfw_ir_execution_raw` as "syslog = Tier 1 shared" — a single-OS
metaphor.

**Decision:** Update to reflect per-lifecycle datasets. The syslog metaphor
still holds; facilities are partitioned per-application (`/var/log/auth.log`
vs `/var/log/syslog` is exactly how real syslog handles isolation). The OS
analogy row should read: "syslog facility — per-lifecycle dataset,
RBAC-scoped" instead of treating the dataset as a single shared resource.

**This is a skill content update only**, not an architecture change.

---

## Volatility / Change Frequency Notes

Not a tier, but worth tracking for change-budget purposes. Things that
change most often during current lifecycle immaturity:

- **`SOCFramework.Artifacts.*` namespace** — high churn now as Domains stabilize.
  Expected to slow as each lifecycle's contract matures. Lifecycle teams can
  freely add fields within a domain (Tier 4); cross-lifecycle Domain renames
  are the danger.
- **`SOCFrameworkActions_V3`** — high churn while lifecycles are young and
  product coverage expands. Mostly additive; rarely breaking.
- **Playbooks (per-lifecycle)** — always volatile. Per-lifecycle ownership
  means freely editable (Tier 4).
- **Layouts and custom fields (future)** — expected to grow as lifecycles
  mature. Per-lifecycle (Tier 4).

Watch for: anything that should be Tier 4 leaking into Tier 1 or Tier 2
because of an expedient hardcode. Today's two known instances of that
leakage are V1 (dataset) and V2 (dedup keys). Both fix before posture.

---

## Stability Watch — Surfaces to Monitor for Drift

Items that aren't violations today but where future work could push Tier-4
concerns into higher tiers. Worth re-auditing before each minor release:

- New shared script in soc-opt that reads lifecycle-specific data → check it
  resolves by convention, not by hardcoded lifecycle name.
- New required column in any Tier-3 registry → check all lifecycle packs
  populate it.
- New Foundation playbook → check it's lifecycle-agnostic and dispatches via
  schema, not branches.
- Dashboard widgets querying datasets → check they UNION across all
  per-lifecycle datasets when V1 lands; otherwise scope to the relevant
  dataset only.
- New Action in `SOCFrameworkActions_V3` → check it's vendor/category-typed,
  not lifecycle-typed (lifecycle-typed actions belong in the lifecycle pack
  or as a per-lifecycle namespaced subset).
