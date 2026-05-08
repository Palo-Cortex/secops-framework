# SOC Framework — Tooling & CI Reference

This is the canonical reference for every script in `tools/`. Tools are organized
by lifecycle phase, not alphabetically — find the phase you're in, find the tool.

## Daily Workflow (Short Version)

The single command for every iteration:

```bash
python3 tools/check_contribution.py
```

That orchestrator runs the full validation chain and pushes to the review tenant.
Everything below is the long version of what that one command does.

If you only need to validate without pushing:

```bash
python3 tools/check_contribution.py --no-upload
```

If you're working on a specific pack outside a branch:

```bash
python3 tools/check_contribution.py --input Packs/soc-framework-nist-ir
```

---

## Tools by Lifecycle Phase

### 1. Vendor Pack Authoring — Creating Content From Contracts

The SOC Framework drives every vendor pack from a single source-of-truth YAML
in `schemas/vendors/<vendor>/<data-source>.yaml`. The contract declares
modeling rules and correlation rules; the generator emits them. **Edit the
contract, not the generated files.**

#### `new_vendor_pack.py` — Bootstrap a new vendor pack from scratch

One-shot creator. Takes a schema YAML and produces a complete pack skeleton
with `pack_metadata.json`, directory layout, and all required scaffolding.

```bash
python3 tools/new_vendor_pack.py \
  --schema schemas/vendors/<vendor>/<data-source>.yaml \
  --pack-root Packs/<new-pack-name>
```

Use this for first-time onboarding of a new vendor (e.g., adding Vision One,
SentinelOne). After the pack exists, switch to `generate_vendor_content.py`
for ongoing edits.

#### `init_pack.py` — Initialize an empty pack with SOC Framework conventions

For when `new_vendor_pack.py` is overkill — initializes a minimal pack
structure with the right metadata fields and folder layout. Useful when
you're building a non-vendor pack (e.g., a new lifecycle pack, a Foundation
extension).

```bash
python3 tools/init_pack.py --name <pack-name> --root Packs/
```

#### `generate_vendor_content.py` — Emit rules from contract YAML

The workhorse for ongoing vendor pack edits. Reads the contract, emits
`ModelingRules/<id>/<id>.{xif,yml,_schema.json}` and
`CorrelationRules/<name>.yml`. **Always run this after editing a contract.**

```bash
# Validate the contract (no files written)
python3 tools/generate_vendor_content.py validate \
  --mapping schemas/vendors/<vendor>/<data-source>.yaml

# Emit all declared rules
python3 tools/generate_vendor_content.py emit \
  --mapping schemas/vendors/<vendor>/<data-source>.yaml \
  --pack-root Packs/<pack-name>

# Roundtrip — emit to temp dir and diff against shipped (review changes before commit)
python3 tools/generate_vendor_content.py roundtrip \
  --mapping schemas/vendors/<vendor>/<data-source>.yaml \
  --pack-root Packs/<pack-name>
```

`roundtrip` is the recommended flow when iterating — emit, diff, commit only
when the diff matches your intent. Saves you from yaml-key-reorder surprises.

#### `generate_soc_framework_content.py` — Schema-driven list/lookup generator

Generates `SOCFrameworkActions_V3` and other framework lists from JSON
schemas in `schemas/`. Used during framework-level changes (e.g., adding
new actions to the Universal Command), not during vendor pack work.

```bash
python3 tools/generate_soc_framework_content.py \
  --schema schemas/Artifacts.Endpoint.schema.json
```

#### `extract_normalizer_contracts.py` — Pull contracts from existing rules

Reverse-engineers a contract YAML from an existing modeling rule + correlation
rule pair. Useful when migrating a hand-written vendor pack into the
contract-driven flow.

```bash
python3 tools/extract_normalizer_contracts.py \
  --pack-root Packs/<existing-pack-name>
```

---

### 2. Contract & Rule Validation — Pre-Commit Sanity

These run automatically inside `check_contribution.py`, but you can invoke
them individually when iterating on a single rule.

#### `check_contracts.py` — Layer contract validator

Catches layer-contract violations: `setIssue` from a Workflow playbook,
writes to the wrong namespace, missing Lifecycle phase boundaries,
Workflow playbooks reading `issue.*` (only Foundation may).

```bash
python3 tools/check_contracts.py --pack Packs/<pack-name>
```

Run this whenever you've edited playbooks. The Universal Command boundary
is the most common violation source.

#### `correlation_rule_preflight.py` — 10-check correlation rule validator

Catches the platform gotchas the SDK validator misses. The 10 checks include:
`rule_id: 0` SDK null resolution, `alert_category: OTHER` (must be `User Defined`),
missing `id`/`ruleid` (causes 101704), `fromversion: 6.10.0` mismatch on
correlation rules, optional fields omitted instead of explicit `null`,
`config case_sensitive` first-line breakage on REAL_TIME rules, and a few
more edge cases learned the hard way.

```bash
python3 tools/correlation_rule_preflight.py Packs/<pack-name>/CorrelationRules/
```

If the rule fails preflight, it will fail upload. Do not skip.

#### `playbook_condition_lint.py` — Catch broken context interpolations

Validates playbook YAML for two patterns that parse cleanly but silently
fail at runtime: broken `${X / Y}` context interpolation expressions, and
AND-impossible condition blocks (where two branches' conditions can never
simultaneously hold). Fast, catches subtle bugs that show up only in production.

```bash
python3 tools/playbook_condition_lint.py Packs/<pack-name>/Playbooks/
```

#### `validate_playbooks.py` — Full playbook integrity check

Heavier than the condition lint — validates structural integrity, task
references, input/output completeness, dependency declarations. Run this
on demand when you've made significant playbook changes.

```bash
python3 tools/validate_playbooks.py --pack Packs/<pack-name>
```

#### `validate_shadow_mode.py` — Shadow Mode consistency gate

Verifies every action playbook respects the Shadow Mode contract. Reads
`SOCFrameworkActions_V3` and confirms each action has the right
`shadow_mode` flag, that `SOCCommandWrapper` is invoked correctly, and
that no action bypasses the wrapper. **This is the most important PoV
safety check** — a mis-flagged action will execute a real vendor command
during a Shadow Mode demo.

```bash
python3 tools/validate_shadow_mode.py
```

Set up as a pre-commit hook, not a CI gate (per architectural decision —
too fragile in CI environments where the full pack context isn't available).

#### `validate_xsoar_configs.py` — `xsoar_config.json` CI gate

Validates `xsoar_config.json` in every pack against the schema. Catches
malformed dependency declarations, bad version pins, missing required
fields. Runs in CI on every PR.

```bash
python3 tools/validate_xsoar_configs.py
```

#### `validate_pack_catalog.py` / `validate_catalog_urls.py` — Catalog gates

Two related catalog validators:

- `validate_pack_catalog.py` — confirms every pack in `pack_catalog.json`
  has a matching `pack_metadata.json` with consistent version
- `validate_catalog_urls.py` — verifies every catalog URL resolves
  (no broken zip links after a release)

```bash
python3 tools/validate_pack_catalog.py
python3 tools/validate_catalog_urls.py
```

#### `check_dependency_versions.py` — Cross-pack version drift detector

Compares version strings embedded in each pack's `xsoar_config.json` URLs
against the pack's actual `pack_metadata.json` version. Catches the
common drift bug where you bump a pack but forget to update its consumers.

```bash
python3 tools/check_dependency_versions.py
```

A `pin` field for explicit version locks is on the backlog; today this
script flags any drift.

#### `check_foundation_continueonerror.py` — Foundation playbook safety check

Verifies every Foundation playbook task that calls a sub-playbook has
`continueonerror: true`. Foundation runs on every alert before lifecycle
routing — a single failure must never block the chain.

```bash
python3 tools/check_foundation_continueonerror.py
```

#### `preflight_xsoar_config.py` — Pre-deployment config sanity

Pre-deployment validator for `xsoar_config.json` — verifies all referenced
integrations exist, all instance names match what the framework expects
(`PlaybookMetrics`, `socfw_ir_execution`), no orphaned dependencies.

```bash
python3 tools/preflight_xsoar_config.py --pack Packs/<pack-name>
```

#### `playbook_simulator.py` — Static execution engine

Walks a playbook YAML and simulates execution against a synthetic context.
Useful for verifying branch logic without spinning up a tenant. Doesn't
catch runtime issues — that's what `replay_scenario.py` is for.

```bash
python3 tools/playbook_simulator.py \
  --playbook Packs/<pack>/Playbooks/<name>.yml \
  --context fixtures/<scenario>.json
```

#### `test_playbooks.py` — Playbook test runner

Test runner for SOC Framework playbooks against tenant fixtures. Designed
for L1 unit tests of individual playbooks.

```bash
python3 tools/test_playbooks.py --pack Packs/<pack-name>
```

#### `run_tests.py` — Live XQL test runner

Test runner that executes XQL queries against a live XSIAM tenant and
verifies expected result shapes. Used for L2 smoke tests after upload —
confirms entry point fires, chain runs, terminal status is correct.

```bash
python3 tools/run_tests.py --tenant brumxdr
```

Reads tenant credentials from `.env`.

#### `sdk_classify.py` — Classify SDK validation errors

Buckets `output/sdk_errors.txt` errors by category (BA101, BA106, etc.) so
you can fix them in priority order. Used by `fix_errors.py` internally,
also runnable standalone for diagnostics.

```bash
python3 tools/sdk_classify.py
```

---

### 3. Replay & Test Data — PoV Scenario Generation

#### `replay_scenario.py` — XSIAM attack scenario replay

The canonical replay tool. Reads a manifest YAML from `scenarios/<name>.yml`
that lists per-vendor TSV files, and posts events to the appropriate
HTTP Collector URLs. Drives PoV demos and end-to-end testing.

```bash
python3 tools/replay_scenario.py \
  --manifest scenarios/turla-carbon.yml \
  --tenant brumxdr
```

HTTP Collector URLs are per-vendor and live in `SOCFWPoVConfig` on the
tenant. The tool reads them via the `SOCFWPoVSend` script.

#### `replay_crowdstrike_scenario.py` — CrowdStrike-specific replay

Older CrowdStrike-only replay path, kept for legacy scenarios. New work
should use `replay_scenario.py` (which handles CrowdStrike alongside
every other vendor via the manifest).

#### `send_test_events.py` — Send single events for schema seeding

Posts one event per vendor to seed empty dataset schemas. Use this on a
fresh dev tenant before you upload correlation rules — without seed data,
the rules can fail upload with 101704 (XQL references a field not in the
dataset schema).

```bash
python3 tools/send_test_events.py --vendor crowdstrike --tenant brumxdr
```

#### `build_campaign_from_tsv.py` — Multi-product campaign builder

Builds a multi-product attack campaign JSON from per-vendor TSV files
(e.g., Proofpoint TAP delivery + click + CrowdStrike execution). Output
is a unified manifest you can hand to `replay_scenario.py`.

```bash
python3 tools/build_campaign_from_tsv.py \
  --inputs proofpoint-tap.tsv crowdstrike-falcon.tsv \
  --output scenarios/<name>.yml
```

#### `build_proofpoint_scenarios.py` — Proofpoint TAP scenario generator

Generates 6 realistic Proofpoint TAP TSV scenario files covering the
common phishing patterns (delivered + clicked, blocked + retroactive
discovery, etc.). Useful when you need TAP volume for a PoV without
hand-crafting events.

```bash
python3 tools/build_proofpoint_scenarios.py --output scenarios/proofpoint/
```

#### `sanitize_tsv.py` — Repo-safety scanner

Scans replay TSV files for content that should never end up in a public
repo: real customer hostnames, real email addresses, real IP allocations.
Run this before committing any replay scenario.

```bash
python3 tools/sanitize_tsv.py scenarios/**/*.tsv
```

#### `tsv_to_json.py` — CrowdStrike TSV → JSON

Converts a CrowdStrike Falcon TSV export to a flat JSON array suitable
for `send_test_events.py`. Used by `replay_scenario.py` internally.

```bash
python3 tools/tsv_to_json.py --input crowdstrike-falcon.tsv --output cs.json
```

#### `tsv_to_json_proofpoint.py` — Proofpoint TAP TSV → JSON

Same as above, for Proofpoint TAP. Important: the Proofpoint API returns
camelCase field names; the production XSIAM TAP integration normalizes to
lowercase on ingest. Make sure your replay TSVs use lowercase headers
to match production schema, or correlation rule references will fail
silently.

```bash
python3 tools/tsv_to_json_proofpoint.py \
  --input proofpoint-tap.tsv --output tap.json
```

---

### 4. Push & Test — The Daily Workflow

#### `check_contribution.py` — The single entry point

Pre-merge contribution validation orchestrator. Runs every check in this
file's "Daily Workflow" section in the right order with the right exit
codes for both local dev and CI.

```bash
# Default — find changed packs from git diff and validate + push
python3 tools/check_contribution.py

# Validate only
python3 tools/check_contribution.py --no-upload

# Specific pack (when not on a branch)
python3 tools/check_contribution.py --input Packs/<pack-name>

# CI mode — formats output for GitHub Actions annotations
python3 tools/check_contribution.py --ci
```

Exit codes: `0` = all passed (or upload skipped); `1` = at least one check failed.

The internal chain it runs:

1. `normalize_contribution.py` — strip UI export artifacts
2. `correlation_rule_preflight.py` — 10-check rule validator
3. `playbook_condition_lint.py` — context interpolation + condition logic
4. `pack_prep.py` — SDK validation + dependency check
5. `fix_errors.py --report` — SDK error report (no auto-fix in this mode)
6. `check_contracts.py` — layer contract violations
7. `validate_shadow_mode.py` — shadow mode consistency
8. `upload_package.sh` — deploy to review tenant (skipped with `--no-upload`)

#### `normalize_contribution.py` — Strip UI export artifacts

Strips XSIAM UI-export artifacts (the cruft Cortex's UI adds when you
export a playbook or list) and renames files to canonical names matching
the pack convention. Skips descriptor files where stem == canon name
(prevents UPDATE-MODE corruption of already-normalized files). Scoped
to Added files only via `--diff-filter=A`.

```bash
python3 tools/normalize_contribution.py --pack Packs/<pack-name>
```

The intentional-violation suppression annotation is `# contract:allow`
on the line above the offending field.

#### `normalize_ruleid_adopted.py` — One-shot migration

Migration-style normalizer that adds `adopted: true` as the first key in
every playbook YAML, removes legacy `rule_id: 0` entries, and a few
related cleanups. Run once when adopting a fresh contributed pack into
the framework — not part of the daily flow.

```bash
python3 tools/normalize_ruleid_adopted.py --pack Packs/<pack-name>
```

#### `pack_prep.py` — SDK validation + integrity checks

Runs `demisto-sdk validate`, verifies `xsoar_config.json` parses, runs
the cross-pack dependency check. The first thing in the chain that can
catch upload-blocking errors.

```bash
python3 tools/pack_prep.py Packs/<pack-name>
```

#### `fix_errors.py` — Auto-fix SDK validation errors

Auto-fixes the common BA101/BA106-class errors that the SDK flags but
won't fix itself: ID/name mismatches, `fromversion` drift, malformed
`adopted` flags. Has a `--dry-run` mode to preview changes.

```bash
# Preview
python3 tools/fix_errors.py --pack Packs/<pack-name> --dry-run

# Apply
python3 tools/fix_errors.py --pack Packs/<pack-name>

# Report-only (no fixes, used inside check_contribution.py)
python3 tools/fix_errors.py --pack Packs/<pack-name> --report
```

If `fix_errors.py` finds something `normalize_contribution.py` should have
caught, that's a signal to improve the normalizer rather than rely on the
auto-fix. Both tools exist; `normalize` is preferred where it covers.

#### `fix_xsoar_config_ids.py` — One-shot ID migration

One-shot fix for `xsoar_config.json` files that reference content by old
ID format. Run once when a pack is migrated to the V3 ID convention. Not
part of the daily flow.

```bash
python3 tools/fix_xsoar_config_ids.py --pack Packs/<pack-name>
```

#### `upload_package.sh` — Direct demisto-sdk upload

Wraps `demisto-sdk upload -x -z` with credential loading from `.env` (local)
or environment variables (CI). Includes platform health check — aborts if
the tenant's correlation API is unhealthy.

```bash
./tools/upload_package.sh Packs/<pack-name>

# Without an argument, prompts for the pack
./tools/upload_package.sh
```

Required env vars (loaded from `.env` locally):
- `DEMISTO_BASE_URL`
- `DEMISTO_API_KEY`
- `XSIAM_AUTH_ID`

`upload_package.sh` is what `check_contribution.py` calls for the upload
step. Run it directly when you want to skip the full validation chain
(e.g., re-uploading after a tenant glitch).

#### `platform_health_check.sh` — Pre-upload API health probe

Verifies XSIAM API endpoints are responding. Two probes:

1. `GET /correlations` — verifies 200 + parseable response
2. `CREATE` a disabled test rule — verifies the write path isn't 500ing

Skips the write probe if the pack has no `CorrelationRules/` directory.
Set `SKIP_HEALTH_CHECK=1` to bypass entirely (useful in CI when the
preflight already ran).

```bash
./tools/platform_health_check.sh
SKIP_HEALTH_CHECK=1 ./tools/platform_health_check.sh
```

---

### 5. Versioning & Release

#### `bump_pack_version.py` — Increment pack version + update URLs

Bumps the version in `pack_metadata.json` and updates every URL in
`xsoar_config.json` that references that version. Three modes: `--list-changed`
to see what would change without writing, `--packs <list>` for explicit
packs, `--summary` for a one-line summary across all packs.

```bash
# See what's changed (no writes)
python3 tools/bump_pack_version.py --list-changed

# Bump a specific pack
python3 tools/bump_pack_version.py --packs Packs/<pack-name>

# Summary across all packs
python3 tools/bump_pack_version.py --summary
```

Bumping triggers CI deployment to QA via `soc-packs-release.yml`.

#### `build_pack_catalog.py` — Rebuild the pack catalog

Builds or updates `pack_catalog.json` from each pack's `pack_metadata.json`.
Run after any version bump or pack add/remove.

```bash
python3 tools/build_pack_catalog.py
```

#### `release_pack.sh` — Promote dev → tagged release

Promotes a pack from dev iteration to a tagged release. Bumps minor or
major version (not revision), regenerates `pack_catalog.json`, prints the
resulting version so you can tag the commit. **The one sanctioned way to
produce a release-level version bump.**

```bash
./tools/release_pack.sh Packs/<pack-name> minor
./tools/release_pack.sh Packs/<pack-name> major
```

---

### 6. Documentation Generation

#### `generate_pack_overviews.py` — Per-pack overview docs

Generates a markdown overview for each pack from its `xsoar_config.json`,
listing the contents and dependencies. Used by the MkDocs site.

```bash
python3 tools/generate_pack_overviews.py
```

#### `generate_schema_docs.py` — Schema documentation generator

Generates Swagger-style markdown documentation for SOC Framework JSON
schemas in `schemas/`. Useful for vendor pack contributors who need to
understand the contract.

```bash
python3 tools/generate_schema_docs.py
```

#### `generate_home_page.py` — docs/index.md from template

Generates `docs/index.md` from `docs/index.md.template` by injecting
auto-discovered pack listings and the latest version info.

```bash
python3 tools/generate_home_page.py
```

#### `generate_mkdocs_nav.py` — MkDocs navigation generator

Generates `mkdocs.yml` from `mkdocs.yml.template` by injecting the
auto-generated navigation tree. Run after adding new docs or packs so
they show up in the site nav.

```bash
python3 tools/generate_mkdocs_nav.py
```

---

### 7. Specialized Analysis

#### `ep_nist_dependency_map.py` — Cross-pack dependency mapping

Walks an Entry Point playbook and maps every sub-playbook called across
packs, producing a dependency tree. Useful for verifying NIST IR
lifecycle integrity.

```bash
python3 tools/ep_nist_dependency_map.py \
  --root-pack Packs/soc-framework-nist-ir \
  --root-playbook-name "EP_IR_NIST (800-61)_V3" \
  --other-pack Packs/soc-optimization-unified
```

The entry playbook name inside the YAML is `"EP_IR_NIST (800-61)_V3"`,
not `"EP IR NIST (800-61)"`. The docstring example using `--entry-name`
is wrong — that flag does not exist.

---

## In-Pack XSIAM Scripts (Not CLI Tools)

These three files are XSIAM Scripts — they run inside playbooks via
`executeCommand`, not from the shell. They live in `tools/` historically
but should move to `Packs/<pack>/Scripts/<name>/`:

- `SOCCommandWrapper_test_soc_detonate_file.py` — local test fixture for
  `SOCCommandWrapper.py` (not a CLI tool)
- `SOCFramework_AIVerdictSummary.py` — XSIAM Script that produces the
  AI-written verdict summary on identity incidents
- `SOCFramework_IdentityScoreAnalysis.py` — XSIAM Script that scores
  identity incidents using the CRITICAL/HIGH/MEDIUM/LOW tier system

Backlog: move these to `Packs/soc-optimization-unified/Scripts/` and
remove from `tools/`.

---

## CI Pipeline Reference

### `.github/workflows/soc-packs-pr-gate.yml` — Per-PR validation

Runs on every PR targeting `main`. The chain:

1. Set up Python + demisto-sdk
2. Run `check_contribution.py --ci`
3. Annotate failures inline on the PR

The PR gate **does not run the upload step** — it validates only. Upload
happens on push to `main` via the release workflow below.

The single-pack PR gate is currently warning-only (changed from hard fail
in late 2025 — too many false positives on multi-pack PRs).

### `.github/workflows/soc-packs-release.yml` — Push-to-main deployment

Runs on push to `main`. The chain:

1. Detect changed packs via `bump_pack_version.py --list-changed`
2. For each changed pack with a version bump, upload to the QA tenant
3. Regenerate `pack_catalog.json`
4. Push catalog updates back to the repo

All GitHub Actions are SHA-pinned (supply chain security requirement).

---

## Environment Variables and Secrets

Loaded from `.env` at the repo root (local dev) or from environment
variables already set by the caller (CI / GitHub Secrets).

| Variable | Required for | Notes |
|---|---|---|
| `DEMISTO_BASE_URL` | Every upload | XSIAM tenant URL (e.g., `https://api-brumxdr.xdr.us.paloaltonetworks.com`) |
| `DEMISTO_API_KEY` | Every upload | Tenant API key (from Settings → API Keys) |
| `XSIAM_AUTH_ID` | Every upload | API key ID (the `x-xdr-auth-id` header value) |
| `HTTP_COLLECTOR_URL_*` | Replay scenarios | Per-vendor URLs in `SOCFWPoVConfig`; used by `SOCFWPoVSend` |
| `SKIP_HEALTH_CHECK` | Optional | Bypass `platform_health_check.sh` (useful in CI) |

Variables already in the environment always take precedence over `.env` values.

---

## Common Issues

### "FileNotFoundError" on contract paths

Vendor contracts live in `schemas/vendors/<vendor>/<data-source>.yaml`,
not under `Packs/`. The pack root is separate. Find your contract:

```bash
find . -name "<contract-name>.yaml" 2>/dev/null
```

### "101704 installation failure" on correlation rule upload

Correlation rule references a field not in the dataset schema. Run
`send_test_events.py --vendor <name>` first to seed the dataset, then
re-upload.

### "X field is invalid" in the Preview Correlation Rule UI

The dataset doesn't have the field the rule references. Three causes:

1. **Replay TSV missing the field entirely** — add it to the TSV
2. **Case mismatch** — production normalizes to lowercase; replay TSVs
   may have camelCase from the vendor API. Lowercase the TSV header.
3. **Meta-field that XSOAR injects at ingest** (e.g., `sourceInstance`) —
   add it to the replay TSV with the production-observed constant value

### "BA101: id and name don't match"

Playbook `id` and `name` use spaces (e.g., `"SOC Identity Analysis_V3"`);
filename uses underscores (`SOC_Identity_Analysis_V3.yml`). The SDK
compares `id` to `name` only — both must use spaces.

### Shadow Mode behavior drift after pack reinstall

`SOCFrameworkActions_V3` carries the `requires_approval` and
`prompt_artifact` metadata per action. A wholesale `.txt` re-import wipes
these. Always import via `pack_prep.py` + `upload_package.sh`, never
hand-edit the list in the UI.

### `yaml.dump` corrupted my playbook

Don't use `yaml.dump` anywhere in this repo — it reorders keys and
corrupts XSIAM playbook structure (Upon Trigger chain, multi-MODEL
modeling rules). All YAML edits use targeted `str_replace` on raw text.

---

## Backlog

### BL-001 · Move XSIAM Scripts out of `tools/`

`SOCFramework_AIVerdictSummary.py`, `SOCFramework_IdentityScoreAnalysis.py`,
and `SOCCommandWrapper_test_soc_detonate_file.py` belong in
`Packs/soc-optimization-unified/Scripts/`, not `tools/`.

### BL-002 · Add `--help` blocks to silent tools

Several tools (`bump_pack_version.py`, `build_pack_catalog.py`, the
SOCFramework scripts) lack module docstrings. Adding them would let the
tool itself document usage rather than relying on this README.

### BL-003 · Deprecate `replay_crowdstrike_scenario.py`

`replay_scenario.py` covers CrowdStrike alongside every other vendor via
the manifest format. The CrowdStrike-specific replay should be removed
once all existing scenarios migrate to the generic manifest.

### BL-004 · Add `--pin <version>` flag to `check_dependency_versions.py`

Today the script flags any drift. A `pin` field for explicit version
locks would let packs declare "this is intentional, stop flagging it."

### BL-005 · `output/sdk_errors.txt` is appended-to, never cleared

`fix_errors.py` and `pack_prep.py` both append to this file. After a
day's worth of iterations, it contains stale errors mixed with fresh
ones. Clear it at the start of each run.
