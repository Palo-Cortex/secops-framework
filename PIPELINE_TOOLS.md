# SOC Framework — Pipeline Tools Reference

Developer workflow and CI tooling for the `secops-framework` repo.
All tools live in `tools/` and are designed to be run from the repo root.

---

## Daily dev workflow (in order)

```
pack_prep.py                 ← run this first on any pack you've modified
  └─ normalize_ruleid_adopted.py    (step 1)
  └─ validate_xsoar_configs.py      (step 2 — JSON validity)
  └─ check_dependency_versions.py   (step 3 — cross-pack dep versions, interactive)
  └─ preflight_xsoar_config.py      (step 4 — URL format, no HTTP)
  └─ demisto-sdk validate           (step 5)

upload_package.sh            ← deploy to dev tenant for live testing

bump_pack_version.py         ← trigger CI → deploys to QA

build_pack_catalog.py        ← run after merge to main
```

---

## Tool reference

### `pack_prep.py`

Pre-upload validation pipeline. Run once per pack before `upload_package.sh`.

```bash
python3 tools/pack_prep.py Packs/soc-optimization-unified
```

Runs all five steps in sequence. Exits 1 if any blocking step fails (JSON
validity, URL format, sdk validate). The dependency version check (step 3)
is non-blocking — it warns and optionally prompts to fix, but does not prevent
upload. SDK validation errors are written to `output/sdk_errors.txt`.

---

### `check_dependency_versions.py`

Detects stale cross-pack dependency versions in `xsoar_config.json`.

For every `custom_packs` entry that references a different pack (a dependency,
not the pack itself), compares the pinned version in the entry against that
pack's actual `pack_metadata.json` version.

**Self-entries** (where the pack references itself) are skipped — those are
validated by `preflight_xsoar_config.py`.

```bash
# All packs — interactive (prompts to fix on TTY)
python3 tools/check_dependency_versions.py

# Specific packs
python3 tools/check_dependency_versions.py --packs soc-optimization-unified

# Auto-fix all stale entries, no prompts
python3 tools/check_dependency_versions.py --fix

# Auto-fix a specific pack only
python3 tools/check_dependency_versions.py --packs soc-optimization-unified --fix

# CI mode — exit 1 on any stale entry
python3 tools/check_dependency_versions.py --strict
```

When `--fix` is applied, both `id` and `url` in the entry are updated to
match the current version from `pack_metadata.json`.

**Exit codes:** 0 = all current (or fixed), 1 = stale found with `--strict`
or fix write failure.

**CI:** Runs in `json-integrity` with `--strict` (no `--packs` filter). Scans
all packs so that bumping pack A in a PR fails if any consuming pack's config
still references the old version.

---

### `validate_xsoar_configs.py`

JSON validity check for `xsoar_config.json` files. Called by `pack_prep.py`
and the `json-integrity` CI job.

```bash
python3 tools/validate_xsoar_configs.py                           # all packs
python3 tools/validate_xsoar_configs.py --packs soc-optimization-unified,soc-framework-nist-ir
```

Exit 0 = valid JSON everywhere. Exit 1 = any file fails to parse.

---

### `preflight_xsoar_config.py`

Validates `xsoar_config.json` structure before deployment:

1. `custom_packs[*].url` — format validation (pack name + version match; no
   live HTTP check pre-merge since the release doesn't exist yet)
2. `pre_config_docs[*].url` — live HTTP check (must exist on `main`)
3. `post_config_docs[*].url` — live HTTP check

```bash
python3 tools/preflight_xsoar_config.py --packs SocFrameworkProofPointTap
python3 tools/preflight_xsoar_config.py --no-http          # skip live checks (local use)
```

CI runs full checks (HTTP enabled). `pack_prep.py` runs with `--no-http` to
avoid network latency locally.

---

### `normalize_ruleid_adopted.py`

Ensures every correlation rule YAML has matching `id:` / `ruleid:` fields and
every playbook YAML has `adopted: true` as its first key. Run automatically
by `pack_prep.py` step 1.

```bash
python3 tools/normalize_ruleid_adopted.py --root Packs/soc-framework-nist-ir --fix
```

Without `--fix`, reports issues without writing. With `--fix`, mutates files
in-place.

---

### `bump_pack_version.py`

Increments a pack's version in a tracking file to signal CI that a deploy
is needed. Does **not** modify `pack_metadata.json` — Scott manages that
manually.

```bash
python3 tools/bump_pack_version.py Packs/soc-optimization-unified
```

---

### `build_pack_catalog.py`

Rebuilds `pack_catalog.json` from the current state of all packs. Run after
merging to `main`. Preserves the `category` field on each pack entry.

```bash
python3 tools/build_pack_catalog.py
```

---

### `validate_pack_catalog.py`

Schema validation for `pack_catalog.json`. Run in the `json-integrity` CI job
on every PR.

```bash
python3 tools/validate_pack_catalog.py
```

---

### `validate_shadow_mode.py`

Checks that all Containment / Eradication / Recovery action entries in
`SOCFrameworkActions_V3` have `shadow_mode` set. Catches accidental production
flips.

```bash
python3 tools/validate_shadow_mode.py
```

---

### `ep_nist_dependency_map.py`

Generates a dependency map from an Entry Point playbook through the full NIST
IR lifecycle, crossing pack boundaries.

```bash
python3 tools/ep_nist_dependency_map.py \
  --root-pack Packs/soc-framework-nist-ir \
  --root-playbook-name "EP_IR_NIST (800-61)_V3" \
  --other-pack Packs/soc-optimization-unified
```

> ⚠️ The docstring incorrectly shows `--entry-name` — that argument does not
> exist. Use `--root-playbook-name` as above.

---

### `fix_errors.py`

Automated remediation of known SDK validation error patterns. Run only when
`pack_prep.py` step 5 surfaces errors that match known fixable patterns.

```bash
python3 tools/fix_errors.py Packs/soc-optimization-unified
```

---

### `upload_package.sh`

Deploys a pack zip to the dev tenant using environment credentials. Run after
`pack_prep.py` passes.

```bash
DEMISTO_BASE_URL=... DEMISTO_API_KEY=... XSIAM_AUTH_ID=... \
  bash tools/upload_package.sh Packs/soc-optimization-unified
```

---

## CI gate summary

| Job | Trigger | Tools run | Blocking? |
|---|---|---|---|
| `scan` | Every PR | Customer identifier scan | Yes |
| `detect` | Every PR | Version bump detection | Provides outputs |
| `json-integrity` | Every PR | `validate_pack_catalog.py`, `validate_xsoar_configs.py`, `check_dependency_versions.py --strict` | Yes |
| `validate` | Changed packs only | `normalize_ruleid_adopted.py`, `demisto-sdk validate` | Yes |
| `preflight` | Changed packs only | `preflight_xsoar_config.py` (full HTTP) | Yes |
| `prerelease` | Changed packs only | `demisto-sdk prepare-content`, GitHub release create | Yes |
| `deploy-dev` | Changed packs only | `xsiam-pov-automation/setup.py` | Yes |

Post-merge (`soc-packs-release.yml`): builds immutable production zip + GitHub
release tag only. **No post-merge tenant deploy** — that runs once, pre-merge,
in `deploy-dev`.

---

## Known backlog

| ID | Item |
|---|---|
| BL-001 | Dedup race condition (burst arrivals) — targeted 3.5.0 / 3.4.1 |
| BL-002 | BA106 on `Foundation_-_Upon_Trigger_V3.yml` and `Foundation_-_Enrichment_V3.yml` (pre-existing, blocks force-merge) |
| BL-003 | `validate_shadow_mode.py` not yet wired into `pack_prep.py` or CI |
| BL-004 | `check_dependency_versions.py`: legacy bare `.zip` id entries (`soc-optimization.zip`, `soc-microsoft-graph-security.zip`) cannot be version-checked — manual update required |
