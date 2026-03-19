# SOC Framework — Tooling & CI Reference

This document covers the local development workflow, every tool in `tools/`, and the two CI pipelines. It is the single source of truth for how content moves from your editor to a customer tenant.

---

## Daily Workflow (Short Version)

```
Edit content
  → pack_prep.py          # normalize + validate
  → fix_errors.py         # fix what SDK reported  (only if errors)
  → upload_package.sh     # push directly to your dev tenant
  → (repeat until clean)

Ready to deploy to QA?
  → bump_pack_version.py  # increment version — this triggers CI
  → git commit + push PR  # CI builds, validates, deploys to QA tenant

Ready to update PoV Companion / Package Manager?
  → build_pack_catalog.py # update pack_catalog.json
  → commit pack_catalog.json
```

---

## Tool Reference

### `pack_prep.py` — Normalize and validate a pack

**What it does:**
1. Runs `normalize_ruleid_adopted.py --fix` on the pack to enforce correlation rule IDs, `adopted: true` on playbooks, correct `packID` in `contentitemfields`, and required pack root files.
2. Runs `demisto-sdk validate -i <pack>` and appends all output to `output/sdk_errors.txt`.
3. Exits non-zero if validation fails.

**Usage:**
```bash
python3 tools/pack_prep.py Packs/<PackName>

# Examples
python3 tools/pack_prep.py Packs/soc-framework-nist-ir
python3 tools/pack_prep.py Packs/soc-optimization-unified
```

**Run this every time you add or change content.** It is the required first step before uploading. The CI `validate` job runs the same steps — if `pack_prep.py` passes locally, the CI job should pass too.

**Output:**
- `output/sdk_errors.txt` — SDK validation output. Created on first error; appended on subsequent runs. Clear it between sessions if you want a clean log.
- Exit code `0` = clean. Exit code `1` = errors written to `sdk_errors.txt`.

---

### `fix_errors.py` — Auto-fix SDK validation errors

**What it does:**

Reads `output/sdk_errors.txt` line by line and automatically repairs known error categories. There are two pass types:

**Pre-flight (manual fix required — no auto-repair possible):**

| Condition | What to do |
|---|---|
| Pydantic `ValidationError` block | A List descriptor `.json` file is missing one or more required fields. Fix the descriptor manually. Required fields: `id`, `name`, `display_name`, `type` — all must match the list name exactly. |
| List descriptor scan | Walks all `Packs/**/Lists/**/*.json` (non-`_data.json`) files and prints specific paths and missing fields. |

**Per-line auto-fixes:**

| Error code | What gets fixed |
|---|---|
| Parsing error (`NoneType`) | JSON Dashboard/Layout with `null` array fields — set to `[]`. |
| Layout group `"alert"` / `"incidents"` | Changed to `"incident"`. |
| `PA128` | Creates missing `.secrets-ignore`, `.pack-ignore`, and `README.md` in the pack root. |
| `BA101` | Sets `id` equal to `name` (textual edit only — YAML is never re-serialized). |
| `BA106` | Bumps `fromversion` to the minimum required value (textual for YAML, structured edit for JSON). |
| `BA102` | Runs `demisto-sdk format --assume-yes` on the file. **Skipped for Script YAMLs** (files containing embedded Python) — prints a manual fix instruction instead to avoid corrupting indentation in `script: |-` blocks. |

**Usage:**
```bash
python3 tools/fix_errors.py output/sdk_errors.txt

# Dry run — shows what would change without writing files
python3 tools/fix_errors.py output/sdk_errors.txt --dry-run
```

**Typical loop:**
```bash
python3 tools/pack_prep.py Packs/<PackName>   # run SDK, write sdk_errors.txt
python3 tools/fix_errors.py output/sdk_errors.txt  # auto-fix what it can
python3 tools/pack_prep.py Packs/<PackName>   # re-run — repeat until clean
```

**What it will not fix:**
- Pydantic errors (no file path available in SDK output — find the file manually from the pre-flight scan).
- BA102 on Script YAMLs (embedded Python — fix the specific field manually).
- Errors not matched by its regex patterns (review `sdk_errors.txt` directly for anything not reported as fixed).

---

### `upload_package.sh` — Upload a pack directly to your dev tenant

**What it does:**

Runs `demisto-sdk upload` with the correct flags for XSIAM:
- `--marketplace marketplacev2` — required for XSIAM; omitting this causes silent skip with no error.
- `-x` (`--insecure`) — bypasses SSL verification for lab/dev tenants.
- `-z` (`--zip`) — packages the pack before upload.
- `--console-log-threshold DEBUG` — verbose output so you can see exactly what was skipped or rejected.

**Usage:**
```bash
bash tools/upload_package.sh Packs/<PackName>

# Or run without an argument — it will prompt you
bash tools/upload_package.sh
```

**Prerequisites:** `DEMISTO_BASE_URL` and `DEMISTO_API_KEY` (or `XSIAM_AUTH_ID`) must be set in your environment or `.env`. The script changes to the git root automatically so relative paths resolve correctly.

**When to use:** After `pack_prep.py` passes cleanly. This is your inner-loop shortcut — faster than waiting for CI to deploy.

---

### `bump_pack_version.py` — Increment pack version and update all URLs

**What it does:**

1. Prompts you to choose a version bump type:
   - `R` (Revision) — backwards compatible bug fix → `X.Y.Z+1`
   - `M` (Minor) — new backwards compatible functionality → `X.Y+1.0`
   - `J` (Major) — breaking changes or significant additions → `X+1.0.0`
2. Updates `pack_metadata.json` with the new version.
3. Updates `xsoar_config.json`:
   - `version` field (top-level, if present)
   - `custom_packs[].url` — regenerated from the pack directory name and new version
   - `custom_packs[].id` — regenerated to match the zip filename
   - `pre_config_docs[].url` / `post_config_docs[].url` — corrected to point at the current repo and pack directory

The pack directory name is the source of truth for the zip URL. If the directory was ever renamed, `bump_pack_version.py` will silently correct the stale name in `xsoar_config.json`.

**Usage:**
```bash
python3 tools/bump_pack_version.py Packs/<PackName>

# Example
python3 tools/bump_pack_version.py Packs/SocFrameworkCrowdstrikeFalcon
```

**This is the trigger for CI deployment to QA.** The PR gate detects a version change in `pack_metadata.json` and runs the full validation + deploy pipeline. Without a version bump, CI skips the pack even if you changed content inside it.

**After running:**
```bash
git add Packs/<PackName>/pack_metadata.json Packs/<PackName>/xsoar_config.json
git commit -m "Bump <PackName> to vX.Y.Z"
# Then open a PR — CI takes it from here
```

---

### `build_pack_catalog.py` — Rebuild the pack catalog

**What it does:**

Walks every directory under `Packs/` that contains a `pack_metadata.json` and writes `pack_catalog.json` at the repo root. Used by the PoV Companion and Package Manager to discover available packs and their install URLs.

For each pack it captures:
- `id` — the directory name under `Packs/`
- `display_name` — from `pack_metadata.json`
- `version` — from `pack_metadata.json`
- `path` — relative path to the pack directory
- `visible` — preserved from the existing catalog if present; defaults to `false` for new packs
- `xsoar_config` — raw `githubusercontent.com` URL to `xsoar_config.json` if the file exists, otherwise `null`

**Usage:**
```bash
python3 tools/build_pack_catalog.py

# Optional overrides (defaults are correct for this repo)
python3 tools/build_pack_catalog.py \
  --packs-dir Packs \
  --catalog pack_catalog.json \
  --org Palo-Cortex \
  --repo secops-framework \
  --ref refs/heads/main
```

**Run this after a version bump is merged** to update the catalog so PoV Companion and Package Manager see the new version. Commit the resulting `pack_catalog.json`.

**Catalog updates are always manual.** Run this after a version bump is merged, then commit `pack_catalog.json`. There is no CI automation for the catalog — see backlog.

---

### `validate_playbooks.py` — Playbook integrity check (on-demand)

Validates integration references, orphaned playbooks, missing lists, and sub-playbook dependency chains across all packs. Run this when adding a new playbook or wiring a new integration to catch missing `xsoar_config.json` entries before upload.

```bash
python3 tools/validate_playbooks.py --root Packs/soc-optimization-unified
```

Full documentation in `PLAYBOOK_VALIDATION.md`.

---

### `validate_shadow_mode.py` — PoV safety check (pre-commit, local only)

Checks that every C/E/R (Containment, Eradication, Recovery) playbook is correctly wired for action-list shadow mode. Intended as a local pre-commit guard, not a CI gate.

```bash
python3 tools/validate_shadow_mode.py --all \
  --actions-list Packs/soc-optimization-unified/Lists/SOCFrameworkActions_V3/SOCFrameworkActions_V3_data.json
```

This is also configured in `.pre-commit-config.yaml` and runs automatically on `git commit` if you have pre-commit installed (`pip install pre-commit && pre-commit install`).

---

## CI Pipeline Reference

Two workflows live in `.github/workflows/`. They are complementary — the PR gate validates before merge, the release workflow promotes after merge.

---

### `soc-packs-pr-gate.yml` — Runs on every PR targeting `main`

All jobs must pass before the PR can be merged.

**Trigger:** `pull_request` → `main` (opened, synchronize, reopened)

**Change detection:** The pipeline only processes packs where `pack_metadata.json` version changed relative to `main`. Unchanged packs are skipped entirely. This means **a version bump is required for CI to pick up your changes**.

| Job | Depends on | What it does |
|---|---|---|
| `scan` | — | Diffs the PR against `main` and checks for patterns listed in `Lists/customer-identifiers.json`. Blocks if any customer-specific data is found. |
| `detect` | — | Finds packs with a version bump. Outputs the pack list for downstream jobs. If no packs changed, all downstream jobs are skipped. |
| `validate` | detect | Runs `normalize_ruleid_adopted.py --fix` then `demisto-sdk validate` on each changed pack. Same logic as `pack_prep.py`. |
| `preflight` | detect, validate | Runs `preflight_xsoar_config.py` — checks `xsoar_config.json` zip URL format and doc URL reachability. |
| `prerelease` | detect, preflight | Builds a zip via `demisto-sdk prepare-content --marketplace marketplacev2`. Creates an ephemeral GitHub prerelease tagged `<PackName>-v<version>-pr<number>`. Also uploads a modified `xsoar_config.json` pointing at the prerelease zip URL. |
| `deploy-dev` | detect, prerelease | Deploys to the QA tenant using the prerelease `xsoar_config.json` URL. Uses the `xsiam-pov-automation` helper repo. |

**Prerelease tags** are ephemeral. Every push to the PR overwrites them. They are superseded when the PR merges and the release workflow creates the real immutable tag.

---

### `soc-packs-release.yml` — Runs on push to `main`

**Trigger:** `push` → `main` (post-merge)

**Skip flags:** Commits with `[skip ci]` or `[skip release]` in the message bypass the release job entirely.

| Job | Depends on | What it does |
|---|---|---|
| `release` | — | Same change detection as the PR gate. Builds zip, creates an immutable GitHub release tagged `<PackName>-v<version>`. This is the production artifact. |
| `deploy` | release | Deploys the immutable release to the tenant. |
| ~~`catalog`~~ | ~~release, deploy~~ | **Dead — do not use.** References `tools/update_pack_catalog.py` which does not exist. Job will fail at runtime if the `pack-catalog-gate` approval is ever granted. See backlog. |

---

## Environment Variables and Secrets

| Variable | Used by | Purpose |
|---|---|---|
| `DEMISTO_BASE_URL` | upload_package.sh, deploy jobs | Your XSIAM tenant URL |
| `DEMISTO_API_KEY` | upload_package.sh, deploy jobs | API key for the tenant |
| `XSIAM_AUTH_ID` | deploy jobs (CI) | Advanced auth ID for XSIAM API |
| `DEMISTO_SDK_IGNORE_CONTENT_WARNING` | all SDK calls | Suppresses non-fatal SDK warnings that would otherwise pollute logs |
| `GH_TOKEN` / `GITHUB_TOKEN` | prerelease, release jobs | GitHub token for creating releases |

For local use, set `DEMISTO_BASE_URL` and `DEMISTO_API_KEY` in your shell or a `.env` file. `upload_package.sh` picks these up automatically via the SDK.

---

## Common Issues

**`output/sdk_errors.txt` keeps growing**

The file is appended to, not overwritten. Delete or truncate it between sessions:
```bash
rm output/sdk_errors.txt
```

**CI skipped my pack even though I changed content**

The pipeline detects changes by comparing `pack_metadata.json` version between the PR branch and `main`. If the version didn't change, the pack is skipped. Run `bump_pack_version.py` and re-push.

**`demisto-sdk upload` succeeded but content didn't appear in the tenant**

The most common cause is a missing `--marketplace marketplacev2`. The SDK silently skips XSIAM-incompatible content without this flag. `upload_package.sh` always includes it.

**BA102 was not auto-fixed on a Script YAML**

`fix_errors.py` intentionally skips `demisto-sdk format` on any YAML containing embedded Python (`script: |-` or `type: python`). Running format on these files can corrupt indentation in the script block, breaking the automation. Fix the BA102 error manually in the specific field the SDK flagged.

**Pydantic `ValidationError` from a List descriptor**

The SDK emits these before per-file error lines with no file path. The pre-flight scan in `fix_errors.py` will identify the specific `.json` descriptor file missing required fields. All four fields are required and must be non-null: `id`, `name`, `display_name`, and `type`.

---

## Backlog

Known issues and deferred cleanup work. These are not blocking current PoV delivery but should be addressed before the tooling is used by anyone outside this project.

---

### BL-001 · Remove dead `catalog` job from `soc-packs-release.yml`

**File:** `.github/workflows/soc-packs-release.yml`

The `catalog` job (Job 3) references `tools/update_pack_catalog.py`, which does not exist. The script was part of an earlier design that automated catalog updates on every merge. That approach caused Git flow instability and was abandoned. The job was never removed from the workflow.

**Risk:** If someone approves the `pack-catalog-gate` environment gate in GitHub, the job will fire and immediately fail with a missing file error. No functional harm — the deploy has already succeeded by that point — but it will generate a confusing pipeline failure.

**Fix:** Delete the `catalog` job block from `soc-packs-release.yml` and remove `pack-catalog-gate` from the GitHub environments list.

---

### BL-002 · `validate_shadow_mode.py` has edge cases that silently pass

**File:** `tools/validate_shadow_mode.py`

The script has five gaps identified during review. None of these break current behavior because the runtime architecture (SOCCommandWrapper reading from the action list) is the real enforcement layer. These gaps only matter if the script is ever relied on as a hard guarantee.

**Gap 1 — `UNKNOWN_ACTION` skips Check 3 silently**
If a UC task has no `action` argument, or uses a `complex` expression instead of `simple`, the action resolves to `UNKNOWN_ACTION` and the action-list registration check is skipped entirely. The task reaches the wrapper at runtime with no `shadow_mode` entry to read.

**Gap 2 — Actions list load failure is a soft warning, not a hard exit**
If the path to `SOCFrameworkActions_V3_data.json` is wrong or the file is missing, `load_actions_list` returns an empty dict and prints a warning. Because Check 3 only runs when `actions_map` is truthy, the entire check is silently skipped for every file. The most important check becomes optional by accident.

**Gap 3 — `shadow_mode` presence is checked but not value**
An action entry with `"shadow_mode": "false"` passes Check 3. For C/E/R actions in a PoV context the value needs to be `"true"`, not just the key to exist.

**Gap 4 — Filename-only classifier misses non-standard names**
`is_cer_playbook` matches on `Containment`, `Eradication`, or `Recovery` in the filename. A containment action named without one of those words (e.g., `SOC_Endpoint_Block_V3.yml`) is invisible to the scanner. The script has no awareness of the playbook's YAML `type` field or call hierarchy position.

**Gap 5 — SOCCommandWrapper detection is fragile to YAML normalization**
The wrapper is detected by checking `task.scriptName` and `task.script` for the string `SOCCommandWrapper`. After `demisto-sdk` normalization rewrites a playbook, the field structure can change and the detection can miss the task.

**Fix:** Address Gaps 1–3 in the script (straightforward). Accept Gaps 4–5 as limitations of static filename analysis and document them. The script is most valuable as a local pre-commit check, not a CI hard gate.

---

### ~~BL-003~~ ✅ RESOLVED · Shadow mode job removed from `soc-packs-pr-gate.yml`

The `shadow-mode` job (formerly Job 5) has been removed from `soc-packs-pr-gate.yml`. The `prerelease` job `needs` is restored to `[detect, preflight]` and jobs are renumbered 1–6. The `validate_shadow_mode.py` script remains wired as a pre-commit hook in `.pre-commit-config.yaml` for local use.

---

### BL-004 · `output/sdk_errors.txt` is appended-to, never cleared by tooling

**File:** `tools/pack_prep.py`, `output/sdk_errors.txt`

`pack_prep.py` appends SDK output to `output/sdk_errors.txt` on every run. There is no automated truncation. Over time the file accumulates errors from multiple sessions and packs, making it harder to read and causing `fix_errors.py` to attempt repairs on stale entries that no longer correspond to actual files.

**Risk:** Low — `fix_errors.py` skips missing files gracefully. But a stale log can print misleading output and makes debugging harder.

**Fix:** Either truncate the file at the start of each `pack_prep.py` run, or write per-pack named files (e.g., `output/sdk_errors_<PackName>.txt`) so runs don't bleed into each other.
