# Contributing

How the framework is structured for safe, auditable contribution.

## The contribution model

The framework uses a **contract-driven** approach: schemas define what each
layer reads and writes, and the build pipeline enforces those contracts.
Adding a new vendor pack, modifying a phase, or extending the Foundation
all flow through the same checkpoints:

1. **Author the schema** — every vendor pack and contract gets a YAML
   schema under `schemas/`. The schema declares the pack's raw data shape,
   modeling rule, and correlation rules. See
   [`CONTRACT_DESCRIPTIONS.md`](https://github.com/Palo-Cortex/secops-framework/blob/main/CONTRACT_DESCRIPTIONS.md)
   for adding `description:` fields to contract entries.
2. **Generate the pack content** — `tools/` runs the contract generators
   that turn schema YAML into deployable XSIAM content.
3. **Validate** — `check_contracts.py`, `check_contribution.py`, and
   `validate_shadow_mode.py` enforce the gates.
4. **Submit** — one commit per pack, one PR per pack.

## Where to look

Until contributor docs are migrated into this section, the source-of-truth
references live at the repo root:

- **`CONTRIBUTING.md`** — high-level contribution flow
- **`PIPELINE_TOOLS.md`** — what each generator does
- **`PLAYBOOK_VALIDATION.md`** — how content is validated
- **`TOOLING.md`** — the full toolchain reference
- **`CONTRACT_DESCRIPTIONS.md`** — adding descriptions to schema entries

These will land here progressively as the docs migration completes.

## Drift gates

Three gates protect the framework from unintended drift:

- **`check_contracts.py`** — schemas must match generated artifacts
- **CI doc generation** — `git diff` fails the build if generated docs are
  stale; run the three doc generators locally before committing
- **`validate_shadow_mode.py`** — pre-commit hook enforcing safe-by-default

If a gate fails, the message tells you which generator to run. No magic.
