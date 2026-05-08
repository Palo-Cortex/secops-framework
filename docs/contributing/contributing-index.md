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
   [Editing Vendor Contracts](editing-vendor-contracts.md) for the
   full walkthrough, and
   [`CONTRACT_DESCRIPTIONS.md`](https://github.com/Palo-Cortex/secops-framework/blob/main/CONTRACT_DESCRIPTIONS.md)
   for adding `description:` fields to contract entries.
2. **Generate the pack content** — `tools/` runs the contract generators
   that turn schema YAML into deployable XSIAM content. See the
   [Tooling Reference](tooling.md) for every script and what it does.
3. **Validate** — `check_contracts.py`, `check_contribution.py`, and
   `validate_shadow_mode.py` enforce the gates.
4. **Submit** — one commit per pack, one PR per pack.

## Guides in this section

- **[Editing Vendor Contracts](editing-vendor-contracts.md)** — how to read
  and edit the YAML files under `schemas/vendors/`, with worked examples
  of common edit patterns (grouping pivots, alert-field additions, XDM
  mappings).
- **[Tooling Reference](tooling.md)** — every script in `tools/` organized
  by lifecycle phase (authoring, validation, replay, push & test,
  versioning, docs, CI).

## Where else to look

Source-of-truth references at the repo root, pending migration into this section:

- **`CONTRIBUTING.md`** — high-level contribution flow
- **`PIPELINE_TOOLS.md`** — what each generator does
- **`PLAYBOOK_VALIDATION.md`** — how content is validated
- **`CONTRACT_DESCRIPTIONS.md`** — adding descriptions to schema entries

These will land here progressively as the docs migration completes.

## Drift gates

Three gates protect the framework from unintended drift:

- **`check_contracts.py`** — schemas must match generated artifacts
- **CI doc generation** — `git diff` fails the build if generated docs are
  stale; run the three doc generators locally before committing
- **`validate_shadow_mode.py`** — pre-commit hook enforcing safe-by-default

If a gate fails, the message tells you which generator to run. No magic.
