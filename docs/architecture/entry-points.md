# Entry Points

The inventory of `EP_*` playbooks and their categories.

## What an Entry Point playbook is

An Entry Point (EP) playbook is the **named doorway** for a specific
lifecycle into the framework. Today there's exactly one in production:

- **`EP_IR_NIST (800-61)_V3`** — the NIST IR 800-61 lifecycle entry point

This playbook is what Upon Trigger references on every alert layout. When
the alert is created, this playbook fires.

## Why call it an "Entry Point" if there's only one

Two reasons it's parameterized this way:

**Future lifecycle support.** The framework's structural separation
between Foundation and NIST IR (see [Foundation](../foundation/index.md))
exists precisely so a different lifecycle can plug in. A future
`EP_IR_SANS_V3` or `EP_PostureManagement_V3` would be a peer to
`EP_IR_NIST (800-61)_V3`, sharing the same Foundation but implementing
a different phase model. Naming the doorway makes that swap clean.

**Disambiguation in logs.** When the dataset shows `playbook_name =
"EP_IR_NIST (800-61)_V3"`, you know unambiguously which lifecycle ran.
If multiple lifecycles existed, the dataset would still answer "which
one fired" without inferring it from the action chain.

## What goes inside an EP playbook

EP playbooks are **slim orchestrators**. They:

- Set up the framework context (`Foundation_-_Set_Framework_Context_V3`)
- Resolve product category
- Normalize artifacts (`Foundation_-_Normalize_Artifacts_V3`)
- Call the lifecycle phase playbooks in sequence

They do **not** contain routing decisions, conditional branches, or
vendor-specific logic. All four of those concerns live in lower layers:

- Routing → `SOCExecutionList_V3`
- Categorization → `SOCProductCategoryMap_V3`
- Vendor specifics → per-product Normalize playbooks
- Action gating → Shadow Mode in `SOCFrameworkActions_V3`

## How to find them

Search the `soc-framework-nist-ir` pack for files matching `EP_*.yml`.
Currently:

```
Packs/soc-framework-nist-ir/Playbooks/EP_IR_NIST_(800-61)_V3.yml
```

The filename uses underscores; the playbook `id` and `name` use spaces
(`"EP_IR_NIST (800-61)_V3"`). Both forms appear depending on where you
look. If you're searching XSIAM logs, use the spaced form.

## Adding a new EP playbook

If you need a new lifecycle:

1. Create a new pack under `Packs/` (e.g., `soc-framework-posture`).
2. Add an `EP_*` playbook that orchestrates the new phase model.
3. Implement the phase playbooks the EP calls.
4. Register the EP in any layouts that should use the new lifecycle.

The Foundation pack does not change. That's the value of this split.
