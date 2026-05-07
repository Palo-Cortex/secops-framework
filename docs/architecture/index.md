# Architecture

The framework's structural concepts: how alerts flow, how phases hand off,
where Shadow Mode kicks in, what the Universal Command does, and how value
metrics roll up.

!!! note "Migration in progress"

    The architecture topic prose (Alert Flow, Upon Trigger, Entry Points,
    Auto Triage, Value Metrics) is currently in `docs/soc-optimization/`,
    which is being decommissioned. Topics will move into this section as
    they're updated for the current framework version.

    For now, the most accurate references are the schema docs themselves —
    they describe the contracts the architecture implements:

    - [`SOCFrameworkPhaseContract_V3`](../soc-framework-nist-ir/SOCFrameworkPhaseContract_V3.md) — the NIST IR phase contract
    - [`SOCFrameworkNormalizeMap_V3`](../soc-optimization-unified/SOCFrameworkNormalizeMap_V3.md) — Foundation normalizer outputs

## Core concepts (planned topics)

- **Alert Flow** — how alerts enter the framework, what runs on them, and where they exit
- **Upon Trigger** — the entry-point pattern; what playbooks fire and why
- **Entry Points** — the inventory of `EP_*` playbooks and their categories
- **Universal Command & Shadow Mode** — how every action is gated; how to flip to production
- **NIST IR Lifecycle** — Analysis → Containment → Eradication → Recovery; phase contracts
- **Value Metrics** — MTTD/MTTC/MTTE/MTTR, dashboards, the `xsiam_socfw_ir_execution_raw` dataset

These will land here as the soc-optimization-unified pack is fully documented.
