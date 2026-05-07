# Foundation

The Foundation tier is the framework itself. Two packs define how everything
above them works:

- **`soc-optimization-unified`** — the Foundation layer. Universal Command,
  the normalizer pattern, Shadow Mode wiring, lookup tables, dashboards.
  Every other pack depends on this one.

- **`soc-framework-nist-ir`** — the NIST IR 800-61 lifecycle. Analysis,
  Containment, Eradication, Recovery — implemented as parallel phase
  playbooks that read and write a contractually-defined namespace.

These packs ship together. They define the rails; vendor packs ride them.

## Why two packs

The split exists because the Foundation layer is *infrastructure* — it
doesn't know anything about specific products or attack categories. The NIST
IR pack is *opinion* — it implements one specific lifecycle on top of that
infrastructure. Splitting them lets a customer with a different lifecycle
model swap out the IR pack while keeping the Foundation.

## When to read these

- **Adding a new vendor pack** — read `SOCFrameworkNormalizeMap_V3` to know
  what fields your pack must populate and where they go.
- **Modifying a phase** — read `SOCFrameworkPhaseContract_V3` to see what
  every phase reads and writes. Don't break the contract.
- **Building dashboards** — the active dataset is `xsiam_socfw_ir_execution_raw`,
  populated by `SOCCommandWrapper`. Categories come from `SOCActionTimeMap_V3`.
