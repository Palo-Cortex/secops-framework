# SOC Framework

Opinionated, modular, production-grade SOC content built on Cortex XSIAM. Aligned to NIST IR 800-61.

The framework is the answer to two field failure modes: leading with migration
narratives instead of outcomes, and pitching every XSIAM capability instead of
a scoped PoV. It gives DCs an opinionated starting point and gives PS a clean
inheritance path.

## How the docs are organized

**Architecture** — How the framework thinks. Alert flow, Upon Trigger,
NIST IR lifecycle, Universal Command and Shadow Mode, Blue/Green deployment,
Value Metrics. Start here if you're new.

**Contracts** — The contract schemas that govern what each layer reads and
writes. `SOCFrameworkNormalizeMap_V3` defines the per-category Foundation
normalizer outputs. `SOCFrameworkPhaseContract_V3` defines what each NIST IR
phase produces.

**Vendor Packs** — One reference page per vendor data source. Documents the
raw schema, modeling rule field mappings, and correlation rules. Generated
from `schemas/vendors/<vendor>/<source>.yaml` — drift-checked in CI.

**Contributing** — How to submit a PR, what gets validated, multi-file edit
patterns, component design guide.

## Source of truth

Schemas under `schemas/` are the source of truth. Pages under **Contracts**
and **Vendor Packs** are generated from those schemas by
`tools/generate_schema_docs.py` and re-rendered on every push. Hand-editing
those pages is a no-op — they get overwritten.

Hand-authored prose lives under **Architecture** and **Contributing** and is
edited directly in `docs/`.
