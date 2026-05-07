# SOC Framework

Opinionated, modular SOC content for Cortex XSIAM. Auditable end-to-end. Safe by default via Shadow Mode.

The SOC Framework provides a structured, contract-driven layer over XSIAM that
turns ad-hoc SecOps automation into something composable, testable, and
upgradable. Built on NIST IR 800-61, every alert flows through the same
lifecycle (Analysis → Containment → Eradication → Recovery), every action is
gated by Shadow Mode by default, and every pack inherits the same contracts.

The framework's three core values:

- **Auditable** — every framework action writes to a dataset; every phase
  surface is contractually defined; every value driver maps to a metric.
- **Modular** — vendor packs are interchangeable. Drop in a new EDR or email
  source and the lifecycle adapts.
- **Safe** — Shadow Mode is the default for every action. Flip a flag to go
  to production. No surprises.

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } **Get Started**

    ---

    Concepts, the alert flow, the lifecycle. Read this first.

    [Architecture →](architecture/index.md)

-   :material-foundation:{ .lg .middle } **Foundation**

    ---

    The two packs that define the framework: the contract layer and the
    NIST IR lifecycle.

    [Foundation →](foundation/index.md)

-   :material-package-variant:{ .lg .middle } **Packs**

    ---

    Vendor coverage — endpoint, email, identity, network. One reference page
    per data source.

    [Packs →](packs/index.md)

</div>
