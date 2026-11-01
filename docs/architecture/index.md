# Architecture

How an alert moves through the framework and the lifecycle on top of it: the alert flow, Upon Trigger, entry points, Auto Triage, the universal command with Shadow Mode, and the value metrics every action feeds.

These pages predate the capability reference and describe the mechanisms end to end; for the switch, the steps and the verify block of one capability, use [Reference](../reference/index.md).

- [Alert flow](alert-flow.md): ingest to lifecycle, step by step.
- [Upon Trigger](upon-trigger.md): the Foundation chain that runs on every alert.
- [Entry points](entry-points.md): how a lifecycle is started.
- [Auto Triage](auto-triage.md): the scheduled close of low-signal cases.
- [NIST IR lifecycle](nist-ir-lifecycle.md): the phases and what each reads and writes.
- [Universal Command and Shadow Mode](universal-command-shadow-mode.md): one interface for every vendor action.
- [Value metrics](value-metrics.md): what the execution dataset measures.
- [Cross-lifecycle surfaces](cross-lifecycle-surfaces.md): what the framework and a lifecycle share, tiered by blast radius.
