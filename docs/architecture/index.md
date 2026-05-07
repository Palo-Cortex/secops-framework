# Architecture

The framework's structural concepts: how alerts flow, how phases hand off,
where Shadow Mode kicks in, what the Universal Command does, and how value
metrics roll up.

## Read in this order

If you're new to the framework, read these in order. Each builds on the
previous one. Each is short — under 5 minutes — and stands alone if you
just need the one concept.

1. **[Alert Flow](alert-flow.md)** — the five-stage path from raw vendor
   event to closed alert. The mental model that makes everything else
   make sense.
2. **[Upon Trigger](upon-trigger.md)** — the single doorway every alert
   walks through. Why the framework uses one entry point and not many.
3. **[Entry Points](entry-points.md)** — the inventory of `EP_*`
   playbooks. Today there's one; the slot exists for the next lifecycle.
4. **[Auto Triage](auto-triage.md)** — the fast pre-filter that decides
   which alerts deserve the full lifecycle and which close immediately.
5. **[NIST IR Lifecycle](nist-ir-lifecycle.md)** — the four phases:
   Analysis, Containment, Eradication, Recovery. What each phase does
   and how they hand off via the phase contract.
6. **[Universal Command & Shadow Mode](universal-command-shadow-mode.md)** —
   how every action is gated. The single boolean that flips a pack from
   preview to production.
7. **[Value Metrics](value-metrics.md)** — MTTD/MTTC/MTTE/MTTR, the two
   dashboards, and the dataset that drives them.

## Read by need

If you're solving a specific problem:

- *"An alert came in but nothing ran"* — start with [Upon Trigger](upon-trigger.md)
  and [Entry Points](entry-points.md)
- *"The lifecycle ran but didn't do anything"* — [Universal Command &
  Shadow Mode](universal-command-shadow-mode.md). Probably what you want.
- *"How do I prove value to the customer?"* — [Value Metrics](value-metrics.md)
- *"Why does the framework care about CIA scores?"* — [Auto Triage](auto-triage.md)
- *"What does each NIST IR phase actually do?"* — [NIST IR Lifecycle](nist-ir-lifecycle.md)

## How these docs relate to the schemas

Architecture docs explain *why* things are shaped the way they are. The
[Foundation](../foundation/index.md) schema docs define *exactly* what
each phase reads and writes, field by field. When the schema and the
prose diverge, the schema is authoritative.
