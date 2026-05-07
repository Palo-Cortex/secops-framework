# Universal Command & Shadow Mode

How every action in the framework is gated, and how to flip from preview
to production.

## Universal Command

The framework never invokes vendor commands directly. Every containment,
eradication, or recovery action goes through a single wrapper script:
**`SOCCommandWrapper`**.

When a phase playbook needs to "isolate the host" or "reset the user
password," it calls `SOCCommandWrapper` with an action name like
`soc-isolate-host` or `soc-reset-password`. The wrapper:

1. Looks up the action in `SOCFrameworkActions_V3` to find which vendor
   integration handles it
2. Reads the `shadow_mode` flag for that action
3. Either executes the vendor command (production) or writes a
   simulated entry to the warroom and dataset (shadow mode)
4. Writes the execution record to `xsiam_socfw_ir_execution_raw`

This indirection is the framework's most important single design
choice. It lets every alert show the *full* lifecycle that would run —
including which actions would have fired against which assets — without
touching anything in the customer's environment until they're ready.

## Shadow Mode

Shadow Mode is the framework's safe-by-default execution mode. When an
action's `shadow_mode` flag is `true`:

- The wrapper logs what *would* have happened to the warroom
- The execution dataset captures the action as if it ran
- Downstream playbooks see a "success" response and continue
- The vendor integration is never called

When the flag is `false`, the wrapper actually executes the vendor
command. Same code path either side; just one boolean flips.

## The single source of truth

Shadow mode is set in **one place**: `SOCFrameworkActions_V3`, per
action. Every action has its own `shadow_mode: true|false`.

```
SOCFrameworkActions_V3
├── soc-isolate-host       → shadow_mode: true
├── soc-reset-password     → shadow_mode: true
├── soc-revoke-tokens      → shadow_mode: true
├── soc-block-domain       → shadow_mode: true
└── ...
```

`SOCCommandWrapper` reads this list directly. **It does not read
`args.shadow_mode` from the calling playbook** — that argument is
preserved only for backward compatibility and is ignored. The list is
authoritative.

This has one important consequence: **flipping a pack to production is
one edit per action**. There's no script to run, no dashboard to update,
no environment variable to flip. You change the boolean in
`SOCFrameworkActions_V3` and the next time the action runs it executes
for real.

## What Shadow Mode is NOT

- **Not** controlled by `SOCExecutionList_V3`. That list controls
  *which branch* of a phase playbook runs (branch execution / skip
  logic). It has nothing to do with whether a vendor command actually
  fires.
- **Not** a global toggle. There's no master switch. Every action
  is independently flag-able. This is intentional — production rollouts
  proceed action-by-action as confidence builds.
- **Not** a development feature. Shadow mode is a *deployment* feature.
  PoVs run entirely in shadow. Production rollouts flip actions over
  as the customer signs off on each one.

## A typical rollout

A common deployment pattern:

1. **Day 0** — pack installed, all actions in shadow mode. Lifecycle
   runs end-to-end on real alerts; nothing actually changes.
2. **Week 1** — analyst reviews the shadow execution log, confirms the
   right actions fire on the right alerts. Customer signs off.
3. **Phase 1 production** — flip the lowest-risk actions (e.g.,
   logging-only ACL adds, tag-only quarantines). Eradication and
   Recovery stay in shadow.
4. **Phase 2 production** — flip Containment actions (host isolation,
   user disable). Eradication still in shadow.
5. **Phase 3 production** — flip Eradication and Recovery.

Each step is one edit per action in `SOCFrameworkActions_V3`. The
playbooks don't change. The contracts don't change. Only the boolean.

## Where to look in the dataset

Every wrapper invocation writes to `xsiam_socfw_ir_execution_raw` with
an `execution_mode` field set to either `shadow` or `production`. The
[Value Metrics](value-metrics.md) dashboards pivot on this field — there
are two dashboards, one filtered to shadow and one to production, so
you can watch the same lifecycle behavior with and without the actions
firing.
