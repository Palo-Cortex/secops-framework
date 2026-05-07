# Upon Trigger

The entry-point pattern — what playbook fires when an alert arrives, and why.

## The contract

Every alert that lands on the tenant runs an Upon Trigger playbook. The
framework uses **one** Upon Trigger playbook universally:
`EP_IR_NIST (800-61)_V3`. It's wired in via the Layout's "Upon Trigger"
field and runs for every alert the framework handles.

Upon Trigger is intentionally **dumb**. Its only job is to be the
deterministic entry point — the single doorway through which all alerts
walk. Routing, categorization, normalization, and lifecycle execution
all happen in playbooks that Upon Trigger calls. None of that logic lives
in Upon Trigger itself.

## Why one Upon Trigger, not many

Two reasons.

**Auditability.** When every alert enters through the same playbook, you
have one place to look when something doesn't run. There's no question of
"which trigger did this alert hit." The trigger is constant; only what
runs after it varies.

**Simpler swaps.** If you need to change how the framework starts —
add a pre-flight check, integrate a new analytics tool, gate on a kill
switch — you change one playbook. Not 15 vendor-specific triggers.

## What Upon Trigger does

`EP_IR_NIST (800-61)_V3` is the thinnest possible orchestrator:

1. Calls `Foundation_-_Set_Framework_Context_V3` to populate
   `SOCFramework.*` namespace from the alert's raw fields.
2. Resolves category via `SOCProductCategoryMap_V3`.
3. Calls `Foundation_-_Normalize_Artifacts_V3` to fan out to
   category-specific normalizers.
4. Hands off to the four NIST IR phase playbooks in sequence.

That's the whole list. No vendor-specific branches, no conditional
blocks. Vendor-specificity lives in the Normalize layer, not here.

## What never goes in Upon Trigger

- **Routing logic.** That's `SOCExecutionList_V3` and the Branch
  Execution pattern. Upon Trigger doesn't decide what to skip.
- **Vendor checks.** Vendor specifics belong in the per-vendor normalize
  playbooks. Foundation should never branch on `vendor == "X"`.
- **Direct field reads.** Only Foundation playbooks may read `issue.*`
  fields. Downstream lifecycle playbooks read `SOCFramework.*` — that's
  the contract boundary.
- **Anything that requires reading user input.** Upon Trigger fires
  before any human is in the loop.

## Where this fits

Upon Trigger is one of three doorways in the framework:

- **Upon Trigger** — fires when an alert is created. Always
  `EP_IR_NIST (800-61)_V3`.
- **Pre-process Rules** — XSIAM-native; fire before the alert exists.
  Used for de-dup and field stamping. Outside the framework's scope.
- **Triggers (Layout-bound)** — fire on field changes during a case.
  Rarely used; mostly for analyst-driven escalations.

The framework lives entirely in Upon Trigger and what it calls.
