# NIST IR Lifecycle

The four-phase response model the framework implements:
**Analysis → Containment → Eradication → Recovery**.

## What this is

The framework's lifecycle implements [NIST SP 800-61 Rev 2](https://csrc.nist.gov/pubs/sp/800/61/r2/final),
the standard incident response framework. Every alert that walks through
the framework runs through these four phases in order, with optional
human gates between them.

The phases live in the `soc-framework-nist-ir` pack as four parallel
playbooks. Each phase has a defined contract — what it must read from
prior phases, what it must write for downstream phases — captured in
[`SOCFrameworkPhaseContract_V3`](../soc-framework-nist-ir/SOCFrameworkPhaseContract_V3.md).

## The four phases

### Analysis

**Question answered:** "What is this, and is response warranted?"

Analysis hydrates the alert with everything needed to make a decision.
That includes querying threat intel, scoring MITRE technique
relevance, pulling related events, and computing a verdict
(`malicious` / `benign` / `suspicious` / `unknown`). It also computes
two derived scores:

- **`response_recommended`** — boolean gate downstream phases read
- **`compromise_level`** / **`spread_level`** — magnitude inputs

Analysis writes its outputs to the `Analysis.*` namespace. These are
the *only* fields downstream phases are allowed to read from Analysis.

### Containment

**Question answered:** "Stop the bleeding. Where?"

Containment runs only if Analysis wrote `response_recommended: true`.
It picks the right containment actions based on the alert's category:

- Endpoint → host isolation
- Identity → token revocation, session clearance
- Email → message quarantine, sender block
- Network → ACL block, domain sinkhole

All actions go through `SOCCommandWrapper` and respect the per-action
Shadow Mode flag. See [Universal Command & Shadow Mode](universal-command-shadow-mode.md).

Containment writes `Containment.attempted` and per-action result fields
to the namespace. It does *not* delete or destroy anything — that's
Eradication's job. Containment is reversible.

### Eradication

**Question answered:** "Remove the threat. What's the kill list?"

Eradication runs only if Containment succeeded. It performs the
destructive actions: password resets, account disables, malware
removal, persistent-mechanism cleanup. These are typically irreversible
or require explicit user re-onboarding to undo.

Eradication never *discovers* artifacts on its own. Analysis owns all
artifact hydration; Eradication just acts on what Analysis already
identified. This invariant keeps the lifecycle's data flow strictly
top-down.

### Recovery

**Question answered:** "Bring the user / asset / service back online."

Recovery is the inverse of Containment + Eradication. Re-enable the
disabled user. Take the host out of isolation. Restore the quarantined
message if it was a false positive. Like Containment, Recovery is
gated — it runs only if Eradication wrote `attempted: true`.

## How the phases hand off

Each phase reads from two sources:

- **`SOCFramework.*`** — Foundation's normalized artifacts (host, user,
  hashes, MITRE, etc.)
- **`<PriorPhase>.*`** — outputs from earlier phases in the lifecycle

The exact field-by-field contract is documented in
[`SOCFrameworkPhaseContract_V3`](../soc-framework-nist-ir/SOCFrameworkPhaseContract_V3.md).
The contract is *enforced* — the build pipeline runs `check_contracts.py`
to confirm phase playbooks read only from declared sources and write only
to declared targets.

## The Phase Gate

Between phases, an optional **Phase Gate** can pause the lifecycle for
analyst decision. The gate playbook (`SOC_Phase_Gate_V3`) presents the
analyst with the phase's recommendation and lets them:

- **Approve** → proceed to next phase
- **Override** → proceed with a different decision and a captured reason
- **Skip** → don't run this phase

Gate decisions are written to the parent issue (case-level dedup) so
multiple alerts on the same case don't repeatedly prompt the same human.

## Why the lifecycle stays the same per category

Endpoint and email are wildly different. The actions (isolate vs
quarantine), the artifacts (host vs message), the recovery semantics
(unisolate vs release) — all different. The lifecycle stays uniform
because each phase delegates to a category-specific sub-playbook:

```
SOC_Containment_V3  →  routes by category  →  SOC_Endpoint_Containment_V3
                                            →  SOC_Identity_Containment_V3
                                            →  SOC_Email_Containment_V3
                                            →  ...
```

The phase contract specifies what every sub-playbook must produce. The
sub-playbooks do whatever's appropriate for their category to satisfy
the contract.

This is the modular promise: add a new category, write four sub-playbooks
(one per phase) that satisfy the contract, and you've extended the
framework without touching the lifecycle.
