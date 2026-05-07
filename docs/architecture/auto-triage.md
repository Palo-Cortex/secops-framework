# Auto Triage

How the framework decides which alerts deserve full lifecycle treatment
and which can close fast.

## What Auto Triage is

Auto Triage is the framework's pre-Analysis filter. Before an alert
runs through the full NIST IR lifecycle, it gets a fast pass to decide:

- **Pursue** — proceed with Analysis → Containment → Eradication →
  Recovery
- **Close** — close as benign / known-good / duplicate without further
  work
- **Defer** — pause for analyst review (rare; only when the gate is
  truly ambiguous)

The goal is to keep human attention on the alerts that need humans, and
to close the rest deterministically.

## Why it lives before Analysis

Two reasons.

**Cost.** Analysis runs threat intel lookups, MITRE scoring, related-
events queries — work that costs Cortex Units and analyst attention.
If an alert is obviously a known false positive (the same dev
machine triggering the same rule for the tenth time today), there's no
reason to spend that work.

**Volume realism.** A typical SOC sees 1,500+ alerts per year per data
source. If every alert ran the full lifecycle, the dashboards would be
dominated by closed-as-benign noise, and analysts would tune out.
Triage funnels the volume so what's left is meaningful.

## The triage decision

Auto Triage looks at three classes of signal:

1. **Confidence in the source.** Some correlation rules fire with high
   confidence (e.g., a CrowdStrike detection labeled "high"). Others
   fire on weak signals that need correlation to mean anything.
2. **Asset criticality (the CIA priorities).** Alerts on high-CIA
   assets (production crown-jewel servers, executive accounts) get
   pursued by default; alerts on low-CIA assets can fast-close on
   weaker grounds.
3. **Recent history.** If the same alert fired on the same asset
   recently and was closed as benign, the new occurrence is treated
   as the same pattern unless something else changed.

The output is a triage verdict written to the framework namespace
that downstream lifecycle phases consult. Analysis still runs, but
it knows whether to dig deep or close fast.

## CIA-based prioritization

The framework reads asset criticality from a lookup keyed by hostname
or username. The lookup carries three flags per asset:

- **Confidentiality** — does this asset hold sensitive data?
- **Integrity** — does this asset's correctness matter operationally?
- **Availability** — does this asset's uptime matter?

An alert on a CIA-high asset gets pursued more aggressively (lower
confidence threshold to escalate, less aggressive auto-close). An alert
on a CIA-low asset (a developer's laptop, a kiosk) closes more readily.

This matters because triage at scale isn't binary. The same
correlation rule firing on the CEO's laptop vs a build agent should
not get the same treatment. CIA prioritization makes that judgment
explicit and tunable.

## What Auto Triage is NOT

- **Not** a replacement for Analysis. Analysis is the rich verdict;
  Triage is the fast filter. Triage may decide "pursue normally," and
  Analysis still runs.
- **Not** a substitute for tuning bad detection rules. If a correlation
  rule fires constantly on benign behavior, fix the rule. Triage exists
  to handle the residual noise from a *good* rule, not to paper over
  a bad one.
- **Not** about Shadow Mode. Triage decides whether the lifecycle
  *runs*; Shadow Mode decides whether the lifecycle's *actions*
  actually fire. They're orthogonal.

## Where to tune it

Triage thresholds and CIA lookups live in editable Lists in the
Foundation pack — not hard-coded in playbooks. The deployment pattern
is to ship the framework with sane defaults and then tune the CIA
lookup as the customer's asset inventory becomes known. No playbook
edits required.
