# Auto Triage

Scheduled noise reduction. The JOB that closes low-risk cases
automatically so analysts only see what matters.

The framework ships with a scheduled JOB — `JOB - Auto Triage V3` — that
runs on a recurring cadence, queries open cases via the XSIAM REST API,
and auto-closes the ones that meet a noise profile: low risk score, aged
out of the response window, and untouched by an analyst. Without it,
even a well-tuned tenant accumulates a backlog of low-fidelity cases
that XSIAM already scored as unimportant.

## What Auto Triage is

A **scheduled JOB**, not an alert-triggered playbook. It runs on a
cadence (typically hourly), independent of any alert flow. Every run:

1. Queries open cases via `/public_api/v1/incidents/get_incidents`
2. Filters by the eligibility criteria below
3. Auto-closes the matching cases via `SOC Close Cases V3`
4. Writes execution facts to `xsiam_socfw_ir_execution_raw` for the
   Value Metrics dashboard

It runs **on cases that already exist**, after XSIAM has scored them.
It is not a pre-filter at alert ingest — that's the automation trigger
rule's job, which fires `EP_IR_NIST (800-61)_V3` on alerts meeting the
trigger condition (severity, MITRE tactic, or risk score). Auto Triage
and the lifecycle entry are separate concerns operating at different
points in the case life.

## Eligibility criteria

A case is eligible for auto-close when **all** of these are true:

| Criterion | Default | Configured in |
|---|---|---|
| `status = "new"` | always | hard-coded |
| `manual_score is null` | always | hard-coded — analyst hasn't intervened |
| `aggregated_score <= TriageScoreThreshold` | **40** | `SOCOptimizationConfig_V3` |
| `creation_time` older than `TriageWindowHours` | **6 hours** | `SOCOptimizationConfig_V3` |
| `starred = false` | always (currently) | hard-coded — but see below |

The first four are about ensuring nothing valuable closes by accident.
A case has to be aged out, unscored by humans, in `New` status, and
ranked below the threshold by XSIAM's own ML scoring before the JOB
will touch it.

## Risk score is the primary gate

Auto Triage now operates on **case risk score**. The default threshold
is **40**, configurable per tenant in `SOCOptimizationConfig_V3`.
Anything XSIAM scored above 40 is excluded from auto-close regardless
of how old it is.

This is the framework leaning into XSIAM-native intelligence. The
platform's ML-computed `aggregated_score` is a richer signal than any
binary heuristic the framework could implement on its own — and it
gets better over time as the platform learns the tenant's environment.
Auto Triage respects it.

## Starring is now optional

Originally, starring was the framework's primary case-importance signal:
the lifecycle automation trigger fired on `starred = true`, the Auto
Triage JOB closed everything `starred = false`. That worked, but it
made starring a hard prerequisite for the framework to function.

The framework no longer requires it. Customers can:

- **Skip starring entirely** — the lifecycle automation trigger fires
  on `Severity ≥ Medium` (or any other rule the customer prefers),
  Auto Triage closes everything with `aggregated_score ≤ 40`. No
  starring rule needed.
- **Keep using starring** as an additional safeguard — the JOB still
  excludes starred cases from auto-close. A starring rule like
  `Severity ≥ Medium AND has MITRE tactic` routes the important cases
  to the lifecycle while everything else flows through Auto Triage.

Both patterns work. The score-only pattern is simpler and aligns
better with XSIAM's native scoring model. The hybrid pattern gives
analysts an explicit "do not auto-close" lever — useful for customers
who want manual override of the score threshold on specific cases.

## Pagination — the practical detail

`/public_api/v1/incidents/get_incidents` caps at 100 results per call.
For tenants with thousands of open cases, a single call returns a
slice sorted by `creation_time` ascending — which means the JOB sees
the oldest cases first. But if the oldest 100 are all above the
threshold, none get closed and the queue stalls.

`SOCAutoTriageScoreFilter` handles this by paginating internally:

- Batch size: 100 (API cap)
- Default max batches per run: 5 (500 cases scanned per JOB run)
- Cases above the threshold are skipped without being held in memory
- The script returns only candidates that pass; the JOB's close task
  iterates over those

If a tenant's open case volume routinely exceeds 500 between JOB runs,
raise `max_batches` in the script's input arguments or run the JOB
more frequently. Both are safe — the script is idempotent.

## Configuration

Tunables live in `SOCOptimizationConfig_V3` under the `Auto Triage JOB`
section:

| Key | Default | Effect |
|---|---|---|
| `TriageScoreThreshold` | 40 | Cases at or below this score are eligible |
| `TriageWindowHours` | 6 | Cases must be older than this |

Tune `TriageScoreThreshold` after observing the tenant's score
distribution in the first week. Default 40 protects anything XSIAM
ranked medium-risk or higher from auto-close. Customers with
high-confidence detections often raise it.

## Value driver

**VD3 — Operational Efficiency.** Cases auto-resolved per run ×
average analyst triage time = hours saved per week. The Value Metrics
dashboard surfaces this as the "Cases Auto-Resolved %" widget,
filtered by `execution_mode` and date range.

A typical PoV reports auto-triage closure rates in the 20–50% range
depending on how noisy the source detections are. That number is the
framework's strongest single VD3 talking point — analyst time freed
from triage shows up immediately and is easy to quantify against the
customer's pre-framework baseline.

## What Auto Triage is NOT

- **Not** a real-time pre-filter at alert ingest. It runs on
  already-created cases, on a schedule.
- **Not** a substitute for tuning bad detection rules. If a
  correlation rule fires constantly on benign behavior, fix the
  rule. Auto Triage handles the residual noise from a *good* rule.
- **Not** related to Shadow Mode. Auto Triage decides whether a case
  closes; Shadow Mode decides whether the lifecycle's *actions* fire
  on a different case. Orthogonal concerns.
- **Not** a replacement for Analysis. Cases that pass the threshold
  flow to the full NIST IR lifecycle and get the rich verdict.

## See also

- **[Alert Flow](alert-flow.md)** — where the lifecycle entry sits
  vs. where Auto Triage sits
- **[Value Metrics](value-metrics.md)** — the dashboard that surfaces
  Auto Triage's VD3 contribution
- **`SOCOptimizationConfig_V3`** — the editable list where thresholds
  live
- **`SOCAutoTriageScoreFilter` script** — the pagination + filter
  implementation
