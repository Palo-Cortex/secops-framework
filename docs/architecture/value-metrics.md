# Value Metrics

How the framework measures itself: MTTD, MTTC, MTTE, MTTR, dashboards,
and the dataset they all read from.

## The four metrics

The framework tracks four mean-time metrics, one per NIST IR phase plus
detection:

| Metric | Phase    | What it measures                                    |
|--------|----------|-----------------------------------------------------|
| MTTD   | Detect   | Vendor-side event timestamp → alert creation       |
| MTTC   | Contain  | Alert creation → Containment.attempted = true      |
| MTTE   | Eradicate| Alert creation → Eradication.attempted = true      |
| MTTR   | Recover  | Alert creation → Recovery.attempted = true         |

These are the framework's primary value drivers. A SOC's "before" state
is typically slow MTTC/MTTE/MTTR because containment, eradication, and
recovery are manual. The framework's payoff shows up as those numbers
collapsing once Shadow Mode flips to production.

## How metrics get written

Every action that runs through `SOCCommandWrapper` writes a record to
the **`xsiam_socfw_ir_execution_raw`** dataset. The record includes:

- `playbook_name`, `playbook_id` — which playbook called the wrapper
- `action_name` — e.g., `soc-isolate-host`
- `action_category` — pulled from `SOCActionTimeMap_V3`
- `action_time_minutes` — pulled from `SOCActionTimeMap_V3`
- `execution_mode` — `shadow` or `production`
- `phase` — analysis / containment / eradication / recovery
- `vendor`, `product`, `category`
- timestamps for the action and the alert it ran on

Dashboards roll these records up into the four MT* metrics by phase,
category, and vendor.

## Two dashboards: shadow and production

The framework ships two parallel dashboards:

- **`XSIAM_SOC_Value_Metrics_V3`** — filtered to `execution_mode =
  "production"`. The real story.
- **`XSIAM_SOC_Value_Metrics_Shadow`** — filtered to `execution_mode =
  "shadow"`. The "if you flipped this to production right now, here's
  what your numbers would look like" story.

This split is the operating advantage of Shadow Mode (see [Universal
Command & Shadow Mode](universal-command-shadow-mode.md)). During a
preview deployment, only the Shadow dashboard has data — but it
populates with realistic numbers from realistic alerts, not from
synthetic load. When actions flip to production, those same alerts
start contributing to the production dashboard, and the comparison
between the two becomes the rollout's measurable proof.

## Why not use `xsiam_playbookmetrics_raw`?

XSIAM has a built-in playbook metrics dataset that captures wall-clock
timings of every playbook run. The framework intentionally does not
read from it for its primary metrics, for three reasons:

- **Granularity mismatch.** Playbook metrics measure playbook duration.
  Value metrics measure phase duration, which is action-bounded, not
  playbook-bounded.
- **Mode awareness.** Playbook metrics don't carry the
  `execution_mode` field. There's no way to filter shadow vs production
  in that dataset.
- **Category awareness.** Playbook metrics know the playbook id, not
  the action category — which is what dashboards need to slice by
  endpoint / email / identity.

`xsiam_playbookmetrics_raw` may still be useful for performance
debugging (which playbook is slow?) but it's not the value-metrics
source.

## Action time semantics

`SOCActionTimeMap_V3` is a Lookup that gives every action a category
and a "if this action ran manually, how long would it take?" minutes
estimate. The wrapper looks the action up at execution time and writes
both fields onto the dataset record.

This matters because the *value* the framework demonstrates isn't
"computer is faster than human" — that's obvious. The value is
**accumulated time saved across the whole alert volume**. A 1,500-alerts-
per-year SOC where each alert previously took 3h 8m of analyst handling
saves a measurable, dollarable amount of time when the framework
collapses that to ~30 seconds. The minutes-saved math runs off
`SOCActionTimeMap_V3`'s `time_minutes` field, summed across the
dataset.

## Reading the dashboards

When you open either dashboard, the layout is roughly:

- **Top row** — the four big numbers (MTTD, MTTC, MTTE, MTTR), as
  averages over the chosen time window
- **Volume row** — alerts by category, alerts by phase outcome
- **Distribution row** — phase duration histograms, per-action heatmap
- **Bottom row** — running sum of analyst time saved (the dollar number)

The dashboards are the framework's most visible artifact. If the
lifecycle isn't writing to `xsiam_socfw_ir_execution_raw`, the
dashboards stay empty — which is also a useful signal.
