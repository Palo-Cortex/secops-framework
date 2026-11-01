# SOC Framework

The operating layer for security operations on Cortex XSIAM. It makes any lifecycle vendor-agnostic, safe to run and measurable: every vendor action goes through one command, every changing action ships simulated until it is switched on, and every action writes one row with the analyst minutes it stands for. The framework knows nothing about phases or verdicts; a lifecycle such as NIST IR AI installs on top and calls its actions by name.

Install: [Install the SOC Framework](https://palo-cortex.github.io/secops-framework/evaluate/install/) (about 30 minutes). Read first: [Framework and Lifecycle](https://palo-cortex.github.io/secops-framework/).

## Capabilities

One page per capability on the site, in the same shape every time: what it does, where the switch lives, how to turn it on, how to verify it, what it feeds.

<!-- capabilities:begin -->
<!-- generated from docs/capabilities.yml by tools/generate_capability_catalog.py; edit the yml -->

| Capability | What it does | Page |
|---|---|---|
| Universal Command | Every vendor action goes through one wrapper that resolves the vendor from the action registry and product map, applies Shadow Mode, executes or simulates, and writes one execution row per action. | [Universal Command](https://palo-cortex.github.io/secops-framework/soc-optimization-unified/universal-command/) |
| Shadow Mode | A changing action prints its intent and writes its execution row but does not call the vendor until its flag is flipped, per action and per actor. Fails closed: an unreadable flag means simulated. | [Shadow Mode](https://palo-cortex.github.io/secops-framework/soc-optimization-unified/shadow-mode/) |
| Tenant configuration | One command (`!SOCFWConfig`) to view and flip shadow flags per actor, set customer values, turn jobs on and off, set owners and thresholds, and apply a mode. Dry run unless `apply=yes`; writes survive pack upgrades. | [Tenant configuration](https://palo-cortex.github.io/secops-framework/soc-optimization-unified/tenant-configuration/) |
| Deployment modes | Apply a coherent set of shadow switches and job states in one step (`pov`, `star_and_triage`, `contain_identity_and_hosts`, `contain_all`); `mode=default` reverts. | [Deployment modes](https://palo-cortex.github.io/secops-framework/soc-optimization-unified/deployment-modes/) |
| Foundation chain | Runs on every alert before any lifecycle logic: data integrity, product classification, indicator extraction, normalization, enrichment, case status note, case ledger write. Only Foundation reads `issue.*`. | page pending |
| Product classification | Resolves `SOCFramework.Product.*` from the alert's data-source tag via `SOCProductCategoryMap_V3`, with sub-product override and field-shape fallback. | page pending |
| Normalization | Maps raw `issue.*` fields into `SOCFramework.Artifacts.*` per lifecycle and category from a schema list; no per-category playbook branches. | page pending |
| Enrichment lanes | Fires reputation commands (`ip`, `file`, `domain`, `url`) and action lanes (`identity`, `device`) only when the artifact paths resolve. | page pending |
| Identity resolution | Resolves a bare account name to email and provider facets from the asset inventory; fail-open. The scheduled CIE rule builds `socfw_identity_map` for vendor-pack overlays. | page pending |
| Case ledger | Writes one queryable row per issue carrying the Foundation contract to `xsiam_socfw_case_ledger_raw`, and a "being worked" note per case. | page pending |
| Dedup | Fingerprints similar alerts in a window, keeps the lowest alert id as canonical; duplicates self-close and write a dedup row. An action fingerprint stops the same action running twice on one case. | page pending |
| Auto Triage | Scheduled close of low-signal cases: new, unstarred, no manual score, score at or below the threshold, older than the window. | page pending |
| Analyst assignment | Syncs who is on duty into `socfw_on_duty` (PagerDuty, roles and groups, or a manual list) and assigns open cases least-loaded through `soc-assign-case`. | page pending |
| Emergency response | Acts on a high-confidence malicious issue without waiting for the case, per policy; guarded by role and protection tiers; escalates when blocked. | page pending |
| Elevate case | Stars the case, and optionally raises severity, when the lifecycle's assessment says so at high confidence. | page pending |
| Phase plan and executor | Builds a per-phase action plan from the contract without a model, then applies environment tiers, policy authority, vendor reachability and ledger dedup before dispatch; non-dispatched steps still produce a row. | page pending |
| Health check | Read-only tenant check (`!SOCFWHealthCheck`): configuration, jobs and owners, customer values, named instances, presence of lists, rules, dashboards and packs. | page pending |
| Contract coverage report | Samples tenant issues and reports, per source, whether each normalization-contract field is satisfied, candidate or absent. | page pending |
| Value accounting | Every execution row carries `time_minutes` and `action_category` from `SOCActionTimeMap_V3` (tenant override wins); the dashboards sum them. | page pending |
| Execution dataset writer | Posts events to an HTTP Collector through a named integration instance; never blocks a playbook. | page pending |
| Health dashboard | Command error rate, failed commands, minutes credited to failures, failure reasons, write failures. | page pending |
| Branch execution | `SOCExecutionList_V3` selects which branch of each Workflow playbook runs. | page pending |
| Feature flags | `SOCFWFeatureFlags` gates optional analysis features. | page pending |

<!-- capabilities:end -->

## Lists

Runtime-tunable on the tenant without editing content. Edit them with `!SOCFWConfig` so the change survives upgrades.

| List | What it decides |
|---|---|
| `SOCFrameworkActions_V3` | The action registry: vendor command bindings per action, shadow flags per actor, entity scope, sequencing. |
| `SOCActionClassMap_V3` | Action name to class (`endpoint`, `identity`, `email`, `indicator`, `comms`), so the wrapper knows which vendor responses apply. |
| `SOCActionTimeMap_V3` | Analyst minutes and category per action, written onto every execution row. |
| `SOCProductCategoryMap_V3` | Data source to category, type, confidence and responding vendors. |
| `SOCExecutionList_V3` | Which branch each Workflow playbook runs. |
| `SOCFWConfigModes` | The named bundles of switches that `!SOCFWConfig command=mode` applies. |
| `SOCFrameworkEnvironment_V3` | Asset and identity tiers with deny and require-approval action lists. |
| `SOCFrameworkPhasePolicy_V3` | Per-phase authority and mode, elevate rules, emergency policies, ticketing policy. |
| `SOCOptimizationConfig_V3` | Runtime tunables for the jobs and dedup. |
| `SOCFWFeatureFlags` | Optional analysis features. |

## Datasets

| Dataset | Written by | Read by |
|---|---|---|
| `xsiam_socfw_ir_execution_raw` | every action, through the dataset writer instance `socfw_ir_execution_writer` | the Value Metrics and health dashboards |
| `xsiam_socfw_case_ledger_raw` | the case ledger, through `socfw_case_ledger_writer` | case-scoped analysis |
