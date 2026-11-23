# SOC Framework

The operating layer for security operations on Cortex XSIAM. It makes any lifecycle vendor-agnostic, safe to run and measurable: every vendor action goes through one command, every changing action ships simulated until it is switched on, and every action writes one row with the analyst minutes it stands for. The framework knows nothing about phases or verdicts; a lifecycle such as NIST IR AI installs on top and calls its actions by name.

Install: [Install the SOC Framework](https://palo-cortex.github.io/secops-framework/evaluate/install/) (about 30 minutes). Read first: [Framework and Lifecycle](https://palo-cortex.github.io/secops-framework/).

## Capabilities

One page per capability on the site, in the same shape every time: what it does, where the switch lives, how to turn it on, how to verify it, what it feeds.

<!-- capabilities:begin -->
<!-- generated from docs/capabilities.yml by tools/generate_capability_catalog.py; edit the yml -->

| Capability | Use it when | What it does | Page |
|---|---|---|---|
| Universal Command | One playbook has to act on whichever EDR, email or identity product the customer owns, without a branch per vendor. | Every vendor action goes through one wrapper that resolves the vendor from the action registry and product map, applies Shadow Mode, executes or simulates, and writes one execution row per action. | [Universal Command](https://palo-cortex.github.io/secops-framework/soc-optimization-unified/universal-command/) |
| Shadow Mode | You want to show exactly what would be isolated, revoked or blocked, and when, before anything is allowed to touch production. | A changing action prints its intent and writes its execution row but does not call the vendor until its flag is flipped, per action and per actor. Fails closed: an unreadable flag means simulated. | [Shadow Mode](https://palo-cortex.github.io/secops-framework/soc-optimization-unified/shadow-mode/) |
| Tenant configuration | You need to see or change what is live on a tenant without editing lists by hand, and keep the change through pack upgrades. | One command (`!SOCFWConfig`) to view and flip shadow flags per actor, set customer values, turn jobs on and off, set owners and thresholds, and apply a mode. Dry run unless `apply=yes`; writes survive pack upgrades. | [Tenant configuration](https://palo-cortex.github.io/secops-framework/soc-optimization-unified/tenant-configuration/) |
| Deployment modes | You want to move a tenant between evaluation and production settings in one step instead of switch by switch. | Apply a coherent set of shadow switches and job states in one step (`pov`, `star_and_triage`, `contain_identity_and_hosts`, `contain_all`); `mode=default` reverts. | [Deployment modes](https://palo-cortex.github.io/secops-framework/soc-optimization-unified/deployment-modes/) |
| Foundation chain | Alerts from different products need to look the same before anything decides what to do with them. | Runs on every alert before any lifecycle logic, one script task per step: product classification, normalization, enrichment, case ledger write, case status note. Only Foundation reads `issue.*`. | page pending |
| Product classification | A data source must be recognized as endpoint, email or identity and tied to the product that can act on it. | Resolves `SOCFramework.Product.*` from the alert's data-source tag via `SOCProductCategoryMap_V3`, with sub-product override and field-shape fallback, in one task (`SOCFWClassifyProduct`). | page pending |
| Normalization | Each vendor names the user, host and file hash differently and you need one set of fields to work from. | Maps raw `issue.*` fields into `SOCFramework.Artifacts.*` per lifecycle and category from a schema list; no per-category playbook branches. | page pending |
| Enrichment lanes | You want reputation, user and device lookups to run only when there is something to look up. | Fires reputation commands (`ip`, `file`, `domain`, `url`) and action lanes (`identity`, `device`) only when the artifact paths resolve. | page pending |
| Identity resolution | The same person is an account name in one product and an email in another, so their alerts land in different cases. | Resolves a bare account name to email and provider facets from the asset inventory; fail-open. The scheduled CIE rule builds `socfw_identity_map` for vendor-pack overlays. | page pending |
| Case ledger | You need one queryable row per issue to report on, instead of digging through playbook context. | Writes one queryable row per issue carrying the Foundation contract to `xsiam_socfw_case_ledger_raw`, and a "being worked" note per case. | page pending |
| Dedup | The same detection arrives many times and floods the queue, or the same action would run twice on one case. | Fingerprints similar alerts in a window, keeps the lowest alert id as canonical; duplicates self-close and write a dedup row. An action fingerprint stops the same action running twice on one case. | page pending |
| Auto Triage | Low-signal cases pile up unread and nobody has time to close them. | Scheduled close of low-signal cases: new, unstarred, no manual score, score at or below the threshold, older than the window. | page pending |
| Close without assessment | Mail delivered to an abuse or report mailbox raises issues that do not need analysis. | Closes an issue without an assessment when it matches a reason set with `!SOCFWConfig command=close` (today: delivery to a listed report mailbox; a click is always assessed). The issue closes through `soc-close-issue-unassessed`, which ships in Shadow Mode; the case is never closed. | page pending |
| Analyst assignment | Cases sit unassigned, or one analyst gets them all, and you want them routed to whoever is on duty. | Syncs who is on duty into `socfw_on_duty` (PagerDuty, roles and groups, or a manual list) and assigns open cases least-loaded through `soc-assign-case`. | [Analyst assignment](https://palo-cortex.github.io/secops-framework/soc-optimization-unified/analyst-assignment/) |
| Emergency response | A clearly malicious issue (a compromised identity, malware running, a delivered phish, command-and-control traffic) cannot wait for the whole case to be analyzed. | Acts on a high-confidence malicious issue without waiting for the case, per policy; guarded by role and protection tiers; escalates when blocked. | page pending |
| Elevate case | The cases a person must see first need to stand out from the rest of the queue. | Stars the case, and optionally raises severity, when the lifecycle's assessment says so at high confidence. | page pending |
| Phase plan and executor | Actions have to respect which hosts and accounts are off-limits, which need approval, and which the tenant can actually reach. | Builds a per-phase action plan from the contract without a model, then applies environment tiers, policy authority, vendor reachability and ledger dedup before dispatch; non-dispatched steps still produce a row. | page pending |
| Health check | Something is not working on a tenant and you need to know whether the framework is configured and complete. | Read-only tenant check (`!SOCFWHealthCheck`): configuration, jobs and owners, customer values, named instances, presence of lists, rules, dashboards and packs. | page pending |
| Contract coverage report | You need to know whether a data source gives the framework the fields it needs before relying on it. | Samples tenant issues and reports, per source, whether each normalization-contract field is satisfied, candidate or absent. | page pending |
| Value accounting | You need to show how much analyst time automation returned, in minutes, by action and category. | Every execution row carries `time_minutes` and `action_category` from `SOCActionTimeMap_V3` (tenant override wins); the dashboards sum them. | page pending |
| Execution dataset writer | Every action and decision has to be recorded somewhere you can query and chart. | Posts events to an HTTP Collector through a named integration instance; never blocks a playbook. | page pending |
| Health dashboard | You need to see which commands fail on a tenant and why. | Command error rate, failed commands, minutes credited to failures, failure reasons, write failures. | page pending |
| Feature flags | You want an optional analysis feature on for one tenant without changing the content. | `SOCFWFeatureFlags` gates optional analysis features. | page pending |

<!-- capabilities:end -->

## Lists

Runtime-tunable on the tenant without editing content. Edit them with `!SOCFWConfig` so the change survives upgrades.

| List | What it decides |
|---|---|
| `SOCFrameworkActions_V3` | The action registry: vendor command bindings per action, shadow flags per actor, entity scope, sequencing. |
| `SOCActionClassMap_V3` | Action name to class (`endpoint`, `identity`, `email`, `indicator`, `comms`), so the wrapper knows which vendor responses apply. |
| `SOCActionTimeMap_V3` | Analyst minutes and category per action, written onto every execution row. |
| `SOCProductCategoryMap_V3` | Data source to category, type, confidence and responding vendors. |
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
