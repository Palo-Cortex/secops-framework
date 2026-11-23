# SOC Framework

The operating layer for security operations on Cortex XSIAM. It makes any lifecycle vendor-agnostic, safe to run and measurable: every vendor action goes through one command, every changing action ships simulated until it is switched on, and every action writes one row with the analyst minutes it stands for. The framework knows nothing about phases or verdicts; a lifecycle such as NIST IR AI installs on top and calls its actions by name.

Install: [Install the SOC Framework](https://palo-cortex.github.io/secops-framework/evaluate/install/) (about 30 minutes). Read first: [Framework and Lifecycle](https://palo-cortex.github.io/secops-framework/).

## Capabilities

One page per capability on the site, in the same shape every time: what it does, where the switch lives, how to turn it on, how to verify it, what it feeds.

<!-- capabilities:begin -->
<!-- generated from docs/capabilities.yml by tools/generate_capability_catalog.py; edit the yml -->

| Often asked for as | Capability | What it does | Page |
|---|---|---|---|
| Contain a host the same way whether it runs CrowdStrike, Defender or Cortex XDR. | Universal Command | Every vendor action goes through one wrapper that resolves the vendor from the action registry and product map, applies Shadow Mode, executes or simulates, and writes one execution row per action. | [Universal Command](https://palo-cortex.github.io/secops-framework/soc-optimization-unified/universal-command/) |
| Show us what automation would do before it touches anything. | Shadow Mode | A changing action prints its intent and writes its execution row but does not call the vendor until its flag is flipped, per action and per actor. Fails closed: an unreadable flag means simulated. | [Shadow Mode](https://palo-cortex.github.io/secops-framework/soc-optimization-unified/shadow-mode/) |
| Let our analysts isolate hosts, but keep automation from doing it. | Tenant configuration | One command (`!SOCFWConfig`) to view and flip shadow flags per actor, set customer values, turn jobs on and off, set owners and thresholds, and apply a mode. Dry run unless `apply=yes`; writes survive pack upgrades. | [Tenant configuration](https://palo-cortex.github.io/secops-framework/soc-optimization-unified/tenant-configuration/) |
| Start conservative, then turn containment on once we trust it. | Deployment modes | Apply a coherent set of shadow switches and job states in one step (`pov`, `star_and_triage`, `contain_identity_and_hosts`, `contain_all`); `mode=default` reverts. | [Deployment modes](https://palo-cortex.github.io/secops-framework/soc-optimization-unified/deployment-modes/) |
| Make alerts from all our tools look the same to analysts. | Foundation chain | Runs on every alert before any lifecycle logic, one script task per step: product classification, normalization, enrichment, case ledger write, case status note. Only Foundation reads `issue.*`. | page pending |
| Add our new email or EDR product without rewriting playbooks. | Product classification | Resolves `SOCFramework.Product.*` from the alert's data-source tag via `SOCProductCategoryMap_V3`, with sub-product override and field-shape fallback, in one task (`SOCFWClassifyProduct`). | page pending |
| Our vendors all name the user, host and file hash differently. | Normalization | Maps raw `issue.*` fields into `SOCFramework.Artifacts.*` per lifecycle and category from a schema list; no per-category playbook branches. | page pending |
| Enrich every alert with user, device and reputation automatically. | Enrichment lanes | Fires reputation commands (`ip`, `file`, `domain`, `url`) and action lanes (`identity`, `device`) only when the artifact paths resolve. | page pending |
| Put a user's email alerts and endpoint alerts in the same case. | Identity resolution | Resolves a bare account name to email and provider facets from the asset inventory; fail-open. The scheduled CIE rule builds `socfw_identity_map` for vendor-pack overlays. | page pending |
| Report on every alert and what was done with it. | Case ledger | Writes one queryable row per issue carrying the Foundation contract to `xsiam_socfw_case_ledger_raw`, and a "being worked" note per case. | page pending |
| Stop the same alert flooding the queue. | Dedup | Fingerprints similar alerts in a window, keeps the lowest alert id as canonical; duplicates self-close and write a dedup row. An action fingerprint stops the same action running twice on one case. | page pending |
| Close the low-value cases nobody looks at. | Auto Triage | Scheduled close of low-signal cases: new, unstarred, no manual score, score at or below the threshold, older than the window. | page pending |
| Monitor our phishing report or abuse mailbox. (No new workflow needed.) | Close without assessment | Closes an issue without an assessment when it matches a reason set with `!SOCFWConfig command=close` (today: delivery to a listed report mailbox; a click is always assessed). The issue closes through `soc-close-issue-unassessed`, which ships in Shadow Mode; the case is never closed. | page pending |
| Assign cases to whoever is on call. | Analyst assignment | Syncs who is on duty into `socfw_on_duty` (PagerDuty, roles and groups, or a manual list) and assigns open cases least-loaded through `soc-assign-case`. | [Analyst assignment](https://palo-cortex.github.io/secops-framework/soc-optimization-unified/analyst-assignment/) |
| Isolate the host or kill the sessions right away when it is clearly malicious. | Emergency response | Acts on a high-confidence malicious issue without waiting for the case, per policy; guarded by role and protection tiers; escalates when blocked. | page pending |
| Make the dangerous cases jump to the top of the queue. | Elevate case | Stars the case, and optionally raises severity, when the lifecycle's assessment says so at high confidence. | page pending |
| Never touch our domain controllers; get approval before acting on admin accounts. | Phase plan and executor | Builds a per-phase action plan from the contract without a model, then applies environment tiers, policy authority, vendor reachability and ledger dedup before dispatch; non-dispatched steps still produce a row. | page pending |
| Is the framework installed and set up correctly on this tenant? | Health check | Read-only tenant check (`!SOCFWHealthCheck`): configuration, jobs and owners, customer values, named instances, presence of lists, rules, dashboards and packs. | page pending |
| Does our data source carry what the playbooks need? | Contract coverage report | Samples tenant issues and reports, per source, whether each normalization-contract field is satisfied, candidate or absent. | page pending |
| Show how much analyst time the automation saves. | Value accounting | Every execution row carries `time_minutes` and `action_category` from `SOCActionTimeMap_V3` (tenant override wins); the dashboards sum them. | page pending |
| Audit every automated action and decision. | Execution dataset writer | Posts events to an HTTP Collector through a named integration instance; never blocks a playbook. | page pending |
| Which automated actions are failing, and why? | Health dashboard | Command error rate, failed commands, minutes credited to failures, failure reasons, write failures. | page pending |
| Turn on sandbox detonation for this tenant only. | Feature flags | `SOCFWFeatureFlags` gates optional analysis features. | page pending |

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
