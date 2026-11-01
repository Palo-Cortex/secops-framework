# Reference

One page per capability, the same blocks in the same order every time, under three headings.

<div class="grid cards" markdown>

-   **SOC Framework**

    ---

    `soc-optimization-unified`: the universal command, Shadow Mode, lists, datasets, scripts and dashboards. Generated manifest and list tables.

    [SOC Framework →](../soc-optimization-unified/overview.md)

-   **NIST IR AI**

    ---

    `soc-framework-nist-ir-ai` and the hand-deployed playbooks: entry point, assessment, close decision, jobs, layouts, dashboards.

    [NIST IR AI →](../soc-framework-nist-ir-ai/overview.md)

-   **Vendor packs**

    ---

    One generated overview and schema page per data source.

    [Vendor packs →](../packs/index.md)

</div>

## Catalog

Every capability, by pack, with its page where one exists.

<!-- capabilities:begin -->
<!-- generated from docs/capabilities.yml by tools/generate_capability_catalog.py; edit the yml -->

### SOC Framework

| Capability | What it does | Page |
|---|---|---|
| Universal Command | Every vendor action goes through one wrapper that resolves the vendor from the action registry and product map, applies Shadow Mode, executes or simulates, and writes one execution row per action. | [Universal Command](../soc-optimization-unified/universal-command.md) |
| Shadow Mode | A changing action prints its intent and writes its execution row but does not call the vendor until its flag is flipped, per action and per actor. Fails closed: an unreadable flag means simulated. | [Shadow Mode](../soc-optimization-unified/shadow-mode.md) |
| Tenant configuration | One command (`!SOCFWConfig`) to view and flip shadow flags per actor, set customer values, turn jobs on and off, set owners and thresholds, and apply a mode. Dry run unless `apply=yes`; writes survive pack upgrades. | [Tenant configuration](../soc-optimization-unified/tenant-configuration.md) |
| Deployment modes | Apply a coherent set of shadow switches and job states in one step (`pov`, `star_and_triage`, `contain_identity_and_hosts`, `contain_all`); `mode=default` reverts. | [Deployment modes](../soc-optimization-unified/deployment-modes.md) |
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

### NIST IR AI

| Capability | What it does | Page |
|---|---|---|
| NIST IR AI | The lifecycle in one picture: issue assessment on every issue, scheduled case analysis, and which framework actions each phase calls. | [NIST IR AI](../soc-framework-nist-ir-ai/nist-ir-ai.md) |
| AI Entry Point | Stamps the lifecycle, runs the Foundation chain, collects intel, runs the issue-assessment prompt and renders the verdict; then emergency response, elevate and close by policy. | [AI Entry Point](../soc-framework-nist-ir-ai/entry-point.md) |
| Issue Assessment | Disposition prompt per issue: verdict, confidence, exposure, whether already contained, whether to escalate, whether it may close; promoted into the contract. | [Issue Assessment](../soc-framework-nist-ir-ai/issue-assessment.md) |
| AI Close Decision | Decides whether the assessment may close the issue; hard guards (starred, assigned, truncated, true positive) and a confidence bar per category. | [AI Close Decision](../soc-framework-nist-ir-ai/close-decision.md) |
| Case analysis job | Selects settled cases, collapses each to distinct alert shapes and entities, runs the case-analysis prompt and reports one verdict per case. | page pending |
| Case verdict report | One War Room entry per case tagged socfw-case-verdict; earlier ones marked superseded. | page pending |
| Case containment job | Same selection as case analysis, then runs the deterministic phase plan and executor over every candidate case. | page pending |
| Issue and case layouts | Two-tab issue layout (assessment, buttons, feedback, work plan, notes, export) and a Case Analysis tab on the case. | page pending |
| Analyst feedback | Correct, wrong or missing-context against the verdict as it stood, with an optional note. | page pending |
| Containment options from the layout | Computes at click time which actions the tenant can run for this issue and offers them as buttons. | page pending |
| War Room export | Exports the issue War Room verbatim to a printable HTML file attached to the issue. | page pending |
| Value Driver and Value Metrics dashboards | MTTD, MTTI, MTTC, cases eradicated and recovered, alerts by source, ingestion lag, cases auto-triaged, time saved by category. | page pending |
| Phase contract | Declares per-phase reads, writes and routing for the lifecycle; consumers validate and build rows from it. | page pending |

<!-- capabilities:end -->
