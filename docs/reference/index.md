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

| Capability | Use it when | What it does | Page |
|---|---|---|---|
| Universal Command | One playbook has to act on whichever EDR, email or identity product the customer owns, without a branch per vendor. | Every vendor action goes through one wrapper that resolves the vendor from the action registry and product map, applies Shadow Mode, executes or simulates, and writes one execution row per action. | [Universal Command](../soc-optimization-unified/universal-command.md) |
| Shadow Mode | You want to show exactly what would be isolated, revoked or blocked, and when, before anything is allowed to touch production. | A changing action prints its intent and writes its execution row but does not call the vendor until its flag is flipped, per action and per actor. Fails closed: an unreadable flag means simulated. | [Shadow Mode](../soc-optimization-unified/shadow-mode.md) |
| Tenant configuration | You need to see or change what is live on a tenant without editing lists by hand, and keep the change through pack upgrades. | One command (`!SOCFWConfig`) to view and flip shadow flags per actor, set customer values, turn jobs on and off, set owners and thresholds, and apply a mode. Dry run unless `apply=yes`; writes survive pack upgrades. | [Tenant configuration](../soc-optimization-unified/tenant-configuration.md) |
| Deployment modes | You want to move a tenant between evaluation and production settings in one step instead of switch by switch. | Apply a coherent set of shadow switches and job states in one step (`pov`, `star_and_triage`, `contain_identity_and_hosts`, `contain_all`); `mode=default` reverts. | [Deployment modes](../soc-optimization-unified/deployment-modes.md) |
| Foundation chain | Alerts from different products need to look the same before anything decides what to do with them. | Runs on every alert before any lifecycle logic, one script task per step: product classification, normalization, enrichment, case ledger write, case status note. Only Foundation reads `issue.*`. | page pending |
| Product classification | A data source must be recognized as endpoint, email or identity and tied to the product that can act on it. | Resolves `SOCFramework.Product.*` from the alert's data-source tag via `SOCProductCategoryMap_V3`, with sub-product override and field-shape fallback, in one task (`SOCFWClassifyProduct`). | page pending |
| Normalization | Each vendor names the user, host and file hash differently and you need one set of fields to work from. | Maps raw `issue.*` fields into `SOCFramework.Artifacts.*` per lifecycle and category from a schema list; no per-category playbook branches. | page pending |
| Enrichment lanes | You want reputation, user and device lookups to run only when there is something to look up. | Fires reputation commands (`ip`, `file`, `domain`, `url`) and action lanes (`identity`, `device`) only when the artifact paths resolve. | page pending |
| Identity resolution | The same person is an account name in one product and an email in another, so their alerts land in different cases. | Resolves a bare account name to email and provider facets from the asset inventory; fail-open. The scheduled CIE rule builds `socfw_identity_map` for vendor-pack overlays. | page pending |
| Case ledger | You need one queryable row per issue to report on, instead of digging through playbook context. | Writes one queryable row per issue carrying the Foundation contract to `xsiam_socfw_case_ledger_raw`, and a "being worked" note per case. | page pending |
| Dedup | The same detection arrives many times and floods the queue, or the same action would run twice on one case. | Fingerprints similar alerts in a window, keeps the lowest alert id as canonical; duplicates self-close and write a dedup row. An action fingerprint stops the same action running twice on one case. | page pending |
| Auto Triage | Low-signal cases pile up unread and nobody has time to close them. | Scheduled close of low-signal cases: new, unstarred, no manual score, score at or below the threshold, older than the window. | page pending |
| Close without assessment | Mail delivered to an abuse or report mailbox raises issues that do not need analysis. | Closes an issue without an assessment when it matches a reason set with `!SOCFWConfig command=close` (today: delivery to a listed report mailbox; a click is always assessed). The issue closes through `soc-close-issue-unassessed`, which ships in Shadow Mode; the case is never closed. | page pending |
| Analyst assignment | Cases sit unassigned, or one analyst gets them all, and you want them routed to whoever is on duty. | Syncs who is on duty into `socfw_on_duty` (PagerDuty, roles and groups, or a manual list) and assigns open cases least-loaded through `soc-assign-case`. | [Analyst assignment](../soc-optimization-unified/analyst-assignment.md) |
| Emergency response | A clearly malicious issue (a compromised identity, malware running, a delivered phish, command-and-control traffic) cannot wait for the whole case to be analyzed. | Acts on a high-confidence malicious issue without waiting for the case, per policy; guarded by role and protection tiers; escalates when blocked. | page pending |
| Elevate case | The cases a person must see first need to stand out from the rest of the queue. | Stars the case, and optionally raises severity, when the lifecycle's assessment says so at high confidence. | page pending |
| Phase plan and executor | Actions have to respect which hosts and accounts are off-limits, which need approval, and which the tenant can actually reach. | Builds a per-phase action plan from the contract without a model, then applies environment tiers, policy authority, vendor reachability and ledger dedup before dispatch; non-dispatched steps still produce a row. | page pending |
| Health check | Something is not working on a tenant and you need to know whether the framework is configured and complete. | Read-only tenant check (`!SOCFWHealthCheck`): configuration, jobs and owners, customer values, named instances, presence of lists, rules, dashboards and packs. | page pending |
| Contract coverage report | You need to know whether a data source gives the framework the fields it needs before relying on it. | Samples tenant issues and reports, per source, whether each normalization-contract field is satisfied, candidate or absent. | page pending |
| Value accounting | You need to show how much analyst time automation returned, in minutes, by action and category. | Every execution row carries `time_minutes` and `action_category` from `SOCActionTimeMap_V3` (tenant override wins); the dashboards sum them. | page pending |
| Execution dataset writer | Every action and decision has to be recorded somewhere you can query and chart. | Posts events to an HTTP Collector through a named integration instance; never blocks a playbook. | page pending |
| Health dashboard | You need to see which commands fail on a tenant and why. | Command error rate, failed commands, minutes credited to failures, failure reasons, write failures. | page pending |
| Feature flags | You want an optional analysis feature on for one tenant without changing the content. | `SOCFWFeatureFlags` gates optional analysis features. | page pending |

### NIST IR AI

| Capability | Use it when | What it does | Page |
|---|---|---|---|
| NIST IR AI | You need the overview: how issues are assessed, how cases are analyzed, and which actions each step can call. | The lifecycle in one picture: issue assessment on every issue, scheduled case analysis, and which framework actions each phase calls. | [NIST IR AI](../soc-framework-nist-ir-ai/nist-ir-ai.md) |
| AI Entry Point | You want every new issue triaged the same way the moment it arrives. | Stamps the lifecycle, runs the Foundation chain, collects intel, runs the issue-assessment prompt and renders the verdict; then emergency response, elevate and close by policy. | [AI Entry Point](../soc-framework-nist-ir-ai/entry-point.md) |
| Issue Assessment | Analysts spend their time deciding whether each alert is real; you want a verdict, confidence and reason on every issue. | Disposition prompt per issue: verdict, confidence, exposure, whether already contained, whether to escalate, whether it may close; promoted into the contract. | [Issue Assessment](../soc-framework-nist-ir-ai/issue-assessment.md) |
| AI Close Decision | Benign issues should close themselves, but never one a person has claimed or one that is truly malicious. | Decides whether the assessment may close the issue; hard guards (starred, assigned, truncated, true positive) and a confidence bar per category. | [AI Close Decision](../soc-framework-nist-ir-ai/close-decision.md) |
| Case analysis job | Related alerts need to be read together as one incident to see a campaign and what to do about it. | Selects settled cases, collapses each to distinct alert shapes and entities, runs the case-analysis prompt and reports one verdict per case. | page pending |
| Case verdict report | Analysts need one current verdict on the case, not a stack of old ones. | One War Room entry per case tagged socfw-case-verdict; earlier ones marked superseded. | page pending |
| Case response job | Cases with a malicious verdict should have their response carried out on a schedule, in order, under policy, with steps that need a person held for them. | `SOC Case Response` (ships off) runs each case's containment, eradication and recovery plans from the Analysis contract, in that order, through the phase executor inside the issue that evidences each step; steps that need a person are recorded as awaiting and never dispatched. | page pending |
| Issue and case layouts | Analysts need the verdict, the evidence and the next actions on one screen. | Two-tab issue layout (assessment, buttons, feedback, work plan, notes, export) and a Case Analysis tab on the case. | page pending |
| Analyst feedback | You want to measure how often the AI verdict is right, and capture why when it is wrong. | Correct, wrong or missing-context against the verdict as it stood, with an optional note. | page pending |
| Containment options from the layout | An analyst wants to act on an issue with only the actions this tenant can actually run. | Computes at click time which actions the tenant can run for this issue and offers them as buttons. | page pending |
| War Room export | You need a printable record of everything that happened on an issue. | Exports the issue War Room verbatim to a printable HTML file attached to the issue. | page pending |
| Value Driver and Value Metrics dashboards | You need to prove time to detect, investigate and respond, and time saved, from the tenant's own data. | MTTD, MTTI, MTTC, cases eradicated and recovered, alerts by source, ingestion lag, cases auto-triaged, time saved by category. | page pending |
| Phase contract | You are building on the lifecycle and need to know what each step reads and writes. | Declares per-phase reads, writes and routing for the lifecycle; consumers validate and build rows from it. | page pending |

<!-- capabilities:end -->
