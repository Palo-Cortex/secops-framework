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

| Often asked for as | Capability | What it does | Page |
|---|---|---|---|
| Contain a host the same way whether it runs CrowdStrike, Defender or Cortex XDR. | Universal Command | Every vendor action goes through one wrapper that resolves the vendor from the action registry and product map, applies Shadow Mode, executes or simulates, and writes one execution row per action. | [Universal Command](../soc-optimization-unified/universal-command.md) |
| Show us what automation would do before it touches anything. | Shadow Mode | A changing action prints its intent and writes its execution row but does not call the vendor until its flag is flipped, per action and per actor. Fails closed: an unreadable flag means simulated. | [Shadow Mode](../soc-optimization-unified/shadow-mode.md) |
| Let our analysts isolate hosts, but keep automation from doing it. | Tenant configuration | One command (`!SOCFWConfig`) to view and flip shadow flags per actor, set customer values, turn jobs on and off, set owners and thresholds, and apply a mode. Dry run unless `apply=yes`; writes survive pack upgrades. | [Tenant configuration](../soc-optimization-unified/tenant-configuration.md) |
| Start conservative, then turn containment on once we trust it. | Deployment modes | Apply a coherent set of shadow switches and job states in one step (`pov`, `star_and_triage`, `contain_identity_and_hosts`, `contain_all`); `mode=default` reverts. | [Deployment modes](../soc-optimization-unified/deployment-modes.md) |
| Make alerts from all our tools look the same to analysts. | Foundation chain | Runs on every alert before any lifecycle logic, one script task per step: product classification, normalization, enrichment, case ledger write, case status note. Only Foundation reads `issue.*`. | page pending |
| Add our new email or EDR product without rewriting playbooks. | Product classification | Resolves `SOCFramework.Product.*` from the alert's data-source tag via `SOCProductCategoryMap_V3`, with sub-product override and field-shape fallback, in one task (`SOCFWClassifyProduct`). | page pending |
| Our vendors all name the user, host and file hash differently. | Normalization | Maps raw `issue.*` fields into `SOCFramework.Artifacts.*` per lifecycle and category from a schema list; no per-category playbook branches. | page pending |
| Enrich every alert with user, device and reputation automatically. | Enrichment lanes | Fires reputation commands (`ip`, `file`, `domain`, `url`) and action lanes (`identity`, `device`) only when the artifact paths resolve. | page pending |
| Put a user's email alerts and endpoint alerts in the same case. | Identity resolution | Resolves a bare account name to email and provider facets from the asset inventory; fail-open. The scheduled CIE rule builds `socfw_identity_map` for vendor-pack overlays. | page pending |
| Report on every alert and what was done with it. | Case ledger | Writes one queryable row per issue carrying the Foundation contract to `xsiam_socfw_case_ledger_raw`, and a "being worked" note per case. | page pending |
| Stop the same alert flooding the queue. | Dedup | Fingerprints similar alerts in a window, keeps the lowest alert id as canonical; duplicates self-close and write a dedup row. An action fingerprint stops the same action running twice on one case. | page pending |
| Close the low-value cases nobody looks at. | Auto Triage | Scheduled close of low-signal cases: new, unstarred, no manual score, score at or below the threshold, older than the window. | page pending |
| Monitor our phishing report or abuse mailbox. (No new workflow needed.) | Close without assessment | Closes an issue without an assessment when it matches a reason set with `!SOCFWConfig command=close` (today: delivery to a listed report mailbox; a click is always assessed). The issue closes through `soc-close-issue-unassessed`, which ships in Shadow Mode; the case is never closed. | page pending |
| Assign cases to whoever is on call. | Analyst assignment | Syncs who is on duty into `socfw_on_duty` (PagerDuty, roles and groups, or a manual list) and assigns open cases least-loaded through `soc-assign-case`. | [Analyst assignment](../soc-optimization-unified/analyst-assignment.md) |
| Isolate the host or kill the sessions right away when it is clearly malicious. | Emergency response | Acts on a high-confidence malicious issue without waiting for the case, per policy; guarded by role and protection tiers; escalates when blocked. | page pending |
| Make the dangerous cases jump to the top of the queue. | Elevate case | Stars the case, and optionally raises severity, when the lifecycle's assessment says so at high confidence. | page pending |
| Never touch our domain controllers; get approval before acting on admin accounts. | Phase plan and executor | Builds a per-phase action plan from the contract without a model, then applies environment tiers, policy authority, vendor reachability and ledger dedup before dispatch; non-dispatched steps still produce a row. | page pending |
| Is the framework installed and set up correctly on this tenant? | Health check | Read-only tenant check (`!SOCFWHealthCheck`): configuration, jobs and owners, customer values, named instances, presence of lists, rules, dashboards and packs. | page pending |
| Does our data source carry what the playbooks need? | Contract coverage report | Samples tenant issues and reports, per source, whether each normalization-contract field is satisfied, candidate or absent. | page pending |
| Show how much analyst time the automation saves. | Value accounting | Every execution row carries `time_minutes` and `action_category` from `SOCActionTimeMap_V3` (tenant override wins); the dashboards sum them. | page pending |
| Audit every automated action and decision. | Execution dataset writer | Posts events to an HTTP Collector through a named integration instance; never blocks a playbook. | page pending |
| Which automated actions are failing, and why? | Health dashboard | Command error rate, failed commands, minutes credited to failures, failure reasons, write failures. | page pending |
| Turn on sandbox detonation for this tenant only. | Feature flags | `SOCFWFeatureFlags` gates optional analysis features. | page pending |

### NIST IR AI

| Often asked for as | Capability | What it does | Page |
|---|---|---|---|
| Run incident response the NIST 800-61 way. | NIST IR AI | The lifecycle in one picture: issue assessment on every issue, scheduled case analysis, and which framework actions each phase calls. | [NIST IR AI](../soc-framework-nist-ir-ai/nist-ir-ai.md) |
| Triage every new alert automatically. | AI Entry Point | Stamps the lifecycle, runs the Foundation chain, collects intel, runs the issue-assessment prompt and renders the verdict; then emergency response, elevate and close by policy. | [AI Entry Point](../soc-framework-nist-ir-ai/entry-point.md) |
| Tell the analyst whether an alert is real, and why. | Issue Assessment | Disposition prompt per issue: verdict, confidence, exposure, whether already contained, whether to escalate, whether it may close; promoted into the contract. | [Issue Assessment](../soc-framework-nist-ir-ai/issue-assessment.md) |
| Close the benign alerts automatically, but never one a person has picked up. | AI Close Decision | Decides whether the assessment may close the issue; hard guards (starred, assigned, truncated, true positive) and a confidence bar per category. | [AI Close Decision](../soc-framework-nist-ir-ai/close-decision.md) |
| Look at the whole incident, not one alert at a time. | Case analysis job | Selects settled cases, collapses each to distinct alert shapes and entities, runs the case-analysis prompt and reports one verdict per case. | page pending |
| One current verdict per case, not a pile of old ones. | Case verdict report | One War Room entry per case tagged socfw-case-verdict; earlier ones marked superseded. | page pending |
| Contain, clean up and recover in the right order across a whole case. | Case response job | `SOC Case Response` (ships off) runs each case's containment, eradication and recovery plans from the Analysis contract, in that order, through the phase executor inside the issue that evidences each step; steps that need a person are recorded as awaiting and never dispatched. Containment is held (`policy_blocked`) when the analysis is below the phase policy's `min_verdict` or `min_confidence`, and past `max_actions_per_case`. Recovery undoes only what was contained, in the mode it ran in (shadow undoes shadow), and waits until the same target's eradication has finished. A run stops taking new work before the script timeout and continues on the next pass; its War Room entry says what it read, what it worked and what is left. | page pending |
| Verdict, evidence and next actions on one screen. | Issue and case layouts | Two-tab issue layout (assessment, buttons, feedback, work plan, notes, export) and a Case Analysis tab on the case. | page pending |
| Let analysts tell us when the AI got it wrong. | Analyst feedback | Correct, wrong or missing-context against the verdict as it stood, with an optional note. | page pending |
| Give analysts a contain button that only offers what works on this tenant. | Containment options from the layout | Computes at click time which actions the tenant can run for this issue and offers them as buttons. | page pending |
| A printable record of the incident for the report. | War Room export | Exports the issue War Room verbatim to a printable HTML file attached to the issue. | page pending |
| Prove our time to detect and respond improved. | Value Driver and Value Metrics dashboards | MTTD, MTTI, MTTC, cases eradicated and recovered, alerts by source, ingestion lag, cases auto-triaged, time saved by category. | page pending |
| Add our own step to the incident response lifecycle. | Phase contract | Declares per-phase reads, writes and routing for the lifecycle; consumers validate and build rows from it. | page pending |

<!-- capabilities:end -->
