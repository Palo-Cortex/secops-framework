# AI content — NIST IR case analysis

Detection & Analysis runs once per **case**, on a schedule, instead of once per issue.

**Install this pack only on AI-capable tenants.** It does nothing without an AI Prompt, which is not a packageable content item and must be created by hand.

Requires `soc-framework-nist-ir` and `soc-optimization-unified`, which carry the supporting scripts, the phase contract and the configuration list.

## Contents

| Item | What it is |
| --- | --- |
| `EP_IR_NIST (800-61) AI` | Entry point that ends at Upon Trigger. Issue automation builds the contract and stops |
| `JOB - SOC Case Analysis` | The JOB playbook. Selects cases, collapses them, builds payloads |
| `SOC Case Analysis Phase` | Sub-playbook, once per case. Ships with a placeholder where the `aiTask` goes |
| [SOCFWCaseAnalysis prompt](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-framework-nist-ir-ai/SOCFWCaseAnalysis.prompt.md) | The AI Prompt — configuration and full body. Not installed by the pack |

**Installing this pack changes nothing on its own.** All three playbooks side-load alongside `soc-framework-nist-ir`; the existing `EP_IR_NIST (800-61)_V3` keeps its inline lifecycle and keeps running. Nothing switches over until the automation trigger is pointed at `EP_IR_NIST (800-61) AI`, and pointing it back is the rollback.

The supporting scripts come from `soc-framework-nist-ir`: `SOCFWCaseSelect`, `SOCFWBuildCasePayload`, `SOCFWFetchShapeContracts`, `SOCFWCaseIterationSetup`, `SOCFWCaseVerdictReport`.

## Install

**1. Install this pack.** Both playbooks arrive. The chain runs, but the analysis step is a placeholder and produces no verdict.

**2. Create the AI Prompt.** Follow [SOCFWCaseAnalysis.prompt.md](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-framework-nist-ir-ai/SOCFWCaseAnalysis.prompt.md) — model settings, seven inputs, output path `Analysis.AI`, then paste the body. Create it before binding in step 3, so the aiTask has a prompt to point at.

**3. Bind the `aiTask`.** Open `SOC Case Analysis Phase`, replace task 10 — the *AI Case Analysis* title — with an aiTask pointed at the prompt from step 2. Save.

A pack upgrade replaces this playbook with the shipped placeholder, so re-check the binding after any upgrade and re-bind if needed. Nothing else is lost: the JOB, the entry point and all thresholds upgrade normally.

**4. Configure.** Add or check the `Case Analysis JOB` block in `SOCOptimizationConfig_V3` — see Settings below.

**5. Point the automation trigger** at `EP_IR_NIST (800-61) AI` when ready to move to case scope. Until this step, the pack is installed and inert. Point it back at `EP_IR_NIST (800-61)_V3` to roll back.

**6. Create the scheduled Job** in the Jobs UI:

| Setting | Value |
| --- | --- |
| Playbook | `JOB - SOC Case Analysis` |
| Recurring | Every 10 minutes |
| Trigger new instance while running | **Off** |
| Ending | Never |

Keep the interval well clear of run duration. Runs take minutes on a busy tenant, and overlapping executions repeat work.

## Settings

`SOCOptimizationConfig_V3` → `Case Analysis JOB` → `fields`

### Which cases get analysed

| Field | Default | Effect |
| --- | --- | --- |
| `CaseDomain` | DOMAIN_SECURITY | Lifecycle scope. Posture cases have their own lifecycle |
| `CaseWindowHours` | 72 | Only consider cases modified within this window |
| `CaseMinIssues` | 2 | Single-issue cases go to the per-category prompts instead |
| `CaseMinShapes` | 2 | Repetition is not a chain |
| `CaseCampaignIssues` | 20 | Above this, a single-shape case is a campaign and is analysed |
| `CaseMinScore` | 0 | Optional `predicted_score` floor. 0 disables it |

### When they get analysed

| Field | Default | Effect |
| --- | --- | --- |
| `CaseSettleMinutes` | 15 | Wait for a case to stop changing. Analysing once, late, beats three times, early |
| `CaseMaxWaitMinutes` | 120 | Analyse anyway past this age, so an always-active case still gets a verdict |
| `CaseMaxAnalyses` | 2 | Re-analyses per case before it stops being reselected |

### How much evidence travels

| Field | Default | Effect |
| --- | --- | --- |
| `CaseMaxShapes` | 40 | Distinct shapes carried per case, highest count first |
| `CaseMaxPayloadChars` | 80000 | Prompt budget. The platform rejects anything over 100,000 characters |
| `CaseMaxContractFetches` | 40 | Contract reads per case |
| `CaseMaxDeferrals` | 2 | Retries before a case is analysed without the unreadable parts |
| `CaseIntelRoots` | 8 roots | Context roots carrying reputation and threat intel. Add Recorded Future or GTI here |

### Paging

| Field | Default | Effect |
| --- | --- | --- |
| `CaseBatchSize` | 100 | Cases per page. Platform ceiling is 100 |
| `CaseMaxBatches` | 20 | Pages per run |

## Operating

**Where the verdict goes**

- `SOCFramework.Analysis.AI` on the case — the current verdict, read by Containment and Auto Triage
- The case War Room — one entry per case, tagged `socfw-case-verdict`; earlier ones tagged `socfw-superseded`
- `xsiam_socfw_ir_execution_raw` — a `case_analysis` row per case, a `case_analysis_run` row per run

**Reading a run.** The JOB's own War Room shows selection counts — `scanned`, `candidates`, and each skip reason — payload size per case, and any deferred or skipped cases with the reason.

**Cost.** Three XQL aggregates per run, flat regardless of case count, measured at roughly 0.07 compute units. AI cost scales per case, which is what the selection settings control.

**Another tenant.** A prompt id is tenant-local. Install the pack, create the prompt there, then bind the aiTask — steps 2 and 3 are per tenant.

**After a pack upgrade.** The JOB and the entry point update normally. `SOC Case Analysis Phase` reverts to the shipped placeholder, so re-check task 10 and re-bind the aiTask if it has been replaced. The symptom is a run that completes with no verdict on any case.
