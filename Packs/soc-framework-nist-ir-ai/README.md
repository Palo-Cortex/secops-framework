# AI content — NIST IR issue assessment and case analysis

Two AI steps at different scopes. **Issue assessment** runs once per issue, immediately after Upon Trigger, and decides whether an issue is worth a human's time. **Detection & Analysis** runs once per **case**, on a schedule, instead of once per issue.

Where both have run on the same issue, the case verdict wins — it sees what no single issue can.

**Install this pack only on AI-capable tenants.** It does nothing without its AI Prompts, which are not packageable content items and must be created by hand.

New to building these? Start with [AI_PROMPTS.md](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-framework-nist-ir-ai/AI_PROMPTS.md) — the platform constraints and framework conventions behind both recipes.

Requires `soc-framework-nist-ir` and `soc-optimization-unified`, which carry the supporting scripts, the phase contract and the configuration list.

## Contents

| Item | What it is |
| --- | --- |
| `EP_IR_NIST (800-61) AI` | Entry point. Builds the contract at Upon Trigger, then runs the issue assessment aiTask |
| `JOB - SOC Case Analysis` | The JOB playbook. Selects cases, collapses them, builds payloads |
| `SOC Case Analysis Phase` | Sub-playbook, once per case. Ships with a placeholder where the `aiTask` goes |
| `SOCFWCollectIntel` | Gathers the reputation context roots into one key for the issue prompt |
| `SOCFWRenderAssessment` | Renders the issue verdict as a War Room entry |
| `SOCFramework NIST IR AI Layout` | Issue layout for the AI lifecycle |
| `SOCFWDisplayAssessment` | Renders the assessment in the layout's Assessment section |
| `SOCFWDisplayAlertDetail` | Renders what fired — detection, MITRE, process, target, network, email |
| `SOCFWDisplayIdentityDevice` | Renders who and where — primary entity, user, sign-in source, endpoint, scope |
| `SOCFWAssessmentFeedback` | Records an analyst's judgement of the assessment to the dataset |
| `SOCFWFeedbackWrong`, `SOCFWFeedbackMissingContext` | Layout button handlers |
| `SOCFramework NIST IR AI` layout rule | Serves the AI layout to issues that ran the AI entry point |
| [SOCFWIssueAssessment prompt](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-framework-nist-ir-ai/SOCFWIssueAssessment.prompt.md) | Issue-scope AI Prompt — configuration and full body. Not installed by the pack |
| [SOCFWCaseAnalysis prompt](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-framework-nist-ir-ai/SOCFWCaseAnalysis.prompt.md) | Case-scope AI Prompt — configuration and full body. Not installed by the pack |

**Installing this pack changes nothing on its own.** All three playbooks side-load alongside `soc-framework-nist-ir`; the existing `EP_IR_NIST (800-61)_V3` keeps its inline lifecycle and keeps running. Nothing switches over until the automation trigger is pointed at `EP_IR_NIST (800-61) AI`, and pointing it back is the rollback.

The supporting scripts come from `soc-framework-nist-ir`: `SOCFWCaseSelect`, `SOCFWBuildCasePayload`, `SOCFWFetchShapeContracts`, `SOCFWCaseIterationSetup`, `SOCFWCaseVerdictReport`.

## Install

**1. Install this pack.** All three playbooks arrive. The chain runs, but neither AI step produces a verdict until its prompt exists and is bound.

**2. Create the issue assessment prompt.** Follow [SOCFWIssueAssessment.prompt.md](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-framework-nist-ir-ai/SOCFWIssueAssessment.prompt.md).

| Setting | Value |
| --- | --- |
| Model | Flash tier |
| Temperature | `0` |
| Max output tokens | `2500` |
| Timeout | `45s` |
| Output context path | `Assessment.AI` |
| Use structured output | **off** — the schema is described in the body |

Seven inputs, each bound through `SetIfEmpty` with default `no content`:

| Variable | Context path |
| --- | --- |
| `product_category` | `SOCFramework.Product.category` |
| `product_key` | `SOCFramework.Product.key` |
| `issue_contract` | `SOCFramework.Artifacts` |
| `intel` | `Assessment.Intel` |
| `risk_score` | `SOCFramework.Investigation.RiskScore` |
| `linked_count` | `SOCFramework.Investigation.LinkedCount` |
| `alert_name` | `alert.name` |

`no content` has to arrive as a value the model can read rather than as a missing variable — a sparse category leaves most of the contract empty, and the prompt distinguishes "asked and got nothing" from "never asked". Do not raise the token ceiling below 2500: at 1200 a real endpoint contract truncated mid-reply.

**3. Bind it.** Open `EP_IR_NIST (800-61) AI`, task `9002` — *SOCFWIssueAssessment* — and point its `aiTaskId` at the prompt created in step 2.

**Prompt ids are tenant-local.** The id shipped in the pack belongs to the tenant the content was authored on and will not resolve anywhere else, so this binding is required on every tenant and after every pack upgrade.

**4. Create the case analysis prompt.** Follow [SOCFWCaseAnalysis.prompt.md](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-framework-nist-ir-ai/SOCFWCaseAnalysis.prompt.md).

| Setting | Value |
| --- | --- |
| Model | Thinking tier |
| Temperature | `0` |
| Max output tokens | `4000` |
| Timeout | `120s` |
| Output context path | `Analysis.AI` |
| Use structured output | **off** — the schema is described in the body |

Seven inputs, all written once per case by `SOCFWCaseIterationSetup`:

| Variable | Context path |
| --- | --- |
| `case_id` | `CaseIter.ID` |
| `issue_count` | `CaseIter.IssueCount` |
| `categories` | `CaseIter.Categories` |
| `case_window` | `CaseIter.Window` |
| `shape_coverage` | `CaseIter.ShapeCoverage` |
| `case_payload` | `CaseIter.Payload` |
| `prior_verdict` | `CaseIter.PriorVerdict` |

**Bind to `CaseIter.*`, never to `inputs.Case.*`.** XSIAM runs a task once per element when an argument resolves to an array, and the sub-playbook input accumulates across forEach iterations — binding to it fires every task once per case seen so far, producing duplicate verdicts and rendering one case's reasoning under another's header. A `Stringify` transformer does not fix it.

Create this before binding in step 5.

**5. Bind the case `aiTask`.** Open `SOC Case Analysis Phase`, replace task 10 — the *AI Case Analysis* title — with an aiTask pointed at the prompt from step 4. Save.

A pack upgrade replaces this playbook with the shipped placeholder, so re-check the binding after any upgrade and re-bind if needed. Nothing else is lost: the JOB, the entry point and all thresholds upgrade normally.

**6. Check the layout rule.** The pack ships `SOCFramework NIST IR AI`, which serves `SOCFramework NIST IR AI Layout` to any issue whose `playbookId` is `EP_IR_NIST (800-61) AI`. Issues on the deterministic entry point keep the standard NIST IR layout, so the rule is self-scoping and reverts with the trigger.

The AI layout has two tabs rather than three:

- **Assessment** — the verdict, two feedback buttons, then Work Plan and Notes. What the analyst opens the issue for, and what they do about it.
- **Context** — Alert Detail, Alert Identity, Identity & Device Context, Endpoint Status, NIST IR Timeline, Email Threat Signal and Indicators.

Containment, Eradication and Recovery are gone, because in this lifecycle those are decided at case scope rather than per issue. The duplicate indicators section is gone too — it appeared on both original tabs.

`Alert Detail` and `Identity & Device` read `SOCFramework.Artifacts.*` directly rather than resolving through `Analysis.*`, which this lifecycle never populates — it writes `Assessment.*`. The NIST IR equivalents render empty here for that reason, which is why this pack carries its own.

Both draw only the groups that resolved, so an endpoint detection shows process and target detail with no empty network or email headings, and an identity alert shows sign-in source without an empty process block. A section that renders nothing at all means the contract is empty — check the alert's source has a category in `SOCProductCategoryMap_V3`, since an uncategorised source falls through to `generic` and populates no artifacts.

**Layout rules cannot be uploaded on their own.** The SDK rejects a standalone layout rule and requires the whole pack zipped:

```
demisto-sdk upload -i Packs/soc-framework-nist-ir-ai -z --marketplace marketplacev2
```

If the Assessment section does not appear, this is the first thing to check — an unzipped pack upload installs everything else and silently skips the rule.

**7. Configure.** Add or check the `Case Analysis JOB` block in `SOCOptimizationConfig_V3` — see Settings below.

**8. Point the automation trigger** at `EP_IR_NIST (800-61) AI` when ready to move to case scope. Until this step, the pack is installed and inert. Point it back at `EP_IR_NIST (800-61)_V3` to roll back.

**9. Create the scheduled Job** in the Jobs UI:

| Setting | Value |
| --- | --- |
| Playbook | `JOB - SOC Case Analysis` |
| Recurring | Every 10 minutes |
| Trigger new instance while running | **Off** |
| Ending | Never |

Keep the interval well clear of run duration. Runs take minutes on a busy tenant, and overlapping executions repeat work.

## How the issue assessment runs

`EP_IR_NIST (800-61) AI` chains: **Foundation - Upon Trigger V3 → Collect Intel → SOCFWIssueAssessment → Render Assessment → Promote Assessment Output → Done.**

**Why intel is collected separately.** Foundation's enrichment runs the reputation commands, but their verdicts land in standard context roots — `DBotScore`, `IP`, `Domain`, `File`, `URL` and friends — not inside `SOCFramework.Artifacts`. A prompt variable binds one path, so `SOCFWCollectIntel` gathers them into `Assessment.Intel` first. The root list comes from `SOCOptimizationConfig_V3` → `CaseIntelRoots`, shared with the case JOB, so adding Recorded Future or GTI there reaches both paths. Unit 42 Intelligence and VirusTotal are reputation providers and arrive through those roots with no extra binding.

**Why the aiTask is quiet.** An `aiTask` at the default echoes its entire rendered prompt into the War Room — roughly 10KB on every issue. Task `9002` runs `quietmode: 1`; `9003` prints the verdict instead.

**Why Render runs before Promote.** Promote depends on `SOCPromoteAIPhaseOutput` from `soc-framework-nist-ir`. Where that script is absent, the task marks itself *and everything downstream* `WillNotBeExecuted` — `skipunavailable` does not skip and continue. Rendering first means an analyst still gets the verdict even if the dataset write cannot run.

**What the assessment decides.** A disposition, not an investigation: `verdict`, `confidence`, `exposure`, `already_contained`, `escalate_recommended`, and the `closure_*` fields, with a short story. Verdict and exposure are deliberately separate — a detection can be correct and nothing can have happened, and calling that a false positive feeds bad signal into detection tuning.

**Where the issue verdict goes**

- `Assessment.AI` on the issue, plus the flat fields promoted into `Assessment.*`
- The issue War Room — one entry per issue, in the same format as the case verdict report
- The layout's **Assessment** section, via `SOCFWDisplayAssessment`
- `xsiam_socfw_ir_execution_raw` — an `ai_reasoning` row with `phase: Assessment`

The layout section shows the case verdict beneath the issue assessment where the case JOB has also run, with a note that the case verdict is the one to act on when they differ.

**Cost and concurrency.** One Flash call per issue on the trigger path, so both scale with issue volume. This is the step to watch on a busy tenant — measure wall time in shadow before pointing a high-volume trigger at this playbook.

**If every verdict comes back `inconclusive`**, the contract is not reaching the prompt. Check that `SOCFrameworkNormalizeMap_NIST_IR` and `SOCFrameworkEnrichmentMap_NIST_IR` are installed and parse, and that the alert's source has a category in `SOCProductCategoryMap_V3` — a source with no category falls through to `generic`, which has no `Artifacts.*` structure and fires no enrichment lanes.

## Measuring the assessment

The Assessment tab carries two buttons, which write an `ai_feedback` row to `xsiam_socfw_ir_execution_raw` through `SOCFWAssessmentFeedback`:

- **AI got this wrong** — the assessment reached the wrong answer
- **Missing context** — it reasoned correctly over an incomplete contract

Only these two, because everything else is already recorded. An analyst closing an issue picks from the resolution dropdown — True Positive, False Positive, Known Issue — which is the verdict judgement in the tenant's own vocabulary, and whether it warranted escalation is visible in what happened to the issue. `closure_reason` in the prompt uses those same values so the two join directly. Asking an analyst to state twice what closure already says buys nothing and crowds the tab.

These two are not recoverable that way. **Wrong** is recorded against the verdict as it stood, on an issue that may stay open for days and be re-assessed in between. **Missing context** has no resolution value at all, and it is the distinction that decides where the fix goes: a model problem is a prompt change, an incomplete contract is a normalization or routing one.

Each row snapshots the verdict, confidence, exposure and the escalate and closure flags, plus the analyst, category and product key. That is the difference from earlier free-text agreement tags, where the comment was the only record and carried no verdict, no confidence, and no indication of which model was being judged.

**Both buttons ask for a comment.** Optional, but analysts should give one — the button records that there was a miss, and only a comment records why.

**Missing context** is the more insistent of the two. "No process lineage" and "no reputation on the C2 address" are different gaps with different fixes, and nothing else on the row distinguishes them; without the comment it says only that something was absent.

**Wrong** asks for the case the resolution cannot show. Wrong plus a Known Issue resolution is environment context; wrong plus True Positive on a benign verdict is a reasoning miss — both recoverable from the join. What is not recoverable is a right verdict reached for the wrong reason, or evidence cited that was not there, and that is the failure most worth catching early.

Either way the comment is enrichment. Agreement is measurable from the rows whether or not anyone writes one.

Each button has its own thin handler script rather than one script taking an argument. A layout button whose script declares an argument opens a prompt whose Submit never enables, which is why `SOCFramework_ManualIsolateEndpoint` and `SOCFramework_ManualDeisolateEndpoint` are separate scripts too.

Explicit disagreement, by category:

```
dataset = xsiam_socfw_ir_execution_raw
| filter event_type = "ai_feedback"
| comp count() as n by feedback, alert_category, verdict, confidence
| sort desc n
```

Verdict agreement across everything closed, which needs no analyst action:

```
dataset = xsiam_socfw_ir_execution_raw
| filter event_type = "ai_reasoning" and phase = "Assessment"
| join type = inner (dataset = issues | fields xdm.issue.id as iid, xdm.issue.status.resolution_reason as resolution) as i i.iid = incident_id
| comp count() as n by alert_category, verdict, resolution
```

The cell that decides whether auto-close is safe is narrower still: assessments that recommended closure where the issue was later escalated or resolved true positive. That has to be zero across a real sample in a category before closing anything in that category.

## Auto-close rules

Auto-close is **not** built yet — the assessment writes a verdict and does nothing else. When it is, these hold:

**A starred issue is always closed by a person.** Starring is set by configuration at alert creation and marks what the SOC has scoped in for analysts. That is a guard, not a setting: it sits above the confidence threshold and is not configurable, because a customer should not be able to configure away human ownership of an issue their own SOC scoped in.

**The threshold is per category, on `closure_confidence`, not `confidence`.** Those two are separate in the prompt on purpose — escalating an issue is recoverable, closing one is a silent miss, so closure is held to a higher bar. Reading the general confidence field would quietly discard that.

**Levels, not percentages.** Model-emitted confidence clusters at a handful of values and is not a probability, so a numeric threshold tunes on noise and invites reading 90 as nine-in-ten. The real decision space is close-on-high, or close-on-high-and-medium.

**Enable per category, each on its own evidence.** Endpoint normalizes 63 fields where an unrouted network source normalizes none, so a single threshold across both is meaningless.

**Never close on a true-positive verdict at any confidence.** Only benign, known issue, or no-exposure outcomes are closable; a high-confidence malicious verdict escalates.

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

Issue assessment, per issue:

- `Assessment.AI` on the issue — deliberately not `Analysis.AI`, which the case verdict owns. Colliding on one key would let the last writer win silently, and keeping them apart lets the two be compared

Case analysis, per case:

- `SOCFramework.Analysis.AI` on the case — the current verdict, read by Containment and Auto Triage
- The case War Room — one entry per case, tagged `socfw-case-verdict`; earlier ones tagged `socfw-superseded`
- `xsiam_socfw_ir_execution_raw` — a `case_analysis` row per case, a `case_analysis_run` row per run

**Reading a run.** The JOB's own War Room shows selection counts — `scanned`, `candidates`, and each skip reason — payload size per case, and any deferred or skipped cases with the reason.

**Cost.** Issue assessment is one Flash call per issue on the trigger path, so its cost and its concurrency both scale with issue volume — it is the step to watch on a busy tenant. For the JOB: three XQL aggregates per run, flat regardless of case count, measured at roughly 0.07 compute units. AI cost scales per case, which is what the selection settings control.

**Another tenant.** Prompt ids are tenant-local. Install the pack, create both prompts there, then bind both aiTasks — steps 2 through 5 are per tenant.

**After a pack upgrade.** The JOB updates normally. `SOC Case Analysis Phase` reverts to the shipped placeholder, so re-check task 10 and re-bind. `EP_IR_NIST (800-61) AI` reverts task `9002` to the placeholder prompt id, so re-check that binding too. The symptoms are a JOB run that completes with no verdict on any case, and issues reaching Done with nothing at `Assessment.AI`.
