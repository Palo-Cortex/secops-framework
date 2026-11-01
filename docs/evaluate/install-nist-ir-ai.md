---
title: "Install NIST IR AI"
---

# Install NIST IR AI

Add the NIST IR AI lifecycle on top of an installed framework: one pack through the Package Manager, two AI Prompts created by hand, two playbooks uploaded by hand and bound to those prompts, an automation rule, and a scheduled job. About 45 minutes. Until the last two steps the lifecycle is installed and inert.

## Before you start

- The framework is installed and `!SOCFWHealthCheck` reports no `FAIL` (see [Install the SOC Framework](install.md)).
- AI Prompts are available on this tenant: Investigation & Response → Automation → **AI Prompts** exists and you can create one.
- At least one evaluation data source is connected and its issues carry a category in `SOCProductCategoryMap_V3`. An uncategorised source falls through to `generic` and the assessment has nothing to read.
- You can upload playbooks through the UI.

Two parts of this lifecycle cannot ship in a pack: AI Prompts are created in the UI, and the two playbooks that call them carry an `aiTaskId` that only resolves on the tenant it was created on. Steps 2 to 4 exist for that reason, and step 4 repeats after every pack upgrade.

## 1. Install the pack

From the Playground:

```
!SOCFWPackManager action=apply pack_id=soc-framework-nist-ir-ai
```

This delivers the scripts, the two layouts and their rule, the three dashboards, the lists, and the `SOC Case Analysis` job definition (installed off). Confirm the scripts landed: Settings → Automations should list `SOCFWCollectIntel`, `SOCFWRenderAssessment`, `SOCFWPromoteAssessment`, `SOCFWCloseDecision`, `SOCFWCaseIterationSetup` and `SOCFWCaseVerdictReport`.

## 2. Create the two AI Prompts

Investigation & Response → Automation → **AI Prompts** → new prompt. Name each exactly as shown; the playbook tasks carry the same names, which is what makes step 4 unambiguous. The body of each prompt is in its recipe file in the pack; paste it verbatim. The recipe is the current copy of the prompt and its settings; if a value on this page and the recipe disagree, the recipe wins.

| Setting | `SOCFWIssueAssessment` | `SOCFWCaseAnalysis` |
|---|---|---|
| Recipe | `SOCFWIssueAssessment.prompt.md` | `SOCFWCaseAnalysis.prompt.md` |
| Model | Flash tier | Thinking tier |
| Temperature | `0` | `0` |
| Max output tokens | `16000` | `16000` |
| Timeout | `120s` | `120s` |
| Output context path | `Assessment.AI` | `Analysis.AI` |
| Use structured output | off | off |

Inputs for `SOCFWIssueAssessment`, each bound through `SetIfEmpty` with default `no content`:

| Variable | Context path |
|---|---|
| `product_category` | `SOCFramework.Product.category` |
| `product_key` | `SOCFramework.Product.key` |
| `issue_contract` | `SOCFramework` |
| `intel` | `Assessment.Intel` |
| `risk_score` | `SOCFramework.Investigation.RiskScore` |
| `linked_count` | `SOCFramework.Investigation.LinkedCount` |
| `alert_name` | `alert.name` |
| `alert_description` | `issue.details` |

Inputs for `SOCFWCaseAnalysis`, all bound to `CaseIter.*` (never to `inputs.Case.*`, which accumulates across iterations and produces duplicate verdicts):

| Variable | Context path |
|---|---|
| `case_id` | `CaseIter.ID` |
| `issue_count` | `CaseIter.IssueCount` |
| `categories` | `CaseIter.Categories` |
| `case_window` | `CaseIter.Window` |
| `shape_coverage` | `CaseIter.ShapeCoverage` |
| `case_payload` | `CaseIter.Payload` |
| `prior_verdict` | `CaseIter.PriorVerdict` |

> Do not lower the token ceilings. A reply that exceeds the ceiling is cut mid-string and arrives as unparseable JSON; both prompts have truncated at lower settings, and on the Thinking tier the model's reasoning draws on the same budget as its output. 16000 is the default for both. Structured output stays off because the schema is described in the prompt body.

## 3. Upload the two playbooks

Investigation & Response → Automation → **Playbooks** → upload, in this order:

1. `ai/nist-ir/SOC_Case_Analysis_Phase.yml`
2. `ai/nist-ir/EP_IR_NIST_-_AI.yml`

Order matters: `JOB - SOC Case Analysis`, installed with the pack, resolves `SOC Case Analysis Phase` as its sub-playbook.

## 4. Bind each aiTask to its prompt

The uploaded playbooks point at prompt ids from another tenant. Open each, select the task, choose the prompt created in step 2, save.

| Playbook | aiTask | Prompt |
|---|---|---|
| `EP_IR_NIST - AI` | the task named `SOCFWIssueAssessment` (id `9002` in the current file) | `SOCFWIssueAssessment` |
| `SOC Case Analysis Phase` | the task named `AI Case Analysis` (id `10` in the current file) | `SOCFWCaseAnalysis` |

Find the task by its name, not its number. Each playbook has exactly one aiTask, and its name matches the prompt it binds to; the numeric id can change when a playbook is re-exported. The task shows the prompt name once bound. A pack upgrade replaces `SOC Case Analysis Phase` with the shipped placeholder, so re-check task `10` after every upgrade. The symptom of a lost binding is a playbook that completes with no verdict.

## 5. Create the automation rule

Investigation & Response → Automation → **Automation Rules**. Four platform behaviours shape how this rule is placed: rules run in order and only the first match runs for each issue; a manually created rule lands at the bottom of the table, below every recommended rule, so move it above any enrichment rule whose conditions overlap it; rules fire on initial ingestion only, so a later severity change or enrichment never re-triggers; and legacy XDR 3.x rules under **XDR Automation** still fire and do not appear in this table.

The rule as it runs today, name `NIST IR (800-61)`:

```
WHEN  issue is created
IF    ( issue domain = Security
        AND observation time in last 24H
        AND starred = True )
   OR ( detection method in (XDR Analytics BIOC, XDR BIOC, XDR IOC,
                             XDR Analytics, XDR Agent)
        AND issue domain = Security
        AND name doesn't contain "Spam Bot Traffic"
        AND observation time in last 24H )
   OR ( severity in (Medium, High, Critical)
        AND issue domain = Security
        AND observation time in last 24H )
THEN  EP_IR_NIST - AI
```

Three branches, each for a reason:

| Branch | Why |
|---|---|
| Starred | A person flagged the issue, at any severity. The only way in for anything the other branches exclude. |
| Detection method | Platform-engine issues are mostly Low, and the platform starts automation on Low Analytic issues and on Low ABIOC issues tagged Identity or Cloud. This branch is what lets them in; without it a severity gate would drop impossible-traveller, brute-force and suspicious-download detections. It does not override the platform floor below. |
| Severity | Vendor sources, where Medium and above is the fidelity signal. |

Two parts of the rule are situational:

- **`observation time in last 24H`** on every branch is a guard against a platform re-run that processes issues back in time and starts the playbook against a whole backlog. It is a rare failure with a large blast radius, so it is cheap insurance, and it stays in. It also means a scenario replay must stamp events with the current time: a replay that carries the original event timestamps never matches this rule and nothing enters the lifecycle. The framework's replay tooling is being updated to send current timestamps; until a replay does, drop the bound on an evaluation tenant and put it back before handover.
- **`name doesn't contain "Spam Bot Traffic"`** works around a defect in native Check Point ingestion that makes one detector most of the analytics volume. Include it only on a tenant ingesting Check Point natively.

Size the rule on this tenant before saving it:

```
config timeframe = 30d
| dataset = issues
| filter xdm.issue.domain = "SECURITY"
| comp count() as issues by xdm.issue.detection.method, xdm.issue.severity
| sort desc issues
```

The platform applies its own floor underneath any rule. Automation rules act on Medium and higher severity issues, on Low severity Analytic issues (`MAGNIFIER` in the `issues` dataset), and on Low severity ABIOC issues (`ANALYTICS_BIOC`) tagged Identity or Cloud. A Low issue raised by a correlation rule never starts a playbook, however the rule is written. If a Low issue you expected is missing from the lifecycle, check its detection method and category before touching the rule.

## 6. Turn on the Case Analysis job

The job ships off. The thresholds it reads are the `Case Analysis JOB` block of `SOCOptimizationConfig_V3`; the shipped values are fine for an evaluation.

```
!SOCFWConfig command=job job="SOC Case Analysis" value=on owner=<email> apply=yes
```

It runs every 10 minutes with *trigger new instance while running* off. Keep the interval clear of run time; overlapping runs repeat work.

## 7. Verify

The automation rule and the layout rule are set by hand and the framework cannot install or inspect them today, so `!SOCFWHealthCheck` says nothing about them. Steps 1 to 3 are the only checks for those two settings.

1. Open both uploaded playbooks: no missing-component warning, and the two tasks show their prompt names.
2. Run `EP_IR_NIST - AI` on one issue from the Playbooks page. The issue's War Room shows the rendered verdict, and context holds `Assessment.AI`.
3. Open the issue: the layout shows the **Assessment** tab with the verdict, the containment and feedback buttons, and the **Context** tab. If the Assessment section is missing, the layout rule did not install; re-upload the whole pack zipped, since a layout rule cannot be uploaded on its own.
4. Query the execution dataset:

```
config timeframe = 1h
| dataset = xsiam_socfw_ir_execution_raw
| filter event_type in ("ai_reasoning", "ai_close_decision", "elevate_decision", "emergency_decision")
| fields _time, event_type, execution_mode
| sort desc _time
```

**Expected:** an `ai_reasoning` row for the issue, and one decision row each from close, elevate and emergency, all `execution_mode = shadow` in evaluation mode. `!SOCFWHealthCheck` shows **JOB: SOC Case Analysis** on with your owner.

## Next

- **Run a scenario** — replay a known attack and watch the assessment, the case verdict and the shadowed containment.
- **Read the dashboards** — `NIST IR - Value Driver Metrics (AI)`, `NIST IR - Value Metrics (AI)` and `NIST IR - Value Metrics Shadow Mode (AI)`.
- **Take NIST IR AI live** (Deploy to production) — close decision, elevate and emergency response, one actor and one action at a time.

---

Verified against **soc-framework-nist-ir-ai 1.6.0** and `ai/nist-ir` source · Tenant run: **pending** · Internal mapping: Notion, Evaluate track › AI layer
