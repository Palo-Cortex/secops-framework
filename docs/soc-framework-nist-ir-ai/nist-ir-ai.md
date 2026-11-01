---
title: "NIST IR AI"
---

# NIST IR AI

NIST IR AI is a lifecycle that runs on the SOC Framework: an AI assessment of every issue at trigger time, an AI analysis of every settled case on a schedule, and three deterministic decisions in between (elevate, emergency response, close) that call framework actions through the universal command. The framework supplies the normalized contract, the actions and the dataset; this lifecycle decides what to ask and when to act.

## 1. What it does

Two scopes, two playbooks.

**Issue scope** runs once per issue the automation rule selects. The entry point `EP_IR_NIST - AI` runs the framework's Foundation chain, gathers the reputation and intel the enrichment produced, asks the issue-assessment prompt for a disposition, writes the verdict to the War Room and to `Assessment.*`, then runs three decisions in order: emergency response (contain now if a policy matches), elevate case (star or raise severity), and close decision (close the issue if the closure policy allows). Every decision writes a row whether or not it acted.

**Case scope** runs every 10 minutes as `JOB - SOC Case Analysis`. It selects security cases that have settled, collapses each to its distinct alert shapes and entities with XQL, attaches one representative contract per shape, and hands one payload per case to `SOC Case Analysis Phase`, which asks the case-analysis prompt for a verdict over the whole case. The verdict lands in the case War Room and in `SOCFramework.Analysis.AI`. Where both scopes have run, the case verdict wins.

Nothing in either scope calls a vendor directly. Every change goes through the universal command, so it is shadowed or live per action and per actor exactly as the framework's switches say.

## 2. How it runs

| Step | Scope | Component | What it writes |
|---|---|---|---|
| Foundation | issue | `Foundation - Upon Trigger V3` (framework) | `SOCFramework.Product.*`, `SOCFramework.Artifacts.*` |
| Collect intel | issue | `SOCFWCollectIntel` | `Assessment.Intel` |
| Issue assessment | issue | aiTask → prompt `SOCFWIssueAssessment` | `Assessment.AI` |
| Promote and render | issue | `SOCFWPromoteAssessment`, `SOCFWRenderAssessment` | `Assessment.*`, War Room verdict, `ai_reasoning` row |
| Emergency response | issue | `SOCFWEmergencyResponse` → framework actions | `emergency_decision` row; `command` rows if it acted |
| Elevate case | issue | `SOCFWElevateCase` → `soc-star-case`, `soc-raise-case-severity` | `elevate_decision` row |
| Close decision | issue | `SOCFWCloseDecision` → `soc-close-issue` | `ai_close_decision` row |
| Case selection and collapse | case | `JOB - SOC Case Analysis`: `SOCFWCaseSelect`, `SOCFWBuildCasePayload`, `SOCFWFetchShapeContracts` | `case_analysis_run` row |
| Case analysis | case | `SOC Case Analysis Phase`: aiTask → prompt `SOCFWCaseAnalysis`, `SOCFWCaseVerdictReport` | `SOCFramework.Analysis.AI`, case War Room verdict, `case_analysis` row |

## 3. Framework actions it calls

| Decision | Actions | Shadowed by |
|---|---|---|
| Emergency response | `soc-clear-sessions`, `soc-revoke-tokens`, `soc-isolate-endpoint`, `soc-retract-email`, `soc-block-domain`, `soc-block-network-indicator`, `soc-close-issue-contained`, `soc-star-case`, `soc-raise-case-severity` | each action's `issue_emergency` actor flag |
| Elevate case | `soc-star-case`, `soc-raise-case-severity` | each action's `automation` actor flag |
| Close decision | `soc-close-issue` | `soc-close-issue` for actor `ai` |

The deployment modes set these flags as a bundle: `pov` leaves every emergency action shadowed and lets star and benign close run; `contain_identity_and_hosts` and `contain_all` take emergency actions live in two steps. See [Deployment Modes](../soc-optimization-unified/deployment-modes.md).

## 4. Where the switches live

| What | Where | Shipped default | Evaluation | Production |
|---|---|---|---|---|
| Which issues enter the lifecycle | automation rule → `EP_IR_NIST - AI` | none; the rule is created at install | the three-branch rule on [Install NIST IR AI](../evaluate/install-nist-ir-ai.md) | same, sized on the tenant |
| Case job on/off and thresholds | `!SOCFWConfig command=job job="SOC Case Analysis"`; `SOCOptimizationConfig_V3 → Case Analysis JOB.fields` | off; `CaseMinIssues=2`, `CaseMinShapes=2`, `CaseCampaignIssues=20`, `CaseWindowHours=72` | on, shipped thresholds | on, thresholds tuned to case volume |
| Emergency policies and guards | `SOCFrameworkPhasePolicy_V3 → phases.triage.emergency`; `!SOCFWConfig command=emergency` | `enabled=true`, `containable_roles=[workstation]`, verdict malicious at high confidence | shipped | protect list and roles set for this estate |
| Elevate rules | `SOCFrameworkPhasePolicy_V3 → phases.triage.elevate` | star on malicious at high confidence with `escalate_recommended`; never unstar | shipped | shipped |
| Closure bar | `SOCFWClosurePolicy` | `min_closure_confidence=low`, `require_no_blockers=true` | shipped | per customer |
| Prompt bodies and model settings | the prompt master, distributed with the lifecycle | per master | per master | per master |

## 5. Verify

```
config timeframe = 24h
| dataset = xsiam_socfw_ir_execution_raw
| filter event_type in ("ai_reasoning", "emergency_decision", "elevate_decision", "ai_close_decision", "case_analysis_run", "case_analysis")
| comp count() as rows by event_type, execution_mode
```

**Expected:** one `ai_reasoning` row per issue the rule selected, one of each decision row per issue, `case_analysis_run` rows every 10 minutes while the job is on, and `case_analysis` rows for cases that cleared the selection thresholds. In `pov` mode the decision rows read `execution_mode = shadow` except star and benign close.

## 6. What it feeds

| Surface | What you see |
|---|---|
| Issue layout `SOCFramework NIST IR AI Layout` | Verdict, story, closure blockers, containment buttons, feedback buttons, export |
| Case layout tab `Case Analysis` | The case verdict the lifecycle will act on |
| Dashboards `NIST IR - Value Driver Metrics (AI)`, `NIST IR - Value Metrics (AI)`, `NIST IR - Value Metrics Shadow Mode (AI)` | Time to detect, investigate and contain; cases auto-triaged and AI-would-close; analyst minutes returned; shadow against live |
| Dataset `xsiam_socfw_ir_execution_raw` | Every assessment and decision as a row, joinable to the framework's `command` rows |

---

Verified against **soc-framework-nist-ir-ai 1.6.0**, `ai/nist-ir` and **soc-optimization-unified 3.31.1** source · Tenant run: **pending** · Internal mapping: Notion, AI › Issue Assessment and Case Analysis master pages
