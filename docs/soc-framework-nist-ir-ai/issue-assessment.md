---
title: "Issue Assessment"
---

# Issue Assessment

On every issue the automation rule admits, the lifecycle asks a prompt one question: is this worth a person's time, and what would have to be true to close it? The answer is a disposition, not an investigation. It is written to the War Room where the analyst reads it first, promoted into context where the three decisions read it, and recorded as a row so its accuracy can be measured against what analysts later did.

## 1. What it does

The prompt `SOCFWIssueAssessment` runs after the framework's Foundation chain has normalized and enriched the issue, so it reasons over the contract (`SOCFramework.*`) and the reputation intel gathered into `Assessment.Intel`, never over the raw alert. It returns one JSON object with fourteen fields. The ones the lifecycle acts on:

| Field | Meaning | Read by |
|---|---|---|
| `verdict` | `malicious`, `suspicious`, `benign`, `inconclusive`: did the thing the detection claims actually happen | elevate, emergency, close |
| `confidence` | `high`, `medium`, `low` for the verdict | elevate, emergency |
| `exposure` | `none`, `attempted`, `delivered`, `executed`, `unknown`: what reached the asset | emergency, close |
| `already_contained` | a control already acted (blocked, quarantined, dropped) | close |
| `escalate_recommended` | a person should look now | elevate |
| `closure_recommended`, `closure_reason`, `closure_confidence`, `closure_blockers` | whether it could close unseen, under which resolution reason, how sure, and what a person would have to verify first | close |
| `primary_entity_name`, `primary_entity_type`, `mitre_tactic`, `mitre_technique_id` | what the issue is about | emergency, layout |
| `story` | four short labelled lines (what fired, exposure, verdict, next check) for the War Room | render |

Two rules the prompt is built around, because they are where analysts' hand-closes clustered: a verdict is not an exposure (a blocked malicious URL is a true detection with no exposure, not a false positive), and anything that landed never satisfies closure, since removing it is a remediation decided at case scope.

## 2. Where the switch lives

| Where | Key | Shipped default | Evaluation | Production |
|---|---|---|---|---|
| AI Prompt `SOCFWIssueAssessment` (tenant) | model settings | Flash tier · temperature 0 · max output tokens 16000 · timeout 120s · output `Assessment.AI` · structured output off | as shipped | as shipped; raise the tier only on a measured agreement number |
| AI Prompt `SOCFWIssueAssessment` (tenant) | eight inputs, each `SetIfEmpty` → `no content` | per the recipe `SOCFWIssueAssessment.prompt.md` | as recipe | as recipe |
| `EP_IR_NIST - AI` | the aiTask named `SOCFWIssueAssessment` → `aiTaskId` | authoring tenant's id | bound at install | re-bound after upgrade |
| `SOCOptimizationConfig_V3` | `Case Analysis JOB.fields.CaseIntelRoots` (shared with the case job) | `DBotScore,File,IP,Domain,URL,WildFire,AttackPattern,Tactic` | as shipped | add a provider root (for example a new reputation feed) here and both prompts see it |

> The prompt body and its settings are created by hand on each tenant from the recipe file in the pack. The recipe is the current copy; a tenant prompt that drifts from it voids any measurement taken on that tenant.

## 3. Turn it on

The assessment runs whenever the entry point runs; there is no separate switch. To change what it does:

1. Edit the recipe, never the tenant prompt first. The recipe is versioned and the gate checks fixtures against it.
2. Paste the new body into the tenant prompt and save. The binding in the playbook does not change.
3. Run the entry point on one issue and read the aiTask entry in its War Room: it carries the full rendered prompt and the model's reply.
4. Watch the next hundred issues for parse errors and `no_output` rows before trusting the change.

## 4. Verify

```
config timeframe = 7d
| dataset = xsiam_socfw_ir_execution_raw
| filter event_type = "ai_reasoning"
| comp count() as rows by lifecycle, execution_mode
```

**Expected:** one row per issue the automation rule admitted. Then open any issue's War Room: the verdict entry is on line one, the four-line story follows, and `Assessment.AI` in context holds the full object. An issue with the layout but no verdict entry means the aiTask returned nothing: read the aiTask's own War Room entry first (it holds the rendered prompt and the reply), then check the binding.

## 5. What it feeds

| Surface | What you see |
|---|---|
| Issue War Room and the layout's Assessment tab | Verdict, story, closure blockers; the feedback buttons record whether the analyst agreed |
| Dataset rows `ai_reasoning` | One per assessment, joinable to the decision rows that read it |
| Dataset rows `ai_feedback` | Analyst agreement, by verdict and confidence, which is how the prompt is tuned |
| Dashboards `NIST IR - … (AI)` | Time to investigate per issue, and the would-close and would-star counts the decisions derive from this assessment |

---

Verified against **soc-framework-nist-ir-ai 1.6.0** source (`SOCFWIssueAssessment.prompt.md`, `SOCFWPromoteAssessment`, `SOCFWRenderAssessment`) and the prompt master page · Tenant run: **pending** · Internal mapping: Notion, AI › Issue Assessment
