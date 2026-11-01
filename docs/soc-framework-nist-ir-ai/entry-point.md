---
title: "AI Entry Point"
---

# AI Entry Point

`EP_IR_NIST - AI` is the playbook the automation rule starts on each selected issue. It runs the framework's Foundation chain, asks the issue-assessment prompt for a disposition, and then runs the three issue-scope decisions. Pointing the automation rule at it is the lifecycle's on switch; pointing the rule elsewhere is the rollback.

## 1. What it does

Ten tasks in a fixed order. The first three belong to the framework; the rest are this lifecycle's.

| Task (by name) | Does |
|---|---|
| Set Lifecycle, Set Lifecycle Version | Stamps `SOCFramework.lifecycle = NIST_IR` and `lifecycle_version = 3` so every row this issue writes carries the lifecycle |
| `Foundation - Upon Trigger V3` | Classifies the source, normalizes the issue into `SOCFramework.Artifacts.*`, enriches, writes the case ledger row |
| Collect Intel for Assessment | Gathers the reputation roots Foundation produced (`DBotScore`, `File`, `IP`, `Domain`, `URL`, `WildFire`, `AttackPattern`, `Tactic`) into `Assessment.Intel`, since a prompt variable binds one path |
| `SOCFWIssueAssessment` (aiTask) | Runs the prompt quietly (`quietmode: 1`, so the rendered prompt is not echoed to the War Room) and writes `Assessment.AI` |
| Promote Assessment Output | Parses the JSON, promotes the fields to `Assessment.*`, writes the `ai_reasoning` row |
| Render Assessment | Posts the scannable verdict entry to the War Room |
| Emergency Response | Contains the issue now if an emergency policy matches; see *Emergency Response* |
| Elevate Case | Stars or raises the case per the elevate rules; see *Elevate Case* |
| Close Decision | Closes the issue if the closure policy allows; see [AI Close Decision](close-decision.md) |

Promote runs before the three decisions on purpose: each decision reads `Assessment.*`, and a decision that ran before promotion would read nothing and hold every issue.

## 2. Where the switch lives

| Where | Key | Shipped default | Evaluation | Production |
|---|---|---|---|---|
| Automation rule | `WHEN issue is created … THEN EP_IR_NIST - AI` | none | the three-branch rule from [Install NIST IR AI](../evaluate/install-nist-ir-ai.md) | same, sized per tenant; rollback is pointing the rule at another playbook |
| Playbook file `ai/nist-ir/EP_IR_NIST_-_AI.yml` | aiTask named `SOCFWIssueAssessment` → `aiTaskId` | the authoring tenant's id; resolves nowhere else | bound to this tenant's prompt at install | re-bound after every upgrade |
| Context | `SOCFramework.lifecycle`, `SOCFramework.lifecycle_version` | `NIST_IR`, `3` | as shipped | as shipped |

> The playbook is uploaded by hand, not shipped in the pack, because the aiTask carries a tenant-local prompt id. Upgrading the pack does not touch it; upgrading the playbook means re-uploading the file and re-binding the aiTask.

## 3. Turn it on

1. Complete [Install NIST IR AI](../evaluate/install-nist-ir-ai.md) through the binding step, so the aiTask shows `SOCFWIssueAssessment`.
2. Run the playbook once on an issue from the Playbooks page and confirm `Assessment.AI` is populated.
3. Create the automation rule, placed above any enrichment rule whose conditions overlap it; only the first matching rule runs per issue.
4. Watch the first ten issues: each should show the verdict entry in its War Room within about two minutes.

To roll back, point the rule at a different playbook. Nothing else needs undoing; the decisions were shadowed or policy-gated throughout.

## 4. Verify

```
config timeframe = 1h
| dataset = xsiam_socfw_ir_execution_raw
| filter event_type = "ai_reasoning"
| fields _time, lifecycle, execution_mode
| sort desc _time
```

**Expected:** one `ai_reasoning` row per issue the rule selected, `lifecycle = NIST_IR`. An issue the rule selected with no row means the playbook stopped before promotion: open its War Room and read the aiTask entry first, then the Foundation errors.

## 5. What it feeds

| Surface | What you see |
|---|---|
| Issue War Room | The verdict entry on line one, then the story and closure blockers |
| Issue layout | Served only to issues whose `playbookId` is `EP_IR_NIST - AI`, so the layout follows the rule |
| Dataset `xsiam_socfw_ir_execution_raw` | `ai_reasoning`, then one decision row each from emergency, elevate and close |
| Dashboards `NIST IR - … (AI)` | Time to detect and investigate per issue; what the decisions would have done against what they did |

---

Verified against `ai/nist-ir/EP_IR_NIST_-_AI.yml` and **soc-framework-nist-ir-ai 1.6.0** source · Tenant run: **pending** · Internal mapping: Notion, AI › Issue Assessment master page
