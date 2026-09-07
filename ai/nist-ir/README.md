# NIST IR AI — playbooks installed by hand

These two playbooks contain `aiTask` tasks and are **not** shipped in
`Packs/soc-framework-nist-ir-ai`. They are uploaded through the XSIAM UI after
the pack is installed.

| File | Entry point | aiTask | Prompt |
|---|---|---|---|
| `EP_IR_NIST_(800-61)_AI.yml` | yes — issue entry point | task 9002 | `SOCFWIssueAssessment` |
| `SOC_Case_Analysis_Phase.yml` | no — called by `JOB - SOC Case Analysis` | task 10 | `SOCFWCaseAnalysis` |

## Why they are not in the pack

An `aiTask` carries an `aiTaskId` pointing at an AI Prompt on one specific
tenant. Those ids do not exist anywhere else, and the prompts are not a
packageable content type — they are created in the UI.

The ids currently in these files are the deathstar ones and will not match
elsewhere:

```
SOCFWIssueAssessment   17c97289-2b16-48f9-8ebe-a17e954d4399
SOCFWCaseAnalysis      f018cd64-e2ce-464f-8051-55a12af30d9a
```

## Install order

Order matters. A playbook uploaded before its prompt exists cannot be bound to
it, and `JOB - SOC Case Analysis` cannot resolve its sub-playbook until
`SOC Case Analysis Phase` is present.

### 1. Install the packs

Install `soc-framework-nist-ir-ai` and its dependency `soc-framework-nist-ir`
through the SOC Framework Package Manager. This delivers the automations both
playbooks call, plus `JOB - SOC Case Analysis`.

Confirm the automations landed before continuing — `SOCFWCollectIntel`,
`SOCFWRenderAssessment`, `SOCFWPromoteAssessment` and `SOCFWCloseDecision` from
the AI pack, and `SOCFWCaseIterationSetup` and `SOCFWCaseVerdictReport` from
`soc-framework-nist-ir`.

### 2. Create the AI Prompts

**Investigation & Response → Automation → AI Prompts**

Create one prompt per row in the table above, using the definitions in
`Packs/soc-framework-nist-ir-ai/AI_PROMPTS.md`. Name them exactly as written —
the playbook task names match the prompt names, which is what makes the binding
in step 4 obvious.

### 3. Upload the playbooks

**Investigation & Response → Automation → Playbooks**

Upload `SOC_Case_Analysis_Phase.yml` first, then `EP_IR_NIST_(800-61)_AI.yml`,
so the JOB playbook installed with the pack can resolve its sub-playbook.

### 4. Rebind each aiTask

The uploaded `aiTaskId` values point at the tenant they were authored on, so
each `aiTask` needs pointing at the prompt created in step 2.

Open each playbook, select the `aiTask` task, and choose the matching prompt:

- `EP_IR_NIST (800-61) AI` — task **9002** → `SOCFWIssueAssessment`
- `SOC Case Analysis Phase` — task **10** → `SOCFWCaseAnalysis`

Save. The task shows the prompt name once bound.

### 5. Verify

- Both playbooks open without a missing-component warning
- `JOB - SOC Case Analysis` resolves `SOC Case Analysis Phase` as its sub-playbook
- Run `EP_IR_NIST (800-61) AI` on one issue and confirm `SOCFramework.Analysis.AI`
  is populated

## Updating these files

Edit on a tenant, then export and merge back — do not copy the export over the
file. A tenant export adds runtime-only keys (`aclowner`, `aclrelations`,
`outlinetasks`, `possibleresponses`, `vcShouldKeepItemLegacyProdMachine`), drops
`fromversion`, and serialises task scripts as `scriptName:` where the repo uses
`script:`.

Export with:

```
GET /xsoar/playbook/<url-encoded playbook name>/yaml
```
