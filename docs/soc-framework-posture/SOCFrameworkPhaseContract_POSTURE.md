# SOCFrameworkPhaseContract_POSTURE

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

| Field | Value |
|---|---|
| Pack | `soc-framework-posture` |
| List Name | `SOCFrameworkPhaseContract_POSTURE` |
| Source | [`schemas/soc-framework/soc-framework-posture/SOCFrameworkPhaseContract_POSTURE.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/soc-framework/soc-framework-posture/SOCFrameworkPhaseContract_POSTURE.yaml) |

Posture phase contract — what each phase reads (framework artifacts + prior phases), writes, and routes to. Mirrors SOCFrameworkPhaseContract_V3 shape; names carry no _V3.

## Categories

- `posture_misconfig`
- `posture_compliance`
- `posture_drift`

## Phases

| Phase | Orchestrator | Purpose |
|---|---|---|
| `identify` |  | Detect/acknowledge the misconfig, drift, or compliance violation; classify. |
| `plan` |  | Prioritize, score risk, choose remediation, obtain approvals. |
| `execute` |  | Apply the remediation (config change, IaC PR, ticket) via Universal Command. |
| `verify` |  | Confirm the fix landed and no regression. |

## Routing

| phase | category | sub_playbook | role |
|---|---|---|---|
| `identify` | `posture_misconfig` | `SOC_Misconfig_Identify` | `canonical` |
| `identify` | `posture_compliance` | `SOC_Compliance_Identify` | `canonical` |
| `identify` | `posture_drift` | `SOC_Drift_Identify` | `canonical` |
| `plan` | `posture_misconfig` | `SOC_Misconfig_Plan` | `canonical` |
| `plan` | `posture_compliance` | `SOC_Compliance_Plan` | `canonical` |
| `plan` | `posture_drift` | `SOC_Drift_Plan` | `canonical` |
| `execute` | `posture_misconfig` | `SOC_Misconfig_Execute` | `canonical` |
| `execute` | `posture_compliance` | `SOC_Compliance_Execute` | `canonical` |
| `execute` | `posture_drift` | `SOC_Drift_Execute` | `canonical` |
| `verify` | `posture_misconfig` | `SOC_Misconfig_Verify` | `canonical` |
| `verify` | `posture_compliance` | `SOC_Compliance_Verify` | `canonical` |
| `verify` | `posture_drift` | `SOC_Drift_Verify` | `canonical` |

## Reads from Framework Namespace (`SOCFramework.*`)

| phase | source | role |
|---|---|---|
| `identify` | `SOCFramework.Artifacts.CloudPosture.CloudProvider` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.AccountID` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.AccountName` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.Region` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.ResourceID` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.ResourceARN` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.ResourceType` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.ResourceName` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.ResourceTags` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.ResourceOwner` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.FindingID` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.RuleID` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.RuleName` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.Severity` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.RiskScore` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.CurrentValue` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.ExpectedValue` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.ConfigPath` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.RemediationGuidance` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.AutoRemediable` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.ComplianceFramework` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.ComplianceControlID` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.ComplianceControlTitle` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.ComplianceStatus` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.IaCSource` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.IaCRepo` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.IaCFilePath` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.IaCCommitSHA` | `canonical` |
| `identify` | `SOCFramework.Artifacts.CloudPosture.DriftDetectedAt` | `canonical` |
| `plan` | `SOCFramework.Artifacts.CloudPosture.CloudProvider` | `canonical` |
| `plan` | `SOCFramework.Artifacts.CloudPosture.AccountID` | `canonical` |
| `plan` | `SOCFramework.Artifacts.CloudPosture.Region` | `canonical` |
| `plan` | `SOCFramework.Artifacts.CloudPosture.ResourceID` | `canonical` |
| `plan` | `SOCFramework.Artifacts.CloudPosture.ResourceType` | `canonical` |
| `plan` | `SOCFramework.Artifacts.CloudPosture.FindingID` | `canonical` |
| `plan` | `SOCFramework.Artifacts.CloudPosture.Severity` | `canonical` |
| `plan` | `SOCFramework.Artifacts.CloudPosture.RuleID` | `canonical` |
| `plan` | `SOCFramework.Artifacts.CloudPosture.RiskScore` | `canonical` |
| `plan` | `SOCFramework.Artifacts.CloudPosture.RemediationGuidance` | `canonical` |
| `plan` | `SOCFramework.Artifacts.CloudPosture.AutoRemediable` | `canonical` |
| `plan` | `SOCFramework.Artifacts.CloudPosture.ComplianceControlID` | `canonical` |
| `execute` | `SOCFramework.Artifacts.CloudPosture.CloudProvider` | `canonical` |
| `execute` | `SOCFramework.Artifacts.CloudPosture.AccountID` | `canonical` |
| `execute` | `SOCFramework.Artifacts.CloudPosture.Region` | `canonical` |
| `execute` | `SOCFramework.Artifacts.CloudPosture.ResourceID` | `canonical` |
| `execute` | `SOCFramework.Artifacts.CloudPosture.ResourceType` | `canonical` |
| `execute` | `SOCFramework.Artifacts.CloudPosture.FindingID` | `canonical` |
| `execute` | `SOCFramework.Artifacts.CloudPosture.Severity` | `canonical` |
| `execute` | `SOCFramework.Artifacts.CloudPosture.ResourceARN` | `canonical` |
| `execute` | `SOCFramework.Artifacts.CloudPosture.RuleID` | `canonical` |
| `execute` | `SOCFramework.Artifacts.CloudPosture.RemediationGuidance` | `canonical` |
| `execute` | `SOCFramework.Artifacts.CloudPosture.AutoRemediable` | `canonical` |
| `execute` | `SOCFramework.Artifacts.CloudPosture.ComplianceControlID` | `canonical` |
| `execute` | `SOCFramework.Artifacts.CloudPosture.IaCRepo` | `canonical` |
| `execute` | `SOCFramework.Artifacts.CloudPosture.IaCFilePath` | `canonical` |
| `verify` | `SOCFramework.Artifacts.CloudPosture.CloudProvider` | `canonical` |
| `verify` | `SOCFramework.Artifacts.CloudPosture.AccountID` | `canonical` |
| `verify` | `SOCFramework.Artifacts.CloudPosture.Region` | `canonical` |
| `verify` | `SOCFramework.Artifacts.CloudPosture.ResourceID` | `canonical` |
| `verify` | `SOCFramework.Artifacts.CloudPosture.ResourceType` | `canonical` |
| `verify` | `SOCFramework.Artifacts.CloudPosture.FindingID` | `canonical` |
| `verify` | `SOCFramework.Artifacts.CloudPosture.Severity` | `canonical` |
| `verify` | `SOCFramework.Artifacts.CloudPosture.RuleID` | `canonical` |
| `verify` | `SOCFramework.Artifacts.CloudPosture.ComplianceControlID` | `canonical` |

## Reads from Upstream Phases

| phase | source | from_phase | role |
|---|---|---|---|
| `plan` | `Identify.classification` | `identify` | `canonical` |
| `plan` | `Identify.exploitability_assessment` | `identify` | `canonical` |
| `execute` | `Plan.remediation_approach` | `plan` | `canonical` |
| `execute` | `Plan.approval_obtained` | `plan` | `canonical` |
| `verify` | `Execute.attempted` | `execute` | `canonical` |
| `verify` | `Execute.success` | `execute` | `canonical` |

## Writes (Top-Level)

| phase | target | type | init | role |
|---|---|---|---|---|
| `identify` | `Identify.finding_acknowledged` | `boolean` |  | `canonical` |
| `identify` | `Identify.classification` | `string` |  | `canonical` |
| `identify` | `Identify.first_detected_at` | `string` |  | `canonical` |
| `identify` | `Identify.detection_source` | `string` |  | `canonical` |
| `identify` | `Identify.exploitability_assessment` | `string` |  | `canonical` |
| `identify` | `Identify.story` | `array` |  | `canonical` |
| `plan` | `Plan.risk_score` | `number` | `0` | `canonical` |
| `plan` | `Plan.business_impact` | `string` |  | `canonical` |
| `plan` | `Plan.blast_radius` | `string` |  | `canonical` |
| `plan` | `Plan.remediation_approach` | `string` |  | `canonical` |
| `plan` | `Plan.approval_required` | `boolean` |  | `canonical` |
| `plan` | `Plan.approval_obtained` | `boolean` |  | `canonical` |
| `plan` | `Plan.approval_obtained_by` | `string` |  | `canonical` |
| `plan` | `Plan.target_remediation_deadline` | `string` |  | `canonical` |
| `plan` | `Plan.story` | `array` |  | `canonical` |
| `execute` | `Execute.attempted` | `boolean` |  | `canonical` |
| `execute` | `Execute.success` | `boolean` |  | `canonical` |
| `execute` | `Execute.execution_mode` | `string` |  | `canonical` |
| `execute` | `Execute.remediation_action_taken` | `string` |  | `canonical` |
| `execute` | `Execute.remediation_artifact` | `string` |  | `canonical` |
| `execute` | `Execute.executed_at` | `string` |  | `canonical` |
| `execute` | `Execute.executed_by` | `string` |  | `canonical` |
| `execute` | `Execute.error` | `string` |  | `canonical` |
| `execute` | `Execute.story` | `array` |  | `canonical` |
| `verify` | `Verify.attempted` | `boolean` |  | `canonical` |
| `verify` | `Verify.passed` | `boolean` |  | `canonical` |
| `verify` | `Verify.verification_method` | `string` |  | `canonical` |
| `verify` | `Verify.verified_at` | `string` |  | `canonical` |
| `verify` | `Verify.regression_detected` | `boolean` |  | `canonical` |
| `verify` | `Verify.story` | `array` |  | `canonical` |

## Writes by Category

| phase | category | target | type | init | role |
|---|---|---|---|---|---|
| `identify` | `posture_misconfig` | `Identify.misconfig_summary` | `string` |  | `canonical` |
| `identify` | `posture_compliance` | `Identify.compliance_summary` | `string` |  | `canonical` |
| `identify` | `posture_compliance` | `Identify.failed_control_id` | `string` |  | `canonical` |
| `identify` | `posture_drift` | `Identify.drift_summary` | `string` |  | `canonical` |
| `identify` | `posture_drift` | `Identify.iac_commit_sha_observed` | `string` |  | `canonical` |
| `plan` | `posture_compliance` | `Plan.compliance_deadline_driven` | `boolean` |  | `canonical` |
| `plan` | `posture_drift` | `Plan.iac_repo_pr_target_branch` | `string` |  | `canonical` |
| `execute` | `posture_misconfig` | `Execute.config_change_id` | `string` |  | `canonical` |
| `execute` | `posture_compliance` | `Execute.compliance_evidence_link` | `string` |  | `canonical` |
| `execute` | `posture_drift` | `Execute.iac_pr_url` | `string` |  | `canonical` |
| `execute` | `posture_drift` | `Execute.iac_pr_merged` | `boolean` |  | `canonical` |
| `verify` | `posture_compliance` | `Verify.compliance_status_after_fix` | `string` |  | `canonical` |
| `verify` | `posture_drift` | `Verify.drift_resolved` | `boolean` |  | `canonical` |
