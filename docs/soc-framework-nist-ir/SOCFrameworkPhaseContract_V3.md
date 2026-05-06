# SOCFrameworkPhaseContract_V3

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

| Field | Value |
|---|---|
| Pack | `soc-framework-nist-ir` |
| List Name | `SOCFrameworkPhaseContract_V3` |
| Source | [`schemas/soc-framework/soc-framework-nist-ir/SOCFrameworkPhaseContract_V3.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/soc-framework/soc-framework-nist-ir/SOCFrameworkPhaseContract_V3.yaml) |

NIST IR phase contract — what each phase reads, writes, and routes to

## Validation

**Required blocks:** `phases`, `categories`, `routing`, `writes`

### Block Rules

| Block | Type | Item-Required Fields |
|---|---|---|
| `phases` | mapping | orchestrator, purpose |
| `routing` | list | phase, category, sub_playbook |
| `reads_from_framework` | list | phase, source |
| `reads_from_phases` | list | phase, from_phase, source |
| `writes` | list | phase, target, type, init |
| `writes_by_category` | list | phase, category, target, type, init |

### Drift Gates

- **categories_subset_of_product_map** — `source_block=categories`
- **routing_playbooks_exist** — `block=routing`, `field=sub_playbook`
- **cross_reference** — `from_block=reads_from_phases`, `from_field=source`, `partition_field=from_phase`, `to_block=writes`, `to_field=target`, `to_partition_field=phase`

## Emit

### `group_by`

| block | key | into | drop_key_in_items |
|---|---|---|---|
| `routing` | `phase` | `routing_by_phase` | `✓` |
| `reads_from_framework` | `phase` | `reads_from_framework_by_phase` | `✓` |
| `reads_from_phases` | `phase` | `reads_from_phases_by_phase` | `✓` |
| `writes` | `phase` | `writes_by_phase` | `✓` |
| `writes_by_category` | `phase` | `writes_by_category_by_phase` | `✓` |

## Categories

- `endpoint`
- `email`
- `identity`

## Phases

| Phase | Orchestrator | Purpose |
|---|---|---|
| `analysis` | `SOC_Analysis_V3` | Determine verdict, confidence, scope, and recommended response from raw alerts and SOCFramework artifacts. |
| `containment` | `SOC_Containment_V3` | Stop the spread — isolate hosts, block users, quarantine email. |
| `eradication` | `SOC_Eradication_V3` | Remove persistence and remediate compromised entities. |
| `recovery` | `SOC_Recovery_V3` | Restore systems to known-good state and establish monitoring. |

## Routing

| phase | category | sub_playbook |
|---|---|---|
| `analysis` | `endpoint` | `SOC_EndPoint_Analysis_V3` |
| `analysis` | `email` | `SOC_Email_Analysis_V3` |
| `analysis` | `identity` | `SOC_Identity_Analysis_V3` |
| `containment` | `endpoint` | `SOC_Endpoint_Containment_V3` |
| `containment` | `email` | `SOC_Email_Containment_V3` |
| `containment` | `identity` | `SOC_Identity_Containment_V3` |
| `eradication` | `endpoint` | `SOC_EndPoint_Eradication_V3` |
| `eradication` | `email` | `SOC_Email_Eradication_V3` |
| `eradication` | `identity` | `SOC_Identity_Eradication_V3` |
| `recovery` | `endpoint` | `SOC_EndPoint_Recovery_V3` |
| `recovery` | `email` | `SOC_Email_Recovery_V3` |
| `recovery` | `identity` | `SOC_Identity_Recovery_V3` |

## Reads from Framework Namespace (`SOCFramework.*`)

| phase | source |
|---|---|
| `analysis` | `SOCFramework.Artifacts` |
| `analysis` | `SOCFramework.Artifacts.CommandLine` |
| `analysis` | `SOCFramework.Artifacts.Email` |
| `analysis` | `SOCFramework.Artifacts.Email.From` |
| `analysis` | `SOCFramework.Artifacts.Email.Subject` |
| `analysis` | `SOCFramework.Artifacts.Email.ThreatType` |
| `analysis` | `SOCFramework.Artifacts.Email.ThreatURL` |
| `analysis` | `SOCFramework.Artifacts.Email.To` |
| `analysis` | `SOCFramework.Artifacts.EndPointID` |
| `analysis` | `SOCFramework.Artifacts.FeaturedHost` |
| `analysis` | `SOCFramework.Artifacts.File` |
| `analysis` | `SOCFramework.Artifacts.HostName` |
| `analysis` | `SOCFramework.Artifacts.NetworkArtifacts` |
| `analysis` | `SOCFramework.Artifacts.ProcessNames` |
| `analysis` | `SOCFramework.Artifacts.UserName` |
| `analysis` | `SOCFramework.Artifacts.Verdict` |
| `analysis` | `SOCFramework.Email.HighValueUserInvolved` |
| `analysis` | `SOCFramework.Email.reported_by` |
| `analysis` | `SOCFramework.Email.threat_id` |
| `analysis` | `SOCFramework.Email.threat_status` |
| `analysis` | `SOCFramework.Investigation.LinkedCount` |
| `analysis` | `SOCFramework.Investigation.RiskScore` |
| `analysis` | `SOCFramework.Mitre` |
| `analysis` | `SOCFramework.Mitre.Tactic` |
| `analysis` | `SOCFramework.Mitre.Tactic.ID` |
| `analysis` | `SOCFramework.Mitre.Technique` |
| `analysis` | `SOCFramework.Mitre.Technique.ID` |
| `analysis` | `SOCFramework.Product.category` |
| `analysis` | `SOCFramework.Product.key` |
| `analysis` | `SOCFramework.phase` |
| `containment` | `SOCFramework.Artifacts.Domain` |
| `containment` | `SOCFramework.Artifacts.Email.From` |
| `containment` | `SOCFramework.Artifacts.Email.MessageID` |
| `containment` | `SOCFramework.Artifacts.Email.Subject` |
| `containment` | `SOCFramework.Artifacts.Email.To` |
| `containment` | `SOCFramework.Artifacts.Endpoint.AgentID` |
| `containment` | `SOCFramework.Artifacts.Endpoint.Hostname` |
| `containment` | `SOCFramework.Artifacts.Process.Name` |
| `containment` | `SOCFramework.Artifacts.Process.PID` |
| `containment` | `SOCFramework.Artifacts.Target.SHA256` |
| `containment` | `SOCFramework.Artifacts.UserName` |
| `containment` | `SOCFramework.Mitre.Technique.ID` |
| `containment` | `SOCFramework.Product.category` |
| `containment` | `SOCFramework.Product.response` |
| `containment` | `SOCFramework.phase` |
| `eradication` | `SOCFramework.Artifacts.Email.From` |
| `eradication` | `SOCFramework.Artifacts.Email.Subject` |
| `eradication` | `SOCFramework.Artifacts.Email.ThreatType` |
| `eradication` | `SOCFramework.Artifacts.Email.ThreatURL` |
| `eradication` | `SOCFramework.Artifacts.Email.To` |
| `eradication` | `SOCFramework.Artifacts.Endpoint.AgentID` |
| `eradication` | `SOCFramework.Artifacts.Endpoint.Hostname` |
| `eradication` | `SOCFramework.Artifacts.Process.Name` |
| `eradication` | `SOCFramework.Artifacts.Process.Path` |
| `eradication` | `SOCFramework.Artifacts.Process.SHA256` |
| `eradication` | `SOCFramework.Artifacts.Target.Path` |
| `eradication` | `SOCFramework.Artifacts.Target.SHA256` |
| `eradication` | `SOCFramework.Email.TAP.Classification` |
| `eradication` | `SOCFramework.Product.category` |
| `eradication` | `SOCFramework.phase` |
| `recovery` | `SOCFramework.Artifacts.Email.From` |
| `recovery` | `SOCFramework.Artifacts.Email.Subject` |
| `recovery` | `SOCFramework.Artifacts.Email.To` |
| `recovery` | `SOCFramework.Artifacts.Endpoint.AgentID` |
| `recovery` | `SOCFramework.Artifacts.Endpoint.Hostname` |
| `recovery` | `SOCFramework.Artifacts.User` |
| `recovery` | `SOCFramework.Email.TAP.Classification` |
| `recovery` | `SOCFramework.Product.category` |
| `recovery` | `SOCFramework.phase` |

## Reads from Upstream Phases

| phase | from_phase | source |
|---|---|---|
| `containment` | `analysis` | `Analysis.case_score` |
| `eradication` | `analysis` | `Analysis.compromise_decision` |
| `eradication` | `analysis` | `Analysis.compromise_level` |
| `eradication` | `analysis` | `Analysis.mitre_tactic` |
| `eradication` | `analysis` | `Analysis.persistence_type` |
| `eradication` | `analysis` | `Analysis.primary_entity_id` |
| `eradication` | `analysis` | `Analysis.primary_entity_name` |
| `eradication` | `analysis` | `Analysis.primary_entity_user` |
| `eradication` | `analysis` | `Analysis.response_recommended` |
| `eradication` | `analysis` | `Analysis.spread_level` |
| `eradication` | `containment` | `Containment.action` |
| `eradication` | `containment` | `Containment.required` |
| `recovery` | `analysis` | `Analysis.compromise_decision` |
| `recovery` | `analysis` | `Analysis.compromise_level` |
| `recovery` | `analysis` | `Analysis.primary_entity_user` |
| `recovery` | `analysis` | `Analysis.verdict` |
| `recovery` | `eradication` | `Eradication.attempted` |
| `recovery` | `eradication` | `Eradication.story` |
| `recovery` | `eradication` | `Eradication.success` |
| `recovery` | `containment` | `Containment.Execution` |
| `recovery` | `containment` | `Containment.required` |

## Writes (Top-Level)

| phase | target | type | init |
|---|---|---|---|
| `analysis` | `Analysis.verdict` | `string` |  |
| `analysis` | `Analysis.confidence` | `string` |  |
| `analysis` | `Analysis.response_recommended` | `boolean` |  |
| `analysis` | `Analysis.compromise_level` | `string` |  |
| `analysis` | `Analysis.compromise_decision` | `string` |  |
| `analysis` | `Analysis.spread_level` | `string` |  |
| `analysis` | `Analysis.persistence_type` | `string` |  |
| `analysis` | `Analysis.primary_entity_id` | `string` |  |
| `analysis` | `Analysis.primary_entity_name` | `string` |  |
| `analysis` | `Analysis.primary_entity_type` | `string` |  |
| `analysis` | `Analysis.primary_entity_user` | `string` |  |
| `analysis` | `Analysis.case_category` | `string` |  |
| `analysis` | `Analysis.mitre_tactic` | `string` |  |
| `analysis` | `Analysis.mitre_tactic_id` | `string` |  |
| `analysis` | `Analysis.mitre_technique` | `string` |  |
| `analysis` | `Analysis.mitre_technique_id` | `string` |  |
| `analysis` | `Analysis.story` | `array` |  |
| `analysis` | `Analysis.case_score` | `number` | `0` |
| `analysis` | `Analysis.global_hash_prevalence_count` | `number` | `0` |
| `analysis` | `Analysis.case_host_count` | `number` | `0` |
| `analysis` | `Analysis.case_issue_count` | `number` | `0` |
| `analysis` | `Analysis.case_user_count` | `number` | `0` |
| `containment` | `Containment.status` | `string` |  |
| `containment` | `Containment.isolated_hosts` | `array` |  |
| `containment` | `Containment.action` | `string` |  |
| `containment` | `Containment.story` | `array` |  |
| `containment` | `Containment.required` | `boolean` |  |
| `containment` | `Containment.Execution` | `object` |  |
| `containment` | `Containment.disabled_users` | `array` |  |
| `eradication` | `Eradication.success` | `boolean` |  |
| `eradication` | `Eradication.attempted` | `boolean` |  |
| `eradication` | `Eradication.files_removed` | `array` |  |
| `eradication` | `Eradication.persistence_removed` | `array` |  |
| `eradication` | `Eradication.reimage_required` | `boolean` |  |
| `eradication` | `Eradication.escalate_to_reimage` | `boolean` |  |
| `eradication` | `Eradication.story` | `array` |  |
| `recovery` | `Recovery.status` | `string` |  |
| `recovery` | `Recovery.story` | `array` |  |
| `recovery` | `Recovery.monitoring_required` | `boolean` |  |
| `recovery` | `Recovery.monitoring_scope` | `string` |  |
| `recovery` | `Recovery.restore_required` | `boolean` |  |
| `recovery` | `Recovery.restore_method` | `string` |  |

## Writes by Category

| phase | category | target | type | init |
|---|---|---|---|---|
| `analysis` | `endpoint` | `Analysis.verdict` | `string` |  |
| `analysis` | `endpoint` | `Analysis.confidence` | `string` |  |
| `analysis` | `endpoint` | `Analysis.response_recommended` | `boolean` |  |
| `analysis` | `endpoint` | `Analysis.compromise_level` | `string` |  |
| `analysis` | `endpoint` | `Analysis.compromise_decision` | `string` |  |
| `analysis` | `endpoint` | `Analysis.spread_level` | `string` |  |
| `analysis` | `endpoint` | `Analysis.persistence_type` | `string` |  |
| `analysis` | `endpoint` | `Analysis.primary_entity_id` | `string` |  |
| `analysis` | `endpoint` | `Analysis.primary_entity_name` | `string` |  |
| `analysis` | `endpoint` | `Analysis.primary_entity_user` | `string` |  |
| `analysis` | `endpoint` | `Analysis.primary_entity_type` | `string` |  |
| `analysis` | `endpoint` | `Analysis.case_category` | `string` |  |
| `analysis` | `endpoint` | `Analysis.mitre_tactic` | `string` |  |
| `analysis` | `endpoint` | `Analysis.mitre_tactic_id` | `string` |  |
| `analysis` | `endpoint` | `Analysis.mitre_technique` | `string` |  |
| `analysis` | `endpoint` | `Analysis.mitre_technique_id` | `string` |  |
| `analysis` | `endpoint` | `Analysis.story` | `array` |  |
| `analysis` | `endpoint` | `Analysis.case_score` | `number` | `0` |
| `analysis` | `endpoint` | `Analysis.global_hash_prevalence_count` | `number` | `0` |
| `analysis` | `endpoint` | `Analysis.case_host_count` | `number` | `0` |
| `analysis` | `endpoint` | `Analysis.case_issue_count` | `number` | `0` |
| `analysis` | `endpoint` | `Analysis.case_user_count` | `number` | `0` |
| `analysis` | `email` | `Analysis.Email.verdict` | `string` |  |
| `analysis` | `email` | `Analysis.Email.confidence` | `string` |  |
| `analysis` | `email` | `Analysis.Email.category` | `string` |  |
| `analysis` | `email` | `Analysis.Email.signal_type` | `string` |  |
| `analysis` | `email` | `Analysis.Email.source_verdict` | `array` |  |
| `analysis` | `email` | `Analysis.Email.response_recommended` | `boolean` |  |
| `analysis` | `email` | `Analysis.Email.spread_level` | `string` |  |
| `analysis` | `email` | `Analysis.Email.persistence_type` | `string` |  |
| `analysis` | `identity` | `Analysis.verdict` | `string` |  |
| `analysis` | `identity` | `Analysis.confidence` | `string` |  |
| `analysis` | `identity` | `Analysis.response_recommended` | `boolean` |  |
| `analysis` | `identity` | `Analysis.compromise_level` | `string` |  |
| `analysis` | `identity` | `Analysis.compromise_decision` | `string` |  |
| `analysis` | `identity` | `Analysis.spread_level` | `string` |  |
| `analysis` | `identity` | `Analysis.primary_entity_id` | `string` |  |
| `analysis` | `identity` | `Analysis.primary_entity_name` | `string` |  |
| `analysis` | `identity` | `Analysis.primary_entity_user` | `string` |  |
| `analysis` | `identity` | `Analysis.primary_entity_type` | `string` |  |
| `analysis` | `identity` | `Analysis.case_category` | `string` |  |
| `analysis` | `identity` | `Analysis.mitre_tactic` | `string` |  |
| `analysis` | `identity` | `Analysis.mitre_tactic_id` | `string` |  |
| `analysis` | `identity` | `Analysis.mitre_technique` | `string` |  |
| `analysis` | `identity` | `Analysis.mitre_technique_id` | `string` |  |
| `analysis` | `identity` | `Analysis.story` | `array` |  |
| `analysis` | `identity` | `Analysis.case_score` | `number` | `0` |
| `analysis` | `identity` | `Analysis.case_host_count` | `number` | `0` |
| `analysis` | `identity` | `Analysis.case_issue_count` | `number` | `0` |
| `analysis` | `identity` | `Analysis.case_user_count` | `number` | `0` |
| `containment` | `endpoint` | `Containment.story` | `array` |  |
| `containment` | `endpoint` | `Containment.Execution` | `object` |  |
| `containment` | `email` | `Containment.required` | `boolean` |  |
| `containment` | `email` | `Containment.action` | `string` |  |
| `containment` | `email` | `Containment.story` | `array` |  |
| `containment` | `email` | `Containment.Execution` | `object` |  |
| `containment` | `identity` | `Blocklist.Final` | `array` |  |
| `containment` | `identity` | `QuarantinedFilesFromEndpoints` | `array` |  |
| `containment` | `identity` | `Core.blocklist.added_hashes` | `array` |  |
| `containment` | `identity` | `Core.Isolation.endpoint_id` | `string` |  |
| `eradication` | `endpoint` | `Eradication.story` | `array` |  |
| `eradication` | `endpoint` | `Eradication.Execution` | `object` |  |
| `eradication` | `email` | `Eradication.attempted` | `boolean` |  |
| `eradication` | `email` | `Eradication.success` | `boolean` |  |
| `eradication` | `email` | `Eradication.story` | `array` |  |
| `eradication` | `email` | `Eradication.Execution` | `object` |  |
| `eradication` | `identity` | `Eradication.attempted` | `boolean` |  |
| `eradication` | `identity` | `Eradication.credentials_reset` | `array` |  |
| `eradication` | `identity` | `Eradication.tokens_revoked` | `array` |  |
| `eradication` | `identity` | `Eradication.story` | `array` |  |
| `recovery` | `endpoint` | `Recovery.story` | `array` |  |
| `recovery` | `endpoint` | `Recovery.Execution` | `object` |  |
| `recovery` | `email` | `Recovery.status` | `string` |  |
| `recovery` | `email` | `Recovery.monitoring_required` | `boolean` |  |
| `recovery` | `email` | `Recovery.story` | `array` |  |
| `recovery` | `email` | `Recovery.Execution` | `object` |  |
| `recovery` | `identity` | `Recovery.attempted` | `boolean` |  |
| `recovery` | `identity` | `Recovery.account_restored` | `boolean` |  |
| `recovery` | `identity` | `Recovery.monitoring_required` | `boolean` |  |
| `recovery` | `identity` | `Recovery.restore_method` | `string` |  |
| `recovery` | `identity` | `Recovery.story` | `array` |  |
