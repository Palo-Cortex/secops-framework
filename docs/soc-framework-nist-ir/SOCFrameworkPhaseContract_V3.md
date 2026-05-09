# SOCFrameworkPhaseContract_V3

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

| Field | Value |
|---|---|
| Pack | `soc-framework-nist-ir` |
| List Name | `SOCFrameworkPhaseContract_V3` |
| Source | [`schemas/soc-framework/soc-framework-nist-ir/SOCFrameworkPhaseContract_V3.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/soc-framework/soc-framework-nist-ir/SOCFrameworkPhaseContract_V3.yaml) |

NIST IR phase contract — what each phase reads, writes, and routes to. Two roles (canonical, legacy_alias) with banded organization for one-shot legacy cleanup.

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

| phase | category | sub_playbook | role |
|---|---|---|---|
| `analysis` | `endpoint` | `SOC_EndPoint_Analysis_V3` | `canonical` |
| `analysis` | `email` | `SOC_Email_Analysis_V3` | `canonical` |
| `analysis` | `identity` | `SOC_Identity_Analysis_V3` | `canonical` |
| `containment` | `endpoint` | `SOC_Endpoint_Containment_V3` | `canonical` |
| `containment` | `email` | `SOC_Email_Containment_V3` | `canonical` |
| `containment` | `identity` | `SOC_Identity_Containment_V3` | `canonical` |
| `eradication` | `endpoint` | `SOC_EndPoint_Eradication_V3` | `canonical` |
| `eradication` | `email` | `SOC_Email_Eradication_V3` | `canonical` |
| `eradication` | `identity` | `SOC_Identity_Eradication_V3` | `canonical` |
| `recovery` | `endpoint` | `SOC_EndPoint_Recovery_V3` | `canonical` |
| `recovery` | `email` | `SOC_Email_Recovery_V3` | `canonical` |
| `recovery` | `identity` | `SOC_Identity_Recovery_V3` | `canonical` |

## Reads from Framework Namespace (`SOCFramework.*`)

| phase | source | role | notes | superseded_by |
|---|---|---|---|---|
| `analysis` | `SOCFramework.Artifacts.Email.From` | `canonical` |  |  |
| `analysis` | `SOCFramework.Artifacts.Email.Subject` | `canonical` |  |  |
| `analysis` | `SOCFramework.Artifacts.Email.ThreatType` | `canonical` |  |  |
| `analysis` | `SOCFramework.Artifacts.Email.ThreatURL` | `canonical` |  |  |
| `analysis` | `SOCFramework.Artifacts.Email.To` | `canonical` |  |  |
| `analysis` | `SOCFramework.Email.HighValueUserInvolved` | `canonical` | Custom Analysis-side enrichment field; written by upstream enrichment, not normalize map. |  |
| `analysis` | `SOCFramework.Email.reported_by` | `canonical` |  |  |
| `analysis` | `SOCFramework.Email.threat_id` | `canonical` |  |  |
| `analysis` | `SOCFramework.Email.threat_status` | `canonical` |  |  |
| `analysis` | `SOCFramework.Investigation.LinkedCount` | `canonical` | Written by Foundation_-_Enrichment_V3 / Investigation pipeline. |  |
| `analysis` | `SOCFramework.Investigation.RiskScore` | `canonical` | Written by Foundation_-_Enrichment_V3 / Investigation pipeline. |  |
| `analysis` | `SOCFramework.Product.category` | `canonical` |  |  |
| `analysis` | `SOCFramework.Product.key` | `canonical` |  |  |
| `analysis` | `SOCFramework.phase` | `canonical` |  |  |
| `analysis` | `SOCFramework.Artifacts` | `legacy_alias` | Bare namespace read — likely an exists-check. Replace with specific leaf reads or remove. | `TBD` |
| `analysis` | `SOCFramework.Artifacts.CommandLine` | `legacy_alias` |  | `SOCFramework.Artifacts.Process.CommandLine` |
| `analysis` | `SOCFramework.Artifacts.Email` | `legacy_alias` | Bare email namespace read. Replace with specific leaf reads (Email.From/To/Subject/etc.). | `TBD` |
| `analysis` | `SOCFramework.Artifacts.EndPointID` | `legacy_alias` |  | `SOCFramework.Artifacts.Endpoint.AgentID` |
| `analysis` | `SOCFramework.Artifacts.FeaturedHost` | `legacy_alias` | No clear V3 equivalent. Likely Artifacts.Endpoint.Hostname; verify usage in SOC_Analysis_V3 before mapping. | `TBD` |
| `analysis` | `SOCFramework.Artifacts.File` | `legacy_alias` |  | `SOCFramework.Artifacts.Target.SHA256` |
| `analysis` | `SOCFramework.Artifacts.HostName` | `legacy_alias` | Capital N drift — V3 canonical is .Hostname (capital H, lower n). | `SOCFramework.Artifacts.Endpoint.Hostname` |
| `analysis` | `SOCFramework.Artifacts.NetworkArtifacts` | `legacy_alias` | No clear V3 equivalent. Investigate whether replaced by Artifacts.Network.IP or by a future Artifacts.Network.* sub-tree. | `TBD` |
| `analysis` | `SOCFramework.Artifacts.ProcessNames` | `legacy_alias` |  | `SOCFramework.Artifacts.Process.Name` |
| `analysis` | `SOCFramework.Artifacts.UserName` | `legacy_alias` | Migrate to Artifacts.User.Name once User sub-tree is authored. | `SOCFramework.Artifacts.User` |
| `analysis` | `SOCFramework.Artifacts.Verdict` | `legacy_alias` | V3 splits per-entity verdicts: Artifacts.Process.Verdict and Artifacts.Target.Verdict. | `TBD` |
| `analysis` | `SOCFramework.Mitre` | `legacy_alias` | Capital M not under Artifacts. V3 canonical is Artifacts.MITRE.* | `SOCFramework.Artifacts.MITRE` |
| `analysis` | `SOCFramework.Mitre.Tactic` | `legacy_alias` |  | `SOCFramework.Artifacts.MITRE.Tactic` |
| `analysis` | `SOCFramework.Mitre.Tactic.ID` | `legacy_alias` |  | `SOCFramework.Artifacts.MITRE.TacticID` |
| `analysis` | `SOCFramework.Mitre.Technique` | `legacy_alias` |  | `SOCFramework.Artifacts.MITRE.Technique` |
| `analysis` | `SOCFramework.Mitre.Technique.ID` | `legacy_alias` |  | `SOCFramework.Artifacts.MITRE.TechniqueID` |
| `containment` | `SOCFramework.Artifacts.Domain` | `canonical` |  |  |
| `containment` | `SOCFramework.Artifacts.Email.From` | `canonical` |  |  |
| `containment` | `SOCFramework.Artifacts.Email.MessageID` | `canonical` |  |  |
| `containment` | `SOCFramework.Artifacts.Email.Subject` | `canonical` |  |  |
| `containment` | `SOCFramework.Artifacts.Email.To` | `canonical` |  |  |
| `containment` | `SOCFramework.Artifacts.Endpoint.AgentID` | `canonical` |  |  |
| `containment` | `SOCFramework.Artifacts.Endpoint.Hostname` | `canonical` |  |  |
| `containment` | `SOCFramework.Artifacts.Process.Name` | `canonical` |  |  |
| `containment` | `SOCFramework.Artifacts.Process.PID` | `canonical` |  |  |
| `containment` | `SOCFramework.Artifacts.Target.SHA256` | `canonical` |  |  |
| `containment` | `SOCFramework.Product.category` | `canonical` |  |  |
| `containment` | `SOCFramework.Product.response` | `canonical` |  |  |
| `containment` | `SOCFramework.phase` | `canonical` |  |  |
| `containment` | `SOCFramework.Artifacts.UserName` | `legacy_alias` | Migrate to Artifacts.User.Name once User sub-tree is authored. | `SOCFramework.Artifacts.User` |
| `containment` | `SOCFramework.Mitre.Technique.ID` | `legacy_alias` |  | `SOCFramework.Artifacts.MITRE.TechniqueID` |
| `eradication` | `SOCFramework.Artifacts.Email.From` | `canonical` |  |  |
| `eradication` | `SOCFramework.Artifacts.Email.Subject` | `canonical` |  |  |
| `eradication` | `SOCFramework.Artifacts.Email.ThreatType` | `canonical` |  |  |
| `eradication` | `SOCFramework.Artifacts.Email.ThreatURL` | `canonical` |  |  |
| `eradication` | `SOCFramework.Artifacts.Email.To` | `canonical` |  |  |
| `eradication` | `SOCFramework.Artifacts.Endpoint.AgentID` | `canonical` |  |  |
| `eradication` | `SOCFramework.Artifacts.Endpoint.Hostname` | `canonical` |  |  |
| `eradication` | `SOCFramework.Artifacts.Process.Name` | `canonical` |  |  |
| `eradication` | `SOCFramework.Artifacts.Process.Path` | `canonical` |  |  |
| `eradication` | `SOCFramework.Artifacts.Process.SHA256` | `canonical` |  |  |
| `eradication` | `SOCFramework.Artifacts.Target.Path` | `canonical` |  |  |
| `eradication` | `SOCFramework.Artifacts.Target.SHA256` | `canonical` |  |  |
| `eradication` | `SOCFramework.Email.TAP.Classification` | `canonical` | Vendor-specific Email Analysis output; written by Email Analysis sub-playbook. |  |
| `eradication` | `SOCFramework.Product.category` | `canonical` |  |  |
| `eradication` | `SOCFramework.phase` | `canonical` |  |  |
| `recovery` | `SOCFramework.Artifacts.Email.From` | `canonical` |  |  |
| `recovery` | `SOCFramework.Artifacts.Email.Subject` | `canonical` |  |  |
| `recovery` | `SOCFramework.Artifacts.Email.To` | `canonical` |  |  |
| `recovery` | `SOCFramework.Artifacts.Endpoint.AgentID` | `canonical` |  |  |
| `recovery` | `SOCFramework.Artifacts.Endpoint.Hostname` | `canonical` |  |  |
| `recovery` | `SOCFramework.Artifacts.User` | `canonical` | Will become Artifacts.User.Name once User sub-tree is authored; matches normalize-map legacy_alias. |  |
| `recovery` | `SOCFramework.Email.TAP.Classification` | `canonical` |  |  |
| `recovery` | `SOCFramework.Product.category` | `canonical` |  |  |
| `recovery` | `SOCFramework.phase` | `canonical` |  |  |

## Reads from Upstream Phases

| phase | from_phase | source | role |
|---|---|---|---|
| `containment` | `analysis` | `Analysis.case_score` | `canonical` |
| `eradication` | `analysis` | `Analysis.compromise_decision` | `canonical` |
| `eradication` | `analysis` | `Analysis.compromise_level` | `canonical` |
| `eradication` | `analysis` | `Analysis.mitre_tactic` | `canonical` |
| `eradication` | `analysis` | `Analysis.persistence_type` | `canonical` |
| `eradication` | `analysis` | `Analysis.primary_entity_id` | `canonical` |
| `eradication` | `analysis` | `Analysis.primary_entity_name` | `canonical` |
| `eradication` | `analysis` | `Analysis.primary_entity_user` | `canonical` |
| `eradication` | `analysis` | `Analysis.response_recommended` | `canonical` |
| `eradication` | `analysis` | `Analysis.spread_level` | `canonical` |
| `eradication` | `containment` | `Containment.action` | `canonical` |
| `eradication` | `containment` | `Containment.required` | `canonical` |
| `recovery` | `analysis` | `Analysis.compromise_decision` | `canonical` |
| `recovery` | `analysis` | `Analysis.compromise_level` | `canonical` |
| `recovery` | `analysis` | `Analysis.primary_entity_user` | `canonical` |
| `recovery` | `analysis` | `Analysis.verdict` | `canonical` |
| `recovery` | `eradication` | `Eradication.attempted` | `canonical` |
| `recovery` | `eradication` | `Eradication.story` | `canonical` |
| `recovery` | `eradication` | `Eradication.success` | `canonical` |
| `recovery` | `containment` | `Containment.Execution` | `canonical` |
| `recovery` | `containment` | `Containment.required` | `canonical` |

## Writes (Top-Level)

| phase | target | type | init | role |
|---|---|---|---|---|
| `analysis` | `Analysis.verdict` | `string` |  | `canonical` |
| `analysis` | `Analysis.confidence` | `string` |  | `canonical` |
| `analysis` | `Analysis.response_recommended` | `boolean` |  | `canonical` |
| `analysis` | `Analysis.compromise_level` | `string` |  | `canonical` |
| `analysis` | `Analysis.compromise_decision` | `string` |  | `canonical` |
| `analysis` | `Analysis.spread_level` | `string` |  | `canonical` |
| `analysis` | `Analysis.persistence_type` | `string` |  | `canonical` |
| `analysis` | `Analysis.primary_entity_id` | `string` |  | `canonical` |
| `analysis` | `Analysis.primary_entity_name` | `string` |  | `canonical` |
| `analysis` | `Analysis.primary_entity_type` | `string` |  | `canonical` |
| `analysis` | `Analysis.primary_entity_user` | `string` |  | `canonical` |
| `analysis` | `Analysis.case_category` | `string` |  | `canonical` |
| `analysis` | `Analysis.mitre_tactic` | `string` |  | `canonical` |
| `analysis` | `Analysis.mitre_tactic_id` | `string` |  | `canonical` |
| `analysis` | `Analysis.mitre_technique` | `string` |  | `canonical` |
| `analysis` | `Analysis.mitre_technique_id` | `string` |  | `canonical` |
| `analysis` | `Analysis.story` | `array` |  | `canonical` |
| `analysis` | `Analysis.case_score` | `number` | `0` | `canonical` |
| `analysis` | `Analysis.global_hash_prevalence_count` | `number` | `0` | `canonical` |
| `analysis` | `Analysis.case_host_count` | `number` | `0` | `canonical` |
| `analysis` | `Analysis.case_issue_count` | `number` | `0` | `canonical` |
| `analysis` | `Analysis.case_user_count` | `number` | `0` | `canonical` |
| `containment` | `Containment.status` | `string` |  | `canonical` |
| `containment` | `Containment.isolated_hosts` | `array` |  | `canonical` |
| `containment` | `Containment.action` | `string` |  | `canonical` |
| `containment` | `Containment.story` | `array` |  | `canonical` |
| `containment` | `Containment.required` | `boolean` |  | `canonical` |
| `containment` | `Containment.Execution` | `object` |  | `canonical` |
| `containment` | `Containment.disabled_users` | `array` |  | `canonical` |
| `eradication` | `Eradication.success` | `boolean` |  | `canonical` |
| `eradication` | `Eradication.attempted` | `boolean` |  | `canonical` |
| `eradication` | `Eradication.files_removed` | `array` |  | `canonical` |
| `eradication` | `Eradication.persistence_removed` | `array` |  | `canonical` |
| `eradication` | `Eradication.reimage_required` | `boolean` |  | `canonical` |
| `eradication` | `Eradication.escalate_to_reimage` | `boolean` |  | `canonical` |
| `eradication` | `Eradication.story` | `array` |  | `canonical` |
| `recovery` | `Recovery.status` | `string` |  | `canonical` |
| `recovery` | `Recovery.story` | `array` |  | `canonical` |
| `recovery` | `Recovery.monitoring_required` | `boolean` |  | `canonical` |
| `recovery` | `Recovery.monitoring_scope` | `string` |  | `canonical` |
| `recovery` | `Recovery.restore_required` | `boolean` |  | `canonical` |
| `recovery` | `Recovery.restore_method` | `string` |  | `canonical` |

## Writes by Category

| phase | category | target | type | init | role | superseded_by | notes |
|---|---|---|---|---|---|---|---|
| `analysis` | `endpoint` | `Analysis.verdict` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.confidence` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.response_recommended` | `boolean` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.compromise_level` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.compromise_decision` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.spread_level` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.persistence_type` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.primary_entity_id` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.primary_entity_name` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.primary_entity_user` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.primary_entity_type` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.case_category` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.mitre_tactic` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.mitre_tactic_id` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.mitre_technique` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.mitre_technique_id` | `string` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.story` | `array` |  | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.case_score` | `number` | `0` | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.global_hash_prevalence_count` | `number` | `0` | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.case_host_count` | `number` | `0` | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.case_issue_count` | `number` | `0` | `canonical` |  |  |
| `analysis` | `endpoint` | `Analysis.case_user_count` | `number` | `0` | `canonical` |  |  |
| `analysis` | `email` | `Analysis.Email.verdict` | `string` |  | `canonical` |  |  |
| `analysis` | `email` | `Analysis.Email.confidence` | `string` |  | `canonical` |  |  |
| `analysis` | `email` | `Analysis.Email.category` | `string` |  | `canonical` |  |  |
| `analysis` | `email` | `Analysis.Email.signal_type` | `string` |  | `canonical` |  |  |
| `analysis` | `email` | `Analysis.Email.source_verdict` | `array` |  | `canonical` |  |  |
| `analysis` | `email` | `Analysis.Email.response_recommended` | `boolean` |  | `canonical` |  |  |
| `analysis` | `email` | `Analysis.Email.spread_level` | `string` |  | `canonical` |  |  |
| `analysis` | `email` | `Analysis.Email.persistence_type` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.verdict` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.confidence` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.response_recommended` | `boolean` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.compromise_level` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.compromise_decision` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.spread_level` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.primary_entity_id` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.primary_entity_name` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.primary_entity_user` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.primary_entity_type` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.case_category` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.mitre_tactic` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.mitre_tactic_id` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.mitre_technique` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.mitre_technique_id` | `string` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.story` | `array` |  | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.case_score` | `number` | `0` | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.case_host_count` | `number` | `0` | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.case_issue_count` | `number` | `0` | `canonical` |  |  |
| `analysis` | `identity` | `Analysis.case_user_count` | `number` | `0` | `canonical` |  |  |
| `containment` | `endpoint` | `Containment.story` | `array` |  | `canonical` |  |  |
| `containment` | `endpoint` | `Containment.Execution` | `object` |  | `canonical` |  |  |
| `containment` | `email` | `Containment.required` | `boolean` |  | `canonical` |  |  |
| `containment` | `email` | `Containment.action` | `string` |  | `canonical` |  |  |
| `containment` | `email` | `Containment.story` | `array` |  | `canonical` |  |  |
| `containment` | `email` | `Containment.Execution` | `object` |  | `canonical` |  |  |
| `containment` | `identity` | `Blocklist.Final` | `array` |  | `legacy_alias` | `Containment.blocklist_added` | Top-level Blocklist namespace predates Containment.* |
| `containment` | `identity` | `QuarantinedFilesFromEndpoints` | `array` |  | `legacy_alias` | `Containment.quarantined_files` | Top-level write predates Containment.* namespace. |
| `containment` | `identity` | `Core.blocklist.added_hashes` | `array` |  | `legacy_alias` | `Containment.blocklist_added_hashes` | Core.* namespace predates Containment.*. |
| `containment` | `identity` | `Core.Isolation.endpoint_id` | `string` |  | `legacy_alias` | `Containment.isolated_endpoint_id` | Core.* namespace predates Containment.*. |
| `eradication` | `endpoint` | `Eradication.story` | `array` |  | `canonical` |  |  |
| `eradication` | `endpoint` | `Eradication.Execution` | `object` |  | `canonical` |  |  |
| `eradication` | `email` | `Eradication.attempted` | `boolean` |  | `canonical` |  |  |
| `eradication` | `email` | `Eradication.success` | `boolean` |  | `canonical` |  |  |
| `eradication` | `email` | `Eradication.story` | `array` |  | `canonical` |  |  |
| `eradication` | `email` | `Eradication.Execution` | `object` |  | `canonical` |  |  |
| `eradication` | `identity` | `Eradication.attempted` | `boolean` |  | `canonical` |  |  |
| `eradication` | `identity` | `Eradication.credentials_reset` | `array` |  | `canonical` |  |  |
| `eradication` | `identity` | `Eradication.tokens_revoked` | `array` |  | `canonical` |  |  |
| `eradication` | `identity` | `Eradication.story` | `array` |  | `canonical` |  |  |
| `recovery` | `endpoint` | `Recovery.story` | `array` |  | `canonical` |  |  |
| `recovery` | `endpoint` | `Recovery.Execution` | `object` |  | `canonical` |  |  |
| `recovery` | `email` | `Recovery.status` | `string` |  | `canonical` |  |  |
| `recovery` | `email` | `Recovery.monitoring_required` | `boolean` |  | `canonical` |  |  |
| `recovery` | `email` | `Recovery.story` | `array` |  | `canonical` |  |  |
| `recovery` | `email` | `Recovery.Execution` | `object` |  | `canonical` |  |  |
| `recovery` | `identity` | `Recovery.attempted` | `boolean` |  | `canonical` |  |  |
| `recovery` | `identity` | `Recovery.account_restored` | `boolean` |  | `canonical` |  |  |
| `recovery` | `identity` | `Recovery.monitoring_required` | `boolean` |  | `canonical` |  |  |
| `recovery` | `identity` | `Recovery.restore_method` | `string` |  | `canonical` |  |  |
| `recovery` | `identity` | `Recovery.story` | `array` |  | `canonical` |  |  |
