# SOCFrameworkNormalizeMap_V3

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

| Field | Value |
|---|---|
| Pack | `soc-optimization-unified` |
| List Name | `SOCFrameworkNormalizeMap_V3` |
| Source | [`schemas/soc-framework/soc-optimization-unified/SOCFrameworkNormalizeMap_V3.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/soc-framework/soc-optimization-unified/SOCFrameworkNormalizeMap_V3.yaml) |

Maps issue.<field> -> SOCFramework.<target> per product category, plus stamps and mirrors. Two roles (canonical, legacy_alias) and two source origins (native, socfw_custom).

## Categories

| Category | Status | Shape | Source Playbook |
|---|---|---|---|
| `endpoint` | complete |  | `Foundation_-_Normalize_Endpoint_V3` |
| `email` | partial |  | `Foundation_-_Normalize_Email_V3` |
| `identity` | in_progress |  | `Foundation_-_Normalize_Identity_V3` |

## Mappings — `issue.*` → `SOCFramework.*`

| category | target | issue_field | shape | role | source_origin | notes | superseded_by |
|---|---|---|---|---|---|---|---|
| `endpoint` | `Endpoint.alert_action` | `alertaction` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.containment_status` | `endpointstatus` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.dns_queries` | `dns_query_name` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.domain` | `agent_device_domain` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.endpoint_id` | `agent_id` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.external_ip` | `deviceexternalips` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.file_path` | `action_file_path` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.file_sha256` | `action_file_sha256` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.hostname` | `agent_hostname` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.ip_address` | `action_local_ip` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.mac_address` | `mac` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.network_accesses` | `network_accesses` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.os` | `ostype` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.parent_process_cmd` | `parentprocesscmd` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.parent_process_name` | `parentprocessname` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.parent_process_sha256` | `parentprocesssha256` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.process_cmd` | `actor_process_command_line` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.process_name` | `actor_process_image_name` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.process_path` | `actor_process_image_path` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.process_pid` | `actor_process_os_pid` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.process_sha256` | `actor_process_image_sha256` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.tactic` | `mitretacticname` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.tactic_id` | `mitretacticid` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.technique` | `mitretechniquename` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.technique_id` | `mitretechniqueid` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.user_principal` | `user_principal` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.username` | `actor_effective_username` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Endpoint.AgentID` | `agent_id` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Endpoint.Domain` | `agent_device_domain` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Endpoint.FQDN` | `hostfqdn` | `structured` | `canonical` | `native` | No vendor canonical core sibling. hostfqdn is the XSIAM-native name. |  |
| `endpoint` | `Artifacts.Endpoint.Hostname` | `agent_hostname` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Endpoint.MACAddress` | `mac` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Endpoint.OS` | `hostos` | `structured` | `canonical` | `native` | Display string (e.g., 'Windows 10 Pro'). Distinct from flat Endpoint.os which uses ostype family. |  |
| `endpoint` | `Artifacts.Endpoint.OSVersion` | `agentossubtype` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.MITRE.Category` | `categoryname` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.MITRE.Tactic` | `mitretacticname` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.MITRE.TacticID` | `mitretacticid` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.MITRE.Technique` | `mitretechniquename` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.MITRE.TechniqueID` | `mitretechniqueid` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Network.IP` | `hostip.[0]` | `structured` | `canonical` | `native` | Host primary IP. Distinct from flat Endpoint.ip_address (action_local_ip). |  |
| `endpoint` | `Artifacts.Process.Causality.ID` | `causality_actor_causality_id` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.Causality.InstanceID` | `actorprocessinstanceid.[0]` | `structured` | `canonical` | `native` | No vendor canonical core sibling identified. Verify on dev tenant; propose canonical name if drift observed across vendors. |  |
| `endpoint` | `Artifacts.Process.CommandLine` | `actor_process_command_line` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.MD5` | `processmd5` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.Name` | `actor_process_image_name` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.Parent.PID` | `parentprocessid` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.Parent.Signature` | `osparentsignature.[0]` | `structured` | `canonical` | `native` | No canonical core sibling. Vendor packs vary on parent signature surfacing. |  |
| `endpoint` | `Artifacts.Process.Path` | `actor_process_image_path` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.PID` | `actor_process_os_pid` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.SHA256` | `actor_process_image_sha256` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.Signature` | `initiatorsignature.[0]` | `structured` | `canonical` | `native` | No canonical core sibling identified across vendor packs. |  |
| `endpoint` | `Artifacts.Process.Signer` | `initiatorsigner.[0]` | `structured` | `canonical` | `native` | No canonical core sibling identified across vendor packs. |  |
| `endpoint` | `Artifacts.Source.Action` | `action.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Source.AlertDomain` | `alert_domain` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Source.Module` | `module.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Target.File` | `action_file_name` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Target.Path` | `action_file_path` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Target.SHA256` | `action_file_sha256` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Target.SignatureStatus` | `xdmtargetprocessexecutablesignaturestatus.[0]` | `structured` | `canonical` | `native` | XDM-styled name. No canonical core sibling identified. |  |
| `endpoint` | `Artifacts.EndPointID` | `agent_id` | `structured` | `legacy_alias` | `native` |  | `Artifacts.Endpoint.AgentID` |
| `endpoint` | `Artifacts.File` | `action_file_sha256` | `structured` | `legacy_alias` | `native` |  | `Artifacts.Target.SHA256` |
| `endpoint` | `Artifacts.FilePath` | `action_file_path` | `structured` | `legacy_alias` | `native` |  | `Artifacts.Target.Path` |
| `endpoint` | `Artifacts.Hash` | `action_file_sha256` | `structured` | `legacy_alias` | `native` |  | `Artifacts.Target.SHA256` |
| `endpoint` | `Artifacts.User` | `actor_effective_username` | `structured` | `legacy_alias` | `native` |  | `Artifacts.User.Name (TBD — User sub-tree not yet authored)` |
| `email` | `Email.attachment_name` | `action_file_name` | `flat` | `canonical` | `native` |  |  |
| `email` | `Email.attachment_sha256` | `action_file_sha256` | `flat` | `canonical` | `native` |  |  |
| `email` | `Email.campaign_id` | `socfwemailcampaignid` | `flat` | `canonical` | `socfw_custom` |  |  |
| `email` | `Email.classification` | `socfwemailclassification` | `flat` | `canonical` | `socfw_custom` |  |  |
| `email` | `Email.click_ip` | `socfwemailclickip` | `flat` | `canonical` | `socfw_custom` |  |  |
| `email` | `Email.click_time` | `socfwemailclicktime` | `flat` | `canonical` | `socfw_custom` |  |  |
| `email` | `Email.delivery_action` | `socfwemaildeliveryaction` | `flat` | `canonical` | `socfw_custom` |  |  |
| `email` | `Email.direction` | `socfwemaildirection` | `flat` | `canonical` | `socfw_custom` |  |  |
| `email` | `Email.malware_score` | `socfwemailmalwarescore` | `flat` | `canonical` | `socfw_custom` |  |  |
| `email` | `Email.message_id` | `emailmessageid` | `flat` | `canonical` | `native` |  |  |
| `email` | `Email.phish_score` | `socfwemailphishscore` | `flat` | `canonical` | `socfw_custom` |  |  |
| `email` | `Email.recipient` | `emailrecipient` | `flat` | `canonical` | `native` |  |  |
| `email` | `Email.reported_by` | `reporteremailaddress` | `flat` | `canonical` | `native` |  |  |
| `email` | `Email.sender` | `emailsender` | `flat` | `canonical` | `native` |  |  |
| `email` | `Email.sender_ip` | `emailsenderip` | `flat` | `canonical` | `native` |  |  |
| `email` | `Email.subject` | `emailsubject` | `flat` | `canonical` | `native` |  |  |
| `email` | `Email.threat_id` | `socfwemailthreatid` | `flat` | `canonical` | `socfw_custom` |  |  |
| `email` | `Email.threat_status` | `socfwemailthreatstatus` | `flat` | `canonical` | `socfw_custom` |  |  |
| `email` | `Email.threat_type` | `socfwemailthreattype` | `flat` | `canonical` | `socfw_custom` |  |  |
| `email` | `Email.threat_url` | `socfwemailthreaturl` | `flat` | `canonical` | `socfw_custom` |  |  |
| `identity` | `Identity.auth_source` | `authsource` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.client_ip` | `sourceip` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.country` | `sourcecountry` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.device_id` | `deviceid` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.event_type` | `eventtype` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.logon_type` | `logontype` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.mfa_method` | `mfamethod` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.outcome` | `eventoutcome` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.risk_level` | `userrisk` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.session_id` | `sessionid` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.source_hostname` | `sourcehostname` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.target_resource` | `targetresource` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.user_agent` | `useragent` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.user_display_name` | `userdisplayname` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.user_email` | `useremail` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.user_id` | `userid` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.username` | `username` | `flat` | `canonical` | `native` |  |  |

## Stamps — literal value → `SOCFramework.*`

| category | target | value | role | notes |
|---|---|---|---|---|
| `endpoint` | `Endpoint.normalization_source` | `endpoint` | `canonical` |  |
| `endpoint` | `Artifacts.Process.Verdict` |  | `canonical` | Empty-init for downstream Analysis verdict assignment. |
| `endpoint` | `Artifacts.Target.Verdict` |  | `canonical` | Empty-init for downstream Analysis verdict assignment. |
| `email` | `Email.normalization_source` | `email` | `canonical` |  |
| `email` | `Email.normalization_source` | `mail_listener` | `canonical` | Alternate stamp set when alert routes via mail_listener integration. |
| `identity` | `Identity.normalization_source` | `identity` | `canonical` |  |

## Mirrors — `SOCFramework.*` → `SOCFramework.*`

| category | target | source | role | shape |
|---|---|---|---|---|
| `email` | `Artifacts.Email.From` | `Email.sender` | `canonical` | `structured` |
| `email` | `Artifacts.Email.To` | `Email.recipient` | `canonical` | `structured` |
| `email` | `Artifacts.Email.Subject` | `Email.subject` | `canonical` | `structured` |
| `email` | `Artifacts.Email.MessageID` | `Email.message_id` | `canonical` | `structured` |
| `email` | `Artifacts.Email.ThreatType` | `Email.threat_type` | `canonical` | `structured` |
| `email` | `Artifacts.Email.ThreatURL` | `Email.threat_url` | `canonical` | `structured` |
