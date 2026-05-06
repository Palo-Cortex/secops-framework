# SOCFrameworkNormalizeMap_V3

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

| Field | Value |
|---|---|
| Pack | `soc-optimization-unified` |
| List Name | `SOCFrameworkNormalizeMap_V3` |
| Source | [`schemas/soc-framework/soc-optimization-unified/SOCFrameworkNormalizeMap_V3.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/soc-framework/soc-optimization-unified/SOCFrameworkNormalizeMap_V3.yaml) |

Maps issue.<field> -> SOCFramework.<target> per product category, plus stamps and mirrors

## Categories

| Category | Status | Shape | Source Playbook |
|---|---|---|---|
| `endpoint` | complete | peer | `Foundation_-_Normalize_Endpoint_V3` |
| `email` | partial | namespaced | `Foundation_-_Normalize_Email_V3` |
| `identity` | flat-only | namespaced | `Foundation_-_Normalize_Identity_V3` |

## Mappings — `issue.*` → `SOCFramework.*`

| category | target | issue_field | shape |
|---|---|---|---|
| `endpoint` | `Endpoint.alert_action` | `alertaction` | `flat` |
| `endpoint` | `Endpoint.containment_status` | `endpointstatus` | `flat` |
| `endpoint` | `Endpoint.dns_queries` | `dns_query_name` | `flat` |
| `endpoint` | `Endpoint.domain` | `agent_device_domain` | `flat` |
| `endpoint` | `Endpoint.endpoint_id` | `agent_id` | `flat` |
| `endpoint` | `Endpoint.external_ip` | `deviceexternalips` | `flat` |
| `endpoint` | `Endpoint.file_path` | `action_file_path` | `flat` |
| `endpoint` | `Endpoint.file_sha256` | `action_file_sha256` | `flat` |
| `endpoint` | `Endpoint.hostname` | `agent_hostname` | `flat` |
| `endpoint` | `Endpoint.ip_address` | `action_local_ip` | `flat` |
| `endpoint` | `Endpoint.mac_address` | `mac` | `flat` |
| `endpoint` | `Endpoint.network_accesses` | `network_accesses` | `flat` |
| `endpoint` | `Endpoint.os` | `ostype` | `flat` |
| `endpoint` | `Endpoint.parent_process_cmd` | `parentprocesscmd` | `flat` |
| `endpoint` | `Endpoint.parent_process_name` | `parentprocessname` | `flat` |
| `endpoint` | `Endpoint.parent_process_sha256` | `parentprocesssha256` | `flat` |
| `endpoint` | `Endpoint.process_cmd` | `actor_process_command_line` | `flat` |
| `endpoint` | `Endpoint.process_name` | `actor_process_image_name` | `flat` |
| `endpoint` | `Endpoint.process_path` | `actor_process_image_path` | `flat` |
| `endpoint` | `Endpoint.process_pid` | `actor_process_os_pid` | `flat` |
| `endpoint` | `Endpoint.process_sha256` | `actor_process_image_sha256` | `flat` |
| `endpoint` | `Endpoint.tactic` | `mitretacticname` | `flat` |
| `endpoint` | `Endpoint.tactic_id` | `mitretacticid` | `flat` |
| `endpoint` | `Endpoint.technique` | `mitretechniquename` | `flat` |
| `endpoint` | `Endpoint.technique_id` | `mitretechniqueid` | `flat` |
| `endpoint` | `Endpoint.user_principal` | `user_principal` | `flat` |
| `endpoint` | `Endpoint.username` | `actor_effective_username` | `flat` |
| `endpoint` | `Artifacts.EndPointID` | `agentid` | `structured` |
| `endpoint` | `Artifacts.Endpoint.AgentID` | `agentid` | `structured` |
| `endpoint` | `Artifacts.Endpoint.Domain` | `domain` | `structured` |
| `endpoint` | `Artifacts.Endpoint.FQDN` | `hostfqdn` | `structured` |
| `endpoint` | `Artifacts.Endpoint.Hostname` | `hostname` | `structured` |
| `endpoint` | `Artifacts.Endpoint.MACAddress` | `hostmacaddress` | `structured` |
| `endpoint` | `Artifacts.Endpoint.OS` | `hostos` | `structured` |
| `endpoint` | `Artifacts.Endpoint.OSVersion` | `agentossubtype` | `structured` |
| `endpoint` | `Artifacts.File` | `filesha256.[0]` | `structured` |
| `endpoint` | `Artifacts.FilePath` | `filepath.[0]` | `structured` |
| `endpoint` | `Artifacts.Hash` | `filesha256.[0]` | `structured` |
| `endpoint` | `Artifacts.MITRE.Category` | `categoryname` | `structured` |
| `endpoint` | `Artifacts.MITRE.Tactic` | `mitretacticname` | `structured` |
| `endpoint` | `Artifacts.MITRE.TacticID` | `mitretacticid` | `structured` |
| `endpoint` | `Artifacts.MITRE.Technique` | `mitretechniquename` | `structured` |
| `endpoint` | `Artifacts.MITRE.TechniqueID` | `mitretechniqueid` | `structured` |
| `endpoint` | `Artifacts.Network.IP` | `hostip.[0]` | `structured` |
| `endpoint` | `Artifacts.Process.Causality.ID` | `xdmsourceprocesscausalityid.[0]` | `structured` |
| `endpoint` | `Artifacts.Process.Causality.InstanceID` | `actorprocessinstanceid.[0]` | `structured` |
| `endpoint` | `Artifacts.Process.CommandLine` | `initiatorcmd.[0]` | `structured` |
| `endpoint` | `Artifacts.Process.MD5` | `initiatormd5.[0]` | `structured` |
| `endpoint` | `Artifacts.Process.Name` | `initiatedby.[0]` | `structured` |
| `endpoint` | `Artifacts.Process.PID` | `initiatorpid.[0]` | `structured` |
| `endpoint` | `Artifacts.Process.Parent.PID` | `osparentid.[0]` | `structured` |
| `endpoint` | `Artifacts.Process.Parent.Signature` | `osparentsignature.[0]` | `structured` |
| `endpoint` | `Artifacts.Process.Path` | `initiatorpath.[0]` | `structured` |
| `endpoint` | `Artifacts.Process.SHA256` | `initiatorsha256.[0]` | `structured` |
| `endpoint` | `Artifacts.Process.Signature` | `initiatorsignature.[0]` | `structured` |
| `endpoint` | `Artifacts.Process.Signer` | `initiatorsigner.[0]` | `structured` |
| `endpoint` | `Artifacts.Source.Action` | `action.[0]` | `structured` |
| `endpoint` | `Artifacts.Source.AlertDomain` | `alert_domain` | `structured` |
| `endpoint` | `Artifacts.Source.Module` | `module.[0]` | `structured` |
| `endpoint` | `Artifacts.Target.File` | `filename.[0]` | `structured` |
| `endpoint` | `Artifacts.Target.Path` | `filepath.[0]` | `structured` |
| `endpoint` | `Artifacts.Target.SHA256` | `filesha256.[0]` | `structured` |
| `endpoint` | `Artifacts.Target.SignatureStatus` | `xdmtargetprocessexecutablesignaturestatus.[0]` | `structured` |
| `endpoint` | `Artifacts.User` | `username.[0]` | `structured` |
| `email` | `Email.attachment_name` | `action_file_name` | `flat` |
| `email` | `Email.attachment_sha256` | `action_file_sha256` | `flat` |
| `email` | `Email.campaign_id` | `socfwemailcampaignid` | `flat` |
| `email` | `Email.classification` | `socfwemailclassification` | `flat` |
| `email` | `Email.click_ip` | `socfwemailclickip` | `flat` |
| `email` | `Email.click_time` | `socfwemailclicktime` | `flat` |
| `email` | `Email.delivery_action` | `socfwemaildeliveryaction` | `flat` |
| `email` | `Email.direction` | `socfwemaildirection` | `flat` |
| `email` | `Email.malware_score` | `socfwemailmalwarescore` | `flat` |
| `email` | `Email.message_id` | `emailmessageid` | `flat` |
| `email` | `Email.phish_score` | `socfwemailphishscore` | `flat` |
| `email` | `Email.recipient` | `emailrecipient` | `flat` |
| `email` | `Email.reported_by` | `reporteremailaddress` | `flat` |
| `email` | `Email.sender` | `emailsender` | `flat` |
| `email` | `Email.sender_ip` | `emailsenderip` | `flat` |
| `email` | `Email.subject` | `emailsubject` | `flat` |
| `email` | `Email.threat_id` | `socfwemailthreatid` | `flat` |
| `email` | `Email.threat_status` | `socfwemailthreatstatus` | `flat` |
| `email` | `Email.threat_type` | `socfwemailthreattype` | `flat` |
| `email` | `Email.threat_url` | `socfwemailthreaturl` | `flat` |
| `identity` | `Identity.auth_source` | `authsource` | `flat` |
| `identity` | `Identity.client_ip` | `sourceip` | `flat` |
| `identity` | `Identity.country` | `sourcecountry` | `flat` |
| `identity` | `Identity.device_id` | `deviceid` | `flat` |
| `identity` | `Identity.event_type` | `eventtype` | `flat` |
| `identity` | `Identity.logon_type` | `logontype` | `flat` |
| `identity` | `Identity.mfa_method` | `mfamethod` | `flat` |
| `identity` | `Identity.outcome` | `eventoutcome` | `flat` |
| `identity` | `Identity.risk_level` | `userrisk` | `flat` |
| `identity` | `Identity.session_id` | `sessionid` | `flat` |
| `identity` | `Identity.source_hostname` | `sourcehostname` | `flat` |
| `identity` | `Identity.target_resource` | `targetresource` | `flat` |
| `identity` | `Identity.user_agent` | `useragent` | `flat` |
| `identity` | `Identity.user_display_name` | `userdisplayname` | `flat` |
| `identity` | `Identity.user_email` | `useremail` | `flat` |
| `identity` | `Identity.user_id` | `userid` | `flat` |
| `identity` | `Identity.username` | `username` | `flat` |

## Stamps — literal value → `SOCFramework.*`

| category | target | value |
|---|---|---|
| `endpoint` | `Endpoint.normalization_source` | `endpoint` |
| `endpoint` | `Artifacts.Process.Verdict` |  |
| `endpoint` | `Artifacts.Target.Verdict` |  |
| `email` | `Email.normalization_source` | `email` |
| `email` | `Email.normalization_source` | `mail_listener` |
| `identity` | `Identity.normalization_source` | `identity` |

## Mirrors — `SOCFramework.*` → `SOCFramework.*`

| category | target | source |
|---|---|---|
| `email` | `Artifacts.Email.From` | `Email.sender` |
| `email` | `Artifacts.Email.To` | `Email.recipient` |
| `email` | `Artifacts.Email.Subject` | `Email.subject` |
| `email` | `Artifacts.Email.MessageID` | `Email.message_id` |
| `email` | `Artifacts.Email.ThreatType` | `Email.threat_type` |
| `email` | `Artifacts.Email.ThreatURL` | `Email.threat_url` |
