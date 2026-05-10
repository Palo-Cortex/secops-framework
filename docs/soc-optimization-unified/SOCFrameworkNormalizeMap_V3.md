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
| `identity` | in-progress |  | `Foundation_-_Normalize_Identity_V3` |

## Mappings — `issue.*` → `SOCFramework.*`

| category | target | issue_field | shape | role | source_origin | notes | superseded_by |
|---|---|---|---|---|---|---|---|
| `endpoint` | `Endpoint.alert_action` | `alertaction` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.containment_status` | `endpointisolationstatus` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.dns_queries` | `dnsqueryname` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.domain` | `domain` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.endpoint_id` | `agentid` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.external_ip` | `deviceexternalips` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.file_path` | `filepath.[0]` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.file_sha256` | `filesha256.[0]` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.hostname` | `hostname` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.ip_address` | `localip` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.mac_address` | `hostmacaddress` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.os` | `ostype` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.parent_process_cmd` | `parentprocesscmd` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.parent_process_name` | `parentprocessname` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.parent_process_sha256` | `parentprocesssha256` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.process_cmd` | `initiatorcmd.[0]` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.process_name` | `initiatedby.[0]` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.process_path` | `initiatorpath.[0]` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.process_pid` | `initiatorpid.[0]` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.process_sha256` | `initiatorsha256.[0]` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.tactic` | `mitretacticname` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.tactic_id` | `mitretacticid` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.technique` | `mitretechniquename` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.technique_id` | `mitretechniqueid` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Endpoint.username` | `username.[0]` | `flat` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Endpoint.AgentID` | `agentid` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Endpoint.Domain` | `domain` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Endpoint.FQDN` | `hostfqdn` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Endpoint.Hostname` | `hostname` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Endpoint.MACAddress` | `hostmacaddress` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Endpoint.OS` | `hostos` | `structured` | `canonical` | `native` | Display string (e.g., 'Windows 10 Pro'). Distinct from flat Endpoint.os which uses ostype family. |  |
| `endpoint` | `Artifacts.Endpoint.OSVersion` | `agentossubtype` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.MITRE.Category` | `categoryname` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.MITRE.Tactic` | `mitretacticname` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.MITRE.TacticID` | `mitretacticid` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.MITRE.Technique` | `mitretechniquename` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.MITRE.TechniqueID` | `mitretechniqueid` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Network.IP` | `hostip.[0]` | `structured` | `canonical` | `native` | Host primary IP. Distinct from flat Endpoint.ip_address (localip). |  |
| `endpoint` | `Artifacts.Process.Causality.ID` | `xdmsourceprocesscausalityid.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.Causality.InstanceID` | `actorprocessinstanceid.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.CommandLine` | `initiatorcmd.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.MD5` | `initiatormd5.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.Name` | `initiatedby.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.Parent.PID` | `osparentid.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.Parent.Signature` | `osparentsignature.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.Path` | `initiatorpath.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.PID` | `initiatorpid.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.SHA256` | `initiatorsha256.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.Signature` | `initiatorsignature.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Process.Signer` | `initiatorsigner.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Source.Action` | `action.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Source.AlertDomain` | `alert_domain` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Source.Module` | `module.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Target.File` | `filename.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Target.Path` | `filepath.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Target.SHA256` | `filesha256.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.Target.SignatureStatus` | `xdmtargetprocessexecutablesignaturestatus.[0]` | `structured` | `canonical` | `native` |  |  |
| `endpoint` | `Artifacts.EndPointID` | `agentid` | `structured` | `legacy_alias` | `native` |  | `Artifacts.Endpoint.AgentID` |
| `endpoint` | `Artifacts.File` | `filesha256.[0]` | `structured` | `legacy_alias` | `native` |  | `Artifacts.Target.SHA256` |
| `endpoint` | `Artifacts.FilePath` | `filepath.[0]` | `structured` | `legacy_alias` | `native` |  | `Artifacts.Target.Path` |
| `endpoint` | `Artifacts.Hash` | `filesha256.[0]` | `structured` | `legacy_alias` | `native` |  | `Artifacts.Target.SHA256` |
| `endpoint` | `Artifacts.User` | `username.[0]` | `structured` | `legacy_alias` | `native` |  | `Artifacts.User.Name (TBD — User sub-tree not yet authored)` |
| `email` | `Email.attachment_name` | `filename.[0]` | `flat` | `canonical` | `native` | Was: action_file_name (alert-field, not a cliName). Switched to filename per cliName convergence; verify email vendor packs route attachment metadata through filename cliName. |  |
| `email` | `Email.attachment_sha256` | `filesha256.[0]` | `flat` | `canonical` | `native` | Was: action_file_sha256 (alert-field, not a cliName). Same caveat as attachment_name. |  |
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
| `identity` | `Identity.auth_source` | `socfwidentityauthsource` | `flat` | `canonical` | `socfw_custom` | Custom exists on tenant. Was: authsource (not registered). |  |
| `identity` | `Identity.client_ip` | `localip` | `flat` | `canonical` | `native` | Flipped sourceip → localip per cliName convergence. Same cliName as Endpoint.ip_address; on Identity alerts represents the user's source IP, not an endpoint. |  |
| `identity` | `Identity.country` | `socfwidentitycountry` | `flat` | `canonical` | `socfw_custom` | Custom exists on tenant. Was: sourcecountry (not registered). Magnifier alerts also surface a `country` field but its registered status is unverified — sticking with the verified custom. |  |
| `identity` | `Identity.device_id` | `socfwidentitydeviceid` | `flat` | `canonical` | `socfw_custom` | PENDING — assumed not registered, verify on tenant before creating. Source device identifier for the auth event. |  |
| `identity` | `Identity.event_type` | `eventtype` | `flat` | `canonical` | `native` | Native cliName. Magnifier alerts use integer codes (e.g., 102 = Impossible Traveler); xdmeventtype carries the string form (e.g., DML_CONNECTION). |  |
| `identity` | `Identity.logon_type` | `socfwidentitylogontype` | `flat` | `canonical` | `socfw_custom` | PENDING — needs creating. No native cliName, no existing custom. |  |
| `identity` | `Identity.mfa_method` | `socfwidentitymfamethod` | `flat` | `canonical` | `socfw_custom` | PENDING — needs creating. Vendor pack alert_fields would emit from xdm.event.operation_sub_type after MFA factor classification. |  |
| `identity` | `Identity.outcome` | `socfwidentityoutcome` | `flat` | `canonical` | `socfw_custom` | Custom exists on tenant. Was: eventoutcome (not registered). |  |
| `identity` | `Identity.risk_level` | `socfwidentityrisklevel` | `flat` | `canonical` | `socfw_custom` | Custom exists on tenant. Was: userrisk (not registered). |  |
| `identity` | `Identity.session_id` | `socfwidentitysessionid` | `flat` | `canonical` | `socfw_custom` | PENDING — needs creating. Required for forced-session-revocation Containment action (soc-clear-sessions). |  |
| `identity` | `Identity.source_hostname` | `hostname` | `flat` | `canonical` | `native` | Flipped sourcehostname → hostname per cliName convergence. WARNING: For SSO alerts, hostname carries the user's source IP, NOT a hostname. Identity normalizer treats as auth-source signal. |  |
| `identity` | `Identity.target_resource` | `socfwidentitytargetresource` | `flat` | `canonical` | `socfw_custom` | PENDING — needs creating. Target SSO app / resource the auth event hit (Salesforce, GSuite, etc.). |  |
| `identity` | `Identity.user_agent` | `initiatedby.[0]` | `flat` | `canonical` | `native` | Flipped useragent → initiatedby per cliName convergence. Reuses the endpoint-band cliName; on Identity alerts carries browser/UA strings (e.g., 'Edge 18.26200', 'Chrome 146.0.0'). |  |
| `identity` | `Identity.user_display_name` | `socfwidentityuserdisplayname` | `flat` | `canonical` | `socfw_custom` | Custom exists on tenant. Was: userdisplayname (not registered). |  |
| `identity` | `Identity.user_email` | `socfwidentityuseremail` | `flat` | `canonical` | `socfw_custom` | Custom exists on tenant. Was: useremail (not registered). |  |
| `identity` | `Identity.user_id` | `userid` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.username` | `username.[0]` | `flat` | `canonical` | `native` | Array on Magnifier alerts (e.g., ['corp\\5827014']); .[0] extraction matches endpoint-band convention. |  |

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
| `identity` | `Artifacts.Identity.User.Name` | `Identity.username` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.User.ID` | `Identity.user_id` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.User.DisplayName` | `Identity.user_display_name` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.User.Email` | `Identity.user_email` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Source.IP` | `Identity.client_ip` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Source.Hostname` | `Identity.source_hostname` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Source.Country` | `Identity.country` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Source.UserAgent` | `Identity.user_agent` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Source.DeviceID` | `Identity.device_id` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Auth.Source` | `Identity.auth_source` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Auth.Outcome` | `Identity.outcome` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Auth.SessionID` | `Identity.session_id` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Auth.MFAMethod` | `Identity.mfa_method` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Auth.LogonType` | `Identity.logon_type` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Provider.EventType` | `Identity.event_type` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Risk.Level` | `Identity.risk_level` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Target.Resource` | `Identity.target_resource` | `canonical` | `structured` |
