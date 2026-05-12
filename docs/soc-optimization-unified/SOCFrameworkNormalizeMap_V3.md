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
| `network` | in-progress |  | `Foundation_-_Normalize_Network_V3` |

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
| `identity` | `Identity.client_ip` | `localip` | `flat` | `canonical` | `native` | Same cliName as Endpoint.ip_address; on Identity alerts represents the user's source IP, not an endpoint. |  |
| `identity` | `Identity.country` | `country` | `flat` | `canonical` | `native` | Native cliName, observed populated as array of country names on SSO Brute Force dump (e.g., ['AUSTRIA', 'LUXEMBOURG', 'UNITED_STATES', 'NETHERLANDS', 'SWEDEN']). Was: socfwidentitycountry — flipped per lean cut. |  |
| `identity` | `Identity.event_type` | `eventtype` | `flat` | `canonical` | `native` | Native cliName. Magnifier alerts use integer codes (102 observed on both Impossible Traveler and SSO Brute Force samples — code is generic auth-event-of-interest, not alert-specific); xdmeventtype carries the string form (e.g., DML_CONNECTION). |  |
| `identity` | `Identity.source_hostname` | `hostname` | `flat` | `canonical` | `native` | Same cliName as Endpoint.hostname. WARNING: For SSO alerts, hostname carries the user's source IP, NOT a hostname. Identity normalizer treats as auth-source signal. |  |
| `identity` | `Identity.user_agent` | `initiatedby.[0]` | `flat` | `canonical` | `native` | Reuses the endpoint-band cliName; on Identity alerts carries browser/UA strings — full UA on some samples ('Edge 18.26200', 'Chrome 146.0.0'), abbreviated browser names on others ('FIREFOX', 'UNKNOWN'). |  |
| `identity` | `Identity.user_email` | `email` | `flat` | `canonical` | `native` | Native cliName, observed populated on tenant alert dumps. Was: socfwidentityuseremail — flipped per lean cut. |  |
| `identity` | `Identity.user_id` | `userid` | `flat` | `canonical` | `native` |  |  |
| `identity` | `Identity.username` | `username.[0]` | `flat` | `canonical` | `native` | Array on Magnifier alerts (e.g., ['paloaltonetwork\\ocohen']); .[0] extraction matches endpoint-band convention. |  |
| `network` | `Network.action` | `action` | `flat` | `canonical` | `native` | Single value not array on observed Network dump (action: 'DETECTED'). Endpoint band uses action.[0]; Network alerts surface as scalar. |  |
| `network` | `Network.application` | `appid.[0]` | `flat` | `canonical` | `native` | PAN App-ID stack as concatenated string (e.g., 'ip,tcp,ms-ds-smbv3'). Drives Analysis verdict scoring for L7 anomalies. |  |
| `network` | `Network.destination_country` | `xdmtargetlocationcountry.[0]` | `flat` | `canonical` | `native` | Empty ('-') for internal-to-internal traffic on observed dump; populated for egress. |  |
| `network` | `Network.destination_hostname` | `xdmtargethosthostname.[0]` | `flat` | `canonical` | `native` |  |  |
| `network` | `Network.destination_ip` | `xdmtargetipv4.[0]` | `flat` | `canonical` | `native` | Drives soc-block-ip and soc-update-acl. Same value as remoteip on PANW NGFW alerts; xdmtarget chosen as canonical for cross-vendor portability. |  |
| `network` | `Network.destination_port` | `xdmtargetport.[0]` | `flat` | `canonical` | `native` |  |  |
| `network` | `Network.destination_zone` | `destinationzonename.[0]` | `flat` | `canonical` | `native` | Firewall destination zone (e.g., 'Infrastructure'). Network-specific concept, no analogue in Endpoint/Identity bands. |  |
| `network` | `Network.device_name` | `fwname.[0]` | `flat` | `canonical` | `native` | Firewall display name. Drives vendor branch routing in SOC_Network_Containment_V3 / Recovery via SOCExecutionList_V3. |  |
| `network` | `Network.device_rule_name` | `fwrulename.[0]` | `flat` | `canonical` | `native` | Pipe-delimited 'vsys\|policy' form on PAN (e.g., 'rangexsiam\|Lab Learning Policy'). Required by soc-update-acl and soc-restore-acl. |  |
| `network` | `Network.device_serial` | `fwserialnumber.[0]` | `flat` | `canonical` | `native` | Firewall hardware serial. Required for vendor API targeting on multi-firewall deployments. |  |
| `network` | `Network.dns_query` | `dnsqueryname` | `flat` | `canonical` | `native` | Native cliName, verified in prior cliName-convergence changelog (NOT dns_query_name). Not present on NGFW BIOC alerts; populated on DNS-firewall alerts (Umbrella, PAN DNS Security). Required by soc-block-domain DNS-firewall path. |  |
| `network` | `Network.event_type` | `xdmeventtype.[0]` | `flat` | `canonical` | `native` | DML event classification (e.g., 'DML_CONNECTION'). Distinct from numeric eventtype which is alert-classification code. |  |
| `network` | `Network.source_country` | `xdmsourcelocationcountry.[0]` | `flat` | `canonical` | `native` | 'UNKNOWN' for RFC1918 sources on observed dump; populated for external sources. Drives geo-anomaly verdict signals. |  |
| `network` | `Network.source_hostname` | `xdmsourcehosthostname` | `flat` | `canonical` | `native` | Single string not array on observed Network dump (cf. Identity band where the hostname cliName carries source IP for SSO alerts). On Network alerts, carries actual hostname. |  |
| `network` | `Network.source_ip` | `xdmsourceipv4.[0]` | `flat` | `canonical` | `native` | Drives soc-quarantine-network targeting. Same value as localip on PANW NGFW alerts; xdmsource chosen as canonical. |  |
| `network` | `Network.source_port` | `localport.[0]` | `flat` | `canonical` | `native` | Source ephemeral port. No xdmsourceport observed on dump; localport is the canonical source-port cliName. |  |
| `network` | `Network.source_zone` | `sourcezonename.[0]` | `flat` | `canonical` | `native` | Firewall source zone (e.g., 'Users'). Network-specific. |  |

## Stamps — literal value → `SOCFramework.*`

| category | target | value | role | notes |
|---|---|---|---|---|
| `endpoint` | `Endpoint.normalization_source` | `endpoint` | `canonical` |  |
| `endpoint` | `Artifacts.Process.Verdict` |  | `canonical` | Empty-init for downstream Analysis verdict assignment. |
| `endpoint` | `Artifacts.Target.Verdict` |  | `canonical` | Empty-init for downstream Analysis verdict assignment. |
| `email` | `Email.normalization_source` | `email` | `canonical` |  |
| `email` | `Email.normalization_source` | `mail_listener` | `canonical` | Alternate stamp set when alert routes via mail_listener integration. |
| `identity` | `Identity.normalization_source` | `identity` | `canonical` |  |
| `network` | `Network.normalization_source` | `network` | `canonical` |  |

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
| `identity` | `Artifacts.Identity.User.Email` | `Identity.user_email` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Source.IP` | `Identity.client_ip` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Source.Hostname` | `Identity.source_hostname` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Source.Country` | `Identity.country` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Source.UserAgent` | `Identity.user_agent` | `canonical` | `structured` |
| `identity` | `Artifacts.Identity.Provider.EventType` | `Identity.event_type` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Destination.Country` | `Network.destination_country` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Destination.Hostname` | `Network.destination_hostname` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Destination.IP` | `Network.destination_ip` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Destination.Port` | `Network.destination_port` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Destination.Zone` | `Network.destination_zone` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Device.Name` | `Network.device_name` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Device.RuleName` | `Network.device_rule_name` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Device.Serial` | `Network.device_serial` | `canonical` | `structured` |
| `network` | `Artifacts.Network.DNS.Query` | `Network.dns_query` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Flow.Action` | `Network.action` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Flow.Application` | `Network.application` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Flow.EventType` | `Network.event_type` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Source.Country` | `Network.source_country` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Source.Hostname` | `Network.source_hostname` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Source.IP` | `Network.source_ip` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Source.Port` | `Network.source_port` | `canonical` | `structured` |
| `network` | `Artifacts.Network.Source.Zone` | `Network.source_zone` | `canonical` | `structured` |
