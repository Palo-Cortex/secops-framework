# SentinelOne Singularity (sentinelone) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/sentinel-one/soc-sentinelone-threat.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/sentinel-one/soc-sentinelone-threat.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `sentinelone` |
| product | `SentinelOne Singularity` |
| data_source | `sentinelone_v2_generic_alert_raw` |
| category | `Endpoint` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `_alert_data` | `json` |  | declared |  |
| `threatInfo` | `json` |  | declared |  |
| `sourceProcessInfo` | `json` |  | declared |  |
| `sourceParentProcessInfo` | `json` |  | declared |  |
| `agentRealtimeInfo` | `json` |  | declared |  |
| `indicators` | `json` | ✓ | declared |  |

## Modeling Rule — SentinelOne Singularity Modeling Rule

| Field | Value |
|---|---|
| modeling_rule_id | `SentinelOne_V2_ModelingRule` |
| modeling_rule_name | `SentinelOne Singularity Modeling Rule` |
| directory_name | `SentinelOneV2_ModelingRule` |
| fromversion | `8.0.0` |

### Field Mappings

What each XDM field is, where it sources from, what issue field it surfaces on, and why the mapping is shaped the way it is.

| XDM Path | Expression | Sources | Issue Field | Description |
|---|---|---|---|---|
| `xdm.observer.vendor` | `"SentinelOne"` |  |  |  |
| `xdm.observer.product` | `"SentinelOne Singularity"` |  |  |  |
| `xdm.alert.severity` | `lowercase(json_extract_scalar(_alert_data, "$.severity"))` |  |  |  |
| `xdm.alert.name` | `json_extract_scalar(_alert_data, "$.alert_name")` |  |  |  |
| `xdm.alert.description` | `json_extract_scalar(_alert_data, "$.alert_description")` |  |  |  |
| `xdm.source.user.username` | `lowercase(coalesce(   threatInfo -> processUser,   sourceProcessInfo -> effec...` |  |  | Filters SYSTEM / NT AUTHORITY / service accounts to null. No domain-strip — REAL_TIME forbids the identity-map join. |
| `xdm.source.host.hostname` | `agentRealtimeInfo -> agentComputerName` |  |  |  |
| `xdm.source.agent.identifier` | `json_extract_scalar(_alert_data, "$.agent_id")` |  |  |  |
| `xdm.source.host.device_id` | `json_extract_scalar(_alert_data, "$.agent_id")` |  |  |  |
| `xdm.source.process.name` | `coalesce(threatInfo -> originatorProcess, sourceProcessInfo -> name)` |  |  |  |
| `xdm.source.process.executable.path` | `coalesce(threatInfo -> filePath, sourceProcessInfo -> filePath)` |  |  |  |
| `xdm.source.process.executable.sha256` | `coalesce(threatInfo -> sha256, sourceProcessInfo -> fileHashSha256)` |  |  |  |
| `xdm.source.process.command_line` | `coalesce(sourceProcessInfo -> commandline, threatInfo -> maliciousProcessArgu...` |  |  |  |
| `xdm.source.process.pid` | `sourceProcessInfo -> pid` |  |  |  |
| `xdm.source.process.executable.signer` | `coalesce(threatInfo -> publisherName, sourceProcessInfo -> fileSignerIdentity)` |  |  |  |
| `xdm.source.process.parent_process.executable.name` | `sourceParentProcessInfo -> name` |  |  |  |
| `xdm.source.process.parent_process.executable.path` | `sourceParentProcessInfo -> filePath` |  |  |  |
| `xdm.source.process.parent_process.executable.sha256` | `sourceParentProcessInfo -> fileHashSha256` |  |  |  |
| `xdm.source.process.causality_id` | `coalesce(sourceProcessInfo -> storyline, sourceParentProcessInfo -> storyline)` |  |  | S1 storyline is the causality pivot — the strongest cross-alert grouping key. |
| `xdm.target.file.filename` | `threatInfo -> threatName` |  |  |  |
| `xdm.target.file.sha256` | `coalesce(threatInfo -> sha256, sourceProcessInfo -> fileHashSha256)` |  |  |  |
| `xdm.target.file.sha1` | `coalesce(threatInfo -> sha1, sourceProcessInfo -> fileHashSha1)` |  |  |  |
| `xdm.target.file.md5` | `coalesce(threatInfo -> md5, sourceProcessInfo -> fileHashMd5)` |  |  |  |

### Contributes (Artifacts.*)

Fields populated for downstream lifecycle Artifacts schemas:

- `Vendor`
- `Product`
- `User`
- `Endpoint.Hostname`
- `Endpoint.AgentID`
- `Process.Name`
- `Process.Path`
- `Process.SHA256`
- `Process.CommandLine`
- `Process.PID`
- `Process.Signer`
- `Process.Parent.Name`
- `Process.Parent.Path`
- `Process.Parent.SHA256`
- `Process.Causality.ID`
- `Target.File`
- `Target.SHA256`

## Correlation Rules

### SOC SentinelOne Threat

| Field | Value |
|---|---|
| global_rule_id | `SOC SentinelOne Threat` |
| subtype | `passthrough` |
| fromversion | `8.0.0` |

Creates an XSIAM passthrough alert for each SentinelOne Singularity threat, normalized to the SOC Framework endpoint contract for cross-vendor case grouping.

**Tags:** `SOCFramework`, `Passthrough`, `Endpoint`, `SentinelOne`

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| action | `ALERTS` |
| execution_mode | `REAL_TIME` |
| mapping_strategy | `CUSTOM` |
| user_defined_category | `alert_cat` |
| user_defined_severity | `severity` |
| is_enabled | `✓` |
| drilldown_query_timeframe | `ALERT` |
| severity | `User Defined` |

#### Suppression

| Field | Value |
|---|---|
| enabled | `✓` |
| duration | `1 hours` |
| fields | `s1_threat_id` |

#### Alert Fields

Issue-field assignments emitted by the correlation rule. The Description column captures intent — when present, this is what downstream playbooks rely on the field meaning.

| Issue Field | Source | Bucket | Description |
|---|---|---|---|
| `vendor` | `vendor` |  |  |
| `product` | `product` |  |  |
| `severity` | `severity` |  |  |
| `alert_description` | `alert_description` |  |  |
| `alert_name` | `alert_name` |  |  |
| `originalalertid` | `originalalertid` |  |  |
| `originalalertname` | `originalalertname` |  |  |
| `sentinelonethreatid` | `s1_threat_id` |  |  |
| `mitretacticid` | `mitre_tactic_id` |  |  |
| `mitretacticname` | `mitre_tactic` |  |  |
| `mitretechniqueid` | `mitre_ids_str` |  |  |
| `mitretechniquename` | `mitre_ids_str` |  |  |
| `agent_hostname` | `agent_hostname` |  |  |
| `hostname` | `agent_hostname` |  |  |
| `agent_id` | `agent_id` |  |  |
| `agentid` | `agent_id` |  |  |
| `agent_device_domain` | `agent_device_domain` |  |  |
| `domain` | `agent_device_domain` |  |  |
| `deviceosname` | `deviceosname` |  |  |
| `actor_effective_username` | `actor_effective_username` |  |  |
| `username` | `actor_effective_username` |  |  |
| `user_principal` | `user_principal` |  |  |
| `actor_process_image_name` | `actor_process_image_name` |  |  |
| `initiatedby` | `actor_process_image_name` |  |  |
| `actor_process_image_path` | `actor_process_image_path` |  |  |
| `initiatorpath` | `actor_process_image_path` |  |  |
| `actor_process_image_sha256` | `actor_process_image_sha256` |  |  |
| `initiatorsha256` | `actor_process_image_sha256` |  |  |
| `actor_process_command_line` | `actor_process_command_line` |  |  |
| `initiatorcmd` | `actor_process_command_line` |  |  |
| `actor_process_os_pid` | `actor_process_os_pid` |  |  |
| `initiatorpid` | `actor_process_os_pid` |  |  |
| `actor_process_signature_vendor` | `actor_process_signature_vendor` |  |  |
| `initiatorsigner` | `actor_process_signature_vendor` |  |  |
| `causality_actor_process_image_name` | `causality_actor_process_image_name` |  |  |
| `causality_actor_process_image_path` | `causality_actor_process_image_path` |  |  |
| `causality_actor_process_image_sha256` | `causality_actor_process_image_sha256` |  |  |
| `cgosha256` | `causality_actor_process_image_sha256` |  |  |
| `causality_actor_process_command_line` | `causality_actor_process_command_line` |  |  |
| `causality_actor_causality_id` | `causality_actor_causality_id` |  |  |
| `xdmsourceprocesscausalityid` | `causality_actor_causality_id` |  |  |
| `action_file_name` | `action_file_name` |  |  |
| `filename` | `action_file_name` |  |  |
| `action_file_sha256` | `action_file_sha256` |  |  |
| `filesha256` | `action_file_sha256` |  |  |
| `filehash` | `action_file_sha256` |  |  |
| `file_sha1` | `file_sha1` |  |  |
| `filesha1` | `file_sha1` |  |  |
| `filemd5` | `file_md5` |  |  |

#### Pre-Alter XQL

```xql
| filter _alert_data != null
| filter json_extract_scalar(_alert_data, "$.alert_name") ~= "Sentinel One Threat"

| alter
    vendor            = "SentinelOne",
    product           = "SentinelOne Singularity",
    severity          = lowercase(coalesce(json_extract_scalar(_alert_data, "$.severity"), "medium")),
    s1_threat_id      = id,
    classification    = threatInfo -> classification,
    confidence        = threatInfo -> confidenceLevel,
    detection_type    = threatInfo -> detectionType,
    threat_name       = threatInfo -> threatName

| alter
    agent_hostname      = agentRealtimeInfo -> agentComputerName,
    agent_id            = _alert_data -> agent_id,
    agent_device_domain = agentRealtimeInfo -> agentDomain,
    deviceosname        = agentRealtimeInfo -> agentOsName

| alter
    user_raw                 = coalesce(threatInfo -> processUser, sourceProcessInfo -> effectiveUser, sourceProcessInfo -> user),
    actor_effective_username = lowercase(coalesce(threatInfo -> processUser, sourceProcessInfo -> effectiveUser, sourceProcessInfo -> user)),
    user_principal           = if(coalesce(threatInfo -> processUser, sourceProcessInfo -> user, "") contains "@",
                                   coalesce(threatInfo -> processUser, sourceProcessInfo -> user), null)

| alter
    actor_process_image_name       = coalesce(threatInfo -> originatorProcess, sourceProcessInfo -> name),
    actor_process_image_path       = coalesce(threatInfo -> filePath, sourceProcessInfo -> filePath),
    actor_process_image_sha256     = coalesce(threatInfo -> sha256, sourceProcessInfo -> fileHashSha256),
    actor_process_command_line     = coalesce(sourceProcessInfo -> commandline, threatInfo -> maliciousProcessArguments),
    actor_process_os_pid           = sourceProcessInfo -> pid,
    actor_process_signature_vendor = coalesce(threatInfo -> publisherName, sourceProcessInfo -> fileSignerIdentity)

| alter
    causality_actor_process_image_name   = sourceParentProcessInfo -> name,
    causality_actor_process_image_path   = sourceParentProcessInfo -> filePath,
    causality_actor_process_image_sha256 = sourceParentProcessInfo -> fileHashSha256,
    causality_actor_process_command_line = sourceParentProcessInfo -> commandline,
    causality_actor_causality_id         = coalesce(sourceProcessInfo -> storyline, sourceParentProcessInfo -> storyline)

| alter
    action_file_name   = threat_name,
    action_file_sha256 = coalesce(threatInfo -> sha256, sourceProcessInfo -> fileHashSha256),
    file_sha1          = coalesce(threatInfo -> sha1, sourceProcessInfo -> fileHashSha1),
    file_md5           = coalesce(threatInfo -> md5, sourceProcessInfo -> fileHashMd5)

| alter
    indicator_descriptions = arraystring(arraydistinct(arraymap(json_extract_array(to_json_string(indicators), "$."), concat("@element" -> description, " (", "@element" -> category, ")"))), ", "),
    mitre_tactic           = arraystring(arraydistinct(arraymap(json_extract_array(to_json_string(indicators), "$."), "@element" -> category)), ", "),
    mitre_tactic_id        = null,
    mitre_ids_str          = null

| alter
    alert_cat         = coalesce(classification, "Threat"),
    alert_description = coalesce(json_extract_scalar(_alert_data, "$.alert_description"),
                                 concat("SentinelOne threat: ", coalesce(threat_name, "Detection"))),
    originalalertid   = s1_threat_id,
    originalalertname = threat_name,
    alert_name = concat(
        "[Endpoint] ",
        coalesce(agent_hostname, "Unknown Host"), " | ",
        coalesce(classification, "Threat"), " | ",
        coalesce(threat_name, "Detection"))
```
