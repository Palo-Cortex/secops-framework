# SentinelOne Singularity (sentinelone) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/sentinel-one/sentinelone-threat.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/sentinel-one/sentinelone-threat.yaml)

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
| `threatinfo` | `json` |  | declared |  |
| `sourceprocessinfo` | `json` |  | declared |  |
| `sourceparentprocessinfo` | `json` |  | declared |  |
| `targetprocessinfo` | `json` |  | declared |  |
| `agentrealtimeinfo` | `json` |  | declared |  |
| `agentdetectioninfo` | `json` |  | declared |  |
| `indicators` | `json` | ✓ | declared |  |

## Modeling Rule — SentinelOne Singularity Modeling Rule

| Field | Value |
|---|---|
| modeling_rule_id | `SentinelOne_V2_ModelingRule` |
| modeling_rule_name | `SentinelOne Singularity Modeling Rule` |
| directory_name | `SentinelOneV2_ModelingRule` |
| fromversion | `6.10.0` |

### Field Mappings

What each XDM field is, where it sources from, what issue field it surfaces on, and why the mapping is shaped the way it is.

| XDM Path | Expression | Sources | Issue Field | Description |
|---|---|---|---|---|
| `xdm.source.user.username` | `if(   coalesce(     json_extract_scalar(threatinfo, "$.rootProcessUpn"),     ...` | `threatinfo, sourceprocessinfo` | `username` | rootProcessUpn is always clean; sourceprocessinfo.user kept only when it is a real account (SYSTEM/service nulled). processUser dropped — it is the intended field but ~40% arrives encoding-corrupted (mojibake domain prefix), an upstream ingestion bug. Null is preferred over garbage. agentLastLoggedIn* intentionally excluded — it is the host session, not the actor that started the process. |
| `xdm.target.host.hostname` | `json_extract_scalar(agentrealtimeinfo, "$.agentComputerName")` | `agentrealtimeinfo` | `hostname` |  |
| `xdm.target.host.device_id` | `json_extract_scalar(agentrealtimeinfo, "$.agentId")` | `agentrealtimeinfo` | `agentid` |  |
| `xdm.source.process.name` | `json_extract_scalar(sourceprocessinfo, "$.name")` | `sourceprocessinfo` | `initiatedby` |  |
| `xdm.source.process.executable.path` | `json_extract_scalar(sourceprocessinfo, "$.filePath")` | `sourceprocessinfo` | `initiatorpath` |  |
| `xdm.source.process.executable.sha256` | `json_extract_scalar(sourceprocessinfo, "$.fileHashSha256")` | `sourceprocessinfo` | `initiatorsha256` |  |
| `xdm.target.file.sha256` | `json_extract_scalar(threatinfo, "$.sha256")` | `threatinfo` | `filesha256` |  |
| `xdm.target.file.filename` | `json_extract_scalar(threatinfo, "$.threatName")` | `threatinfo` | `filename` |  |
| `xdm.alert.name` | `coalesce(json_extract_scalar(_alert_data, "$.alert_name"), json_extract_scala...` | `_alert_data, threatinfo` | `alertname` |  |
| `xdm.alert.severity` | `lowercase(json_extract_scalar(_alert_data, "$.severity"))` | `_alert_data` | `severity` |  |
| `xdm.alert.description` | `json_extract_scalar(_alert_data, "$.alert_description")` | `_alert_data` | `eventdescription` |  |
| `xdm.observer.vendor` | `"SentinelOne"` |  | `observervendor` |  |
| `xdm.observer.product` | `"SentinelOne Singularity"` |  | `observerproduct` |  |

### Contributes (Artifacts.*)

Fields populated for downstream lifecycle Artifacts schemas:

- `User`
- `Endpoint.Hostname`
- `Endpoint.AgentID`
- `Process.Name`
- `Process.Path`
- `Process.SHA256`
- `Target.File`
- `Target.SHA256`
- `Vendor`
- `Product`

## Correlation Rules

### SOC SentinelOne Threat

| Field | Value |
|---|---|
| global_rule_id | `SOC SentinelOne Threat` |
| subtype | `passthrough` |
| fromversion | `8.0.0` |

Creates an XSIAM passthrough alert for each SentinelOne Singularity threat, normalized to the SOC Framework endpoint contract.

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
| user_defined_category | `tactic` |
| user_defined_severity | `severity` |
| is_enabled | `✓` |
| drilldown_query_timeframe | `ALERT` |
| severity | `User Defined` |

#### Suppression

| Field | Value |
|---|---|
| enabled | `✓` |
| duration | `1 hours` |
| fields | `threat_id` |

threatId is SentinelOne's per-threat unique id.

#### Alert Fields

Issue-field assignments emitted by the correlation rule. The Description column captures intent — when present, this is what downstream playbooks rely on the field meaning.

| Issue Field | Source | Bucket | Description |
|---|---|---|---|
| `vendor` | `vendor_name` | `computed` |  |
| `product` | `product_name` | `computed` |  |
| `severity` | `severity` | `computed` |  |
| `alert_description` | `alert_description` | `computed` |  |
| `originalalertid` | `originalalertid` | `computed` |  |
| `originalalertname` | `originalalertname` | `computed` |  |
| `mitretacticid` | `mitretacticid` | `computed` |  |
| `mitretacticname` | `mitretacticname` | `computed` |  |
| `mitretechniqueid` | `mitretechniqueid` | `computed` |  |
| `agent_hostname` | `agent_hostname` | `computed` |  |
| `agent_id` | `agent_id` | `computed` |  |
| `agent_device_domain` | `agent_device_domain` | `computed` |  |
| `actor_effective_username` | `actor_effective_username` | `computed` |  |
| `actor_process_image_name` | `actor_process_image_name` | `computed` |  |
| `actor_process_image_path` | `actor_process_image_path` | `computed` |  |
| `actor_process_image_sha256` | `actor_process_image_sha256` | `computed` |  |
| `actor_process_command_line` | `actor_process_command_line` | `computed` |  |
| `actor_process_os_pid` | `actor_process_os_pid` | `computed` |  |
| `causality_actor_process_image_name` | `causality_actor_process_image_name` | `computed` |  |
| `causality_actor_process_image_sha256` | `causality_actor_process_image_sha256` | `computed` |  |
| `action_file_name` | `action_file_name` | `computed` |  |
| `action_file_sha256` | `action_file_sha256` | `computed` |  |
| `action_local_ip` | `action_local_ip` | `computed` |  |
| `alert_name` | `alert_name` | `computed` |  |
| `actor_process_signature_vendor` | `actor_process_signature_vendor` | `computed` |  |
| `deviceosname` | `deviceosname` | `computed` |  |
| `deviceexternalips` | `deviceexternalips` | `computed` |  |
| `filesha1` | `file_sha1` | `computed` |  |
| `filemd5` | `file_md5` | `computed` |  |
| `sentinelonethreatid` | `threat_id` | `computed` |  |
| `username` | `actor_effective_username` | `computed` |  |
| `hostname` | `agent_hostname` | `computed` |  |
| `domain` | `agent_device_domain` | `computed` |  |
| `agentid` | `agent_id` | `computed` |  |
| `initiatedby` | `actor_process_image_name` | `computed` |  |
| `initiatorpath` | `actor_process_image_path` | `computed` |  |
| `initiatorsha256` | `actor_process_image_sha256` | `computed` |  |
| `initiatorcmd` | `actor_process_command_line` | `computed` |  |
| `initiatorpid` | `actor_process_os_pid` | `computed` |  |
| `cgosha256` | `causality_actor_process_image_sha256` | `computed` |  |
| `filename` | `action_file_name` | `computed` |  |
| `filesha256` | `action_file_sha256` | `computed` |  |
| `localip` | `action_local_ip` | `computed` |  |

#### Pre-Alter XQL

```xql
| filter _alert_data != null
| alter
    vendor_name  = "SentinelOne",
    product_name = "SentinelOne Singularity",
    severity = lowercase(json_extract_scalar(_alert_data, "$.severity")),
    alert_description = json_extract_scalar(_alert_data, "$.alert_description"),
    threat_id   = json_extract_scalar(threatinfo, "$.threatId"),
    threat_name = json_extract_scalar(threatinfo, "$.threatName"),
    classification = json_extract_scalar(threatinfo, "$.classification"),
    confidence  = json_extract_scalar(threatinfo, "$.confidenceLevel")
// ---- host ----
| alter
    agent_hostname      = json_extract_scalar(agentrealtimeinfo, "$.agentComputerName"),
    agent_id            = json_extract_scalar(agentrealtimeinfo, "$.agentId"),
    agent_device_domain = json_extract_scalar(agentrealtimeinfo, "$.agentDomain"),
    deviceosname        = json_extract_scalar(agentrealtimeinfo, "$.agentOsName"),
    action_local_ip     = json_extract_scalar(agentdetectioninfo, "$.agentIpV4"),
    deviceexternalips   = json_extract_scalar(agentdetectioninfo, "$.externalIp")
// ---- user: clean process-context only; null unless a real account ----
// rootProcessUpn always clean; sourceprocessinfo.user kept only when not
// SYSTEM/service. processUser dropped — ~40% arrives encoding-corrupted.
| alter
    user_candidate = coalesce(
        json_extract_scalar(threatinfo, "$.rootProcessUpn"),
        json_extract_scalar(sourceprocessinfo, "$.user"))
| alter
    actor_effective_username = if(
        user_candidate = null, null,
        lowercase(user_candidate) contains "nt authority", null,
        lowercase(user_candidate) in ("system", "local service", "network service"), null,
        user_candidate)
// ---- initiator process ----
| alter
    actor_process_image_name       = json_extract_scalar(sourceprocessinfo, "$.name"),
    actor_process_image_path       = json_extract_scalar(sourceprocessinfo, "$.filePath"),
    actor_process_image_sha256     = json_extract_scalar(sourceprocessinfo, "$.fileHashSha256"),
    actor_process_command_line     = json_extract_scalar(sourceprocessinfo, "$.commandline"),
    actor_process_os_pid           = json_extract_scalar(sourceprocessinfo, "$.pid"),
    actor_process_signature_vendor = json_extract_scalar(sourceprocessinfo, "$.fileSignerIdentity")
// ---- parent / causality (CGO) ----
| alter
    causality_actor_process_image_name   = json_extract_scalar(sourceparentprocessinfo, "$.name"),
    causality_actor_process_image_path   = json_extract_scalar(sourceparentprocessinfo, "$.filePath"),
    causality_actor_process_image_sha256 = json_extract_scalar(sourceparentprocessinfo, "$.fileHashSha256"),
    causality_actor_causality_id         = coalesce(
        json_extract_scalar(threatinfo, "$.storyline"),
        json_extract_scalar(sourceprocessinfo, "$.storyline"))
// ---- file / threat (detection target) ----
| alter
    action_file_name   = threat_name,
    action_file_sha256 = json_extract_scalar(threatinfo, "$.sha256"),
    file_sha1          = json_extract_scalar(threatinfo, "$.sha1"),
    file_md5           = json_extract_scalar(threatinfo, "$.md5")
// ---- MITRE (best-effort; SentinelOne indicators rarely carry ATT&CK) ----
| alter
    mitretacticname  = arraystring(arraymap(arrayfilter(indicators -> [], array_length("@element" -> tactics[]) > 0), "@element" -> category), ", "),
    mitretacticid    = null,
    mitretechniqueid = null
| alter
    originalalertid     = threat_id,
    originalalertname   = threat_name,
    alert_name = concat(
        "[Endpoint] ",
        coalesce(agent_hostname, "Unknown Host"), " | ",
        coalesce(classification, "Threat"), " | ",
        coalesce(threat_name, "Detection"))
```
