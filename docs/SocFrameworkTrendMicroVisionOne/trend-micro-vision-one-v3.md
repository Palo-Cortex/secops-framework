# Vision One (trend-vision-one) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/trend-micro-vision-one/trend-micro-vision-one-v3.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/trend-micro-vision-one/trend-micro-vision-one-v3.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `trend-vision-one` |
| product | `Vision One` |
| data_source | `trend_micro_vision_one_v3_generic_alert_raw` |
| category | `Endpoint` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `alert_provider` | `string` |  | declared |  |
| `impact_scope` | `json` |  | declared | entities |
| `indicators` | `json` |  | declared |  |
| `matched_rules` | `json` |  | declared | id, name, matched_filters |
| `_raw_json` | `json` |  | declared |  |
| `id` | `string` |  | declared |  |
| `model` | `string` |  | declared |  |
| `model_id` | `string` |  | declared |  |
| `model_type` | `string` |  | declared |  |
| `severity` | `string` |  | declared |  |
| `status` | `string` |  | declared |  |
| `investigation_status` | `string` |  | declared |  |
| `investigation_result` | `string` |  | declared |  |
| `description` | `string` |  | declared |  |
| `workbench_link` | `string` |  | declared |  |
| `score` | `string` |  | declared |  |
| `created_date_time` | `string` |  | declared |  |
| `updated_date_time` | `string` |  | declared |  |
| `schema_version` | `string` |  | declared |  |
| `_alert_data` | `json` |  | inferred_from_correlation | raw_json |

## Modeling Rule — SOC TrendMicro VisionOne Modeling Rule

| Field | Value |
|---|---|
| modeling_rule_id | `SOC_TrendMicro_VisionOne_ModelingRule` |
| modeling_rule_name | `SOC TrendMicro VisionOne Modeling Rule` |
| directory_name | `SOCTrendMicroVisionOneModelingRules` |
| fromversion | `8.3.1` |

### Contributes (Artifacts.*)

Fields populated for downstream lifecycle Artifacts schemas:

- `Endpoint.Hostname`
- `Endpoint.DeviceID`
- `Endpoint.OS`
- `Network.LocalIP`
- `Network.RemoteIP`
- `User`
- `Process.Name`
- `Process.SHA256`
- `Process.CommandLine`
- `MITRE.Tactic`
- `MITRE.Technique`
- `Alert.Name`
- `Alert.Severity`
- `Observer.Vendor`
- `Observer.Product`

## Correlation Rules

### SOC Trend Micro Vision One V3

| Field | Value |
|---|---|
| global_rule_id | `SOC Trend Micro Vision One V3` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Creates an XSIAM alert for each Trend Micro Vision One workbench detection event.

**Tags:** `SOCFramework`, `Passthrough`, `Endpoint`, `TrendMicroVisionOne`

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
| fields | `id` |

#### Alert Fields

Issue-field assignments emitted by the correlation rule. The Description column captures intent — when present, this is what downstream playbooks rely on the field meaning.

| Issue Field | Source | Bucket | Description |
|---|---|---|---|
| `vendor` | `vendor` | `computed` |  |
| `product` | `product` | `computed` |  |
| `originalalertid` | `originalalertid` | `computed` |  |
| `originalalertname` | `originalalertname` | `computed` |  |
| `originalalertsource` | `originalalertsource` | `computed` |  |
| `externallink` | `externallink` | `computed` |  |
| `alert_description` | `alert_description` | `computed` |  |
| `severity` | `severity` | `computed` |  |
| `mitretacticid` | `mitretacticid` | `computed` |  |
| `mitretacticname` | `mitretacticname` | `computed` |  |
| `mitretechniqueid` | `mitretechniqueid` | `computed` |  |
| `mitretechniquename` | `mitretechniquename` | `computed` |  |
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
| `causality_actor_process_image_path` | `causality_actor_process_image_path` | `computed` |  |
| `causality_actor_process_image_sha256` | `causality_actor_process_image_sha256` | `computed` |  |
| `action_file_name` | `action_file_name` | `computed` |  |
| `action_file_path` | `action_file_path` | `computed` |  |
| `action_file_sha256` | `action_file_sha256` | `computed` |  |
| `action_local_ip` | `action_local_ip` | `computed` |  |
| `action_remote_ip` | `action_remote_ip` | `computed` |  |
| `filehash` | `sha256` | `computed` |  |
| `mac` | `mac_address` | `computed` |  |
| `processcmd` | `cmdline` | `computed` |  |
| `parentprocessname` | `parent_process_name` | `computed` |  |
| `parentprocesspath` | `parent_process_path` | `computed` |  |
| `external_pivot_url` | `workbench_link` | `computed` |  |
| `externalstatus` | `status` | `computed` |  |
| `source_insert_ts` | `alert_time` | `computed` |  |
| `userid` | `user_id` | `computed` |  |
| `additionalindicators` | `ioc_value` | `computed` |  |
| `tim_main_indicator` | `ioc_value` | `computed` |  |
| `trendmicrovisiononexdrinvestigationstatus` | `investigation_status` | `computed` |  |
| `trendmicrovisiononexdrpriorityscore` | `score` | `computed` |  |

#### Pre-Alter XQL

```xql
| filter alert_provider = "SAE"

| alter j = _alert_data -> raw_json

| alter j_str = to_string(j)
| alter mitre_technique_id_raw =
    json_extract_scalar(j_str, "$.matched_rules[0].matched_filters[0].mitre_technique_ids[0]")
| alter j_str = null

| alter mitre_ids_str =
    if(
      mitre_technique_id_raw != null and mitre_technique_id_raw != "",
      if(mitre_technique_id_raw contains ".",
         arrayindex(regextract(mitre_technique_id_raw, "(T\\d+)\\."), 0),
         mitre_technique_id_raw),
      "-"
    )

| alter ta0043_reconnaissance       = arraycreate("T1590","T1591","T1592","T1593","T1594","T1595","T1596","T1597","T1598","T1599")
| alter ta0042_resource_development = arraycreate("T1583","T1584","T1585","T1586","T1587","T1650")
| alter ta0001_initial_access       = arraycreate("T1078","T1189","T1190","T1195","T1133","T1200","T1566","T1091")
| alter ta0002_execution            = arraycreate("T1059","T1106","T1047","T1203","T1129","T1559","T1204","T1072")
| alter ta0003_persistence          = arraycreate("T1547","T1543","T1136","T1505","T1053","T1078","T1546","T1574","T1037")
| alter ta0004_privilege_escalation = arraycreate("T1548","T1068","T1078","T1055","T1134","T1547","T1574")
| alter ta0005_defense_evasion      = arraycreate("T1027","T1070","T1218","T1140","T1562","T1036","T1055","T1497","T1620","T1553","T1222","T1202")
| alter ta0006_credential_access    = arraycreate("T1003","T1555","T1552","T1110","T1621","T1558","T1539","T1606")
| alter ta0007_discovery            = arraycreate("T1082","T1083","T1046","T1057","T1016","T1049","T1033","T1518","T1120","T1069","T1087","T1135")
| alter ta0008_lateral_movement     = arraycreate("T1021","T1210","T1091","T1072","T1080","T1550")
| alter ta0009_collection           = arraycreate("T1005","T1039","T1113","T1114","T1115","T1119","T1074","T1560")
| alter ta0011_command_and_control  = arraycreate("T1071","T1095","T1105","T1571","T1572","T1041","T1132","T1001","T1568","T1573")
| alter ta0010_exfiltration         = arraycreate("T1041","T1567","T1020","T1048","T1030")
| alter ta0040_impact               = arraycreate("T1485","T1486","T1490","T1499","T1561","T1529","T1496","T1495","T1491")

| alter mitre_tactic = if(ta0040_impact contains mitre_ids_str, "Impact")
| alter mitre_tactic = if(ta0010_exfiltration contains mitre_ids_str, "Exfiltration", mitre_tactic)
| alter mitre_tactic = if(ta0011_command_and_control contains mitre_ids_str, "Command and Control", mitre_tactic)
| alter mitre_tactic = if(ta0009_collection contains mitre_ids_str, "Collection", mitre_tactic)
| alter mitre_tactic = if(ta0008_lateral_movement contains mitre_ids_str, "Lateral Movement", mitre_tactic)
| alter mitre_tactic = if(ta0007_discovery contains mitre_ids_str, "Discovery", mitre_tactic)
| alter mitre_tactic = if(ta0006_credential_access contains mitre_ids_str, "Credential Access", mitre_tactic)
| alter mitre_tactic = if(ta0005_defense_evasion contains mitre_ids_str, "Defense Evasion", mitre_tactic)
| alter mitre_tactic = if(ta0004_privilege_escalation contains mitre_ids_str, "Privilege Escalation", mitre_tactic)
| alter mitre_tactic = if(ta0003_persistence contains mitre_ids_str, "Persistence", mitre_tactic)
| alter mitre_tactic = if(ta0002_execution contains mitre_ids_str, "Execution", mitre_tactic)
| alter mitre_tactic = if(ta0001_initial_access contains mitre_ids_str, "Initial Access", mitre_tactic)
| alter mitre_tactic = if(ta0042_resource_development contains mitre_ids_str, "Resource Development", mitre_tactic)
| alter mitre_tactic = if(ta0043_reconnaissance contains mitre_ids_str, "Reconnaissance", mitre_tactic)

| alter mitre_tactic_id = if(ta0040_impact contains mitre_ids_str, "TA0040")
| alter mitre_tactic_id = if(ta0010_exfiltration contains mitre_ids_str, "TA0010", mitre_tactic_id)
| alter mitre_tactic_id = if(ta0011_command_and_control contains mitre_ids_str, "TA0011", mitre_tactic_id)
| alter mitre_tactic_id = if(ta0009_collection contains mitre_ids_str, "TA0009", mitre_tactic_id)
| alter mitre_tactic_id = if(ta0008_lateral_movement contains mitre_ids_str, "TA0008", mitre_tactic_id)
| alter mitre_tactic_id = if(ta0007_discovery contains mitre_ids_str, "TA0007", mitre_tactic_id)
| alter mitre_tactic_id = if(ta0006_credential_access contains mitre_ids_str, "TA0006", mitre_tactic_id)
| alter mitre_tactic_id = if(ta0005_defense_evasion contains mitre_ids_str, "TA0005", mitre_tactic_id)
| alter mitre_tactic_id = if(ta0004_privilege_escalation contains mitre_ids_str, "TA0004", mitre_tactic_id)
| alter mitre_tactic_id = if(ta0003_persistence contains mitre_ids_str, "TA0003", mitre_tactic_id)
| alter mitre_tactic_id = if(ta0002_execution contains mitre_ids_str, "TA0002", mitre_tactic_id)
| alter mitre_tactic_id = if(ta0001_initial_access contains mitre_ids_str, "TA0001", mitre_tactic_id)
| alter mitre_tactic_id = if(ta0042_resource_development contains mitre_ids_str, "TA0042", mitre_tactic_id)
| alter mitre_tactic_id = if(ta0043_reconnaissance contains mitre_ids_str, "TA0043", mitre_tactic_id)

| alter
    id                   = j -> id,
    status               = j -> status,
    investigation_status = j -> investigation_status,
    investigation_result = j -> investigation_result,
    workbench_link       = j -> workbench_link,
    alert_provider       = j -> alert_provider,
    alert_name           = j -> model,
    score                = to_integer(j -> score),
    severity             = j -> severity,
    alert_time           = j -> created_date_time,
    alert_description    = j -> description,
    alert_source         = coalesce(j -> alert_provider, "Trend Micro Vision One"),
    indicators           = j -> indicators[]

| alter i_host = arrayindex(arrayfilter(indicators, json_extract_scalar("@element","$.type") = "host"), 0)
| alter
    v1_host_guid = json_extract_scalar(i_host, "$.value.guid"),
    v1_host_name = json_extract_scalar(i_host, "$.value.name"),
    local_ip     = replace(json_extract_scalar(i_host, "$.value.ips[0]"), "\\"", "")

| alter mac_address =
    coalesce(
      json_extract_scalar(i_host, "$.value.mac"),
      json_extract_scalar(i_host, "$.value.mac_address"),
      json_extract_scalar(i_host, "$.value.macs[0]"),
      json_extract_scalar(i_host, "$.value.macAddresses[0]")
    )

| alter i_user = arrayindex(arrayfilter(indicators, json_extract_scalar("@element","$.type") = "user_account"), 0)
| alter
    user_name = json_extract_scalar(i_user, "$.value"),
    user_id   = null

| alter i_cmd1 = arrayindex(arrayfilter(indicators, json_extract_scalar("@element","$.type") = "command_line"), 0)
| alter i_cmd2 = arrayindex(arrayfilter(indicators, json_extract_scalar("@element","$.field") = "processCmd"), 0)
| alter cmdline = coalesce(json_extract_scalar(i_cmd1, "$.value"), json_extract_scalar(i_cmd2, "$.value"))

| alter i_sha = arrayindex(arrayfilter(indicators, json_extract_scalar("@element","$.type") = "file_sha256"), 0)
| alter sha256 = json_extract_scalar(i_sha, "$.value")

| alter i_peer = arrayindex(arrayfilter(indicators, json_extract_scalar("@element","$.field") = "peerIp"), 0)
| alter remote_ip_str = json_extract_scalar(i_peer, "$.value")

| alter i_dom = arrayindex(arrayfilter(indicators, json_extract_scalar("@element","$.field") = "domain"), 0)
| alter domain = json_extract_scalar(i_dom, "$.value")

| alter i_pfp = arrayindex(arrayfilter(indicators, json_extract_scalar("@element","$.field") = "parentFilePath"), 0)
| alter parent_process_path = json_extract_scalar(i_pfp, "$.value")
| alter parent_process_name = replace(parent_process_path, "^.*[\\\\/]", "")

| alter i_reg = arrayindex(arrayfilter(indicators, json_extract_scalar("@element","$.field") = "objectRegistryData"), 0)
| alter reg_path = json_extract_scalar(i_reg, "$.value")
| alter filepath =
    coalesce(
      reg_path,
      arrayindex(regextract(cmdline, "^\\s*([^\\s]+)"), 0)
    )
| alter filename = replace(filepath, "^.*[\\\\/]", "")

| alter ioc_value = coalesce(sha256, null)

| alter vendor_name = "Trend Micro", product_name = "Vision One"

// ============================================================
// CANONICAL CORE NORMALIZATION
// Produces the 29 canonical core columns every vendor pack must
// expose. Column names match issue field names in alert_fields.
// ============================================================
| alter
        vendor                              = vendor_name,
        product                             = product_name,
        originalalertid                     = id,
        originalalertname                   = alert_name,
        originalalertsource                 = alert_source,
        externallink                        = workbench_link,
        alert_description                   = alert_description,
        severity                            = severity,
        mitretacticid                       = mitre_tactic_id,
        mitretacticname                     = mitre_tactic,
        mitretechniqueid                    = mitre_ids_str,
        mitretechniquename                  = mitre_ids_str,
        agent_hostname                      = v1_host_name,
        agent_id                            = v1_host_guid,
        agent_device_domain                 = domain,
        actor_effective_username            = user_name,
        actor_process_image_name            = filename,
        actor_process_image_path            = filepath,
        actor_process_image_sha256          = sha256,
        actor_process_command_line          = cmdline,
        actor_process_os_pid                = null,
        causality_actor_process_image_name  = parent_process_name,
        causality_actor_process_image_path  = parent_process_path,
        causality_actor_process_image_sha256 = null,
        action_file_name                    = filename,
        action_file_path                    = filepath,
        action_file_sha256                  = sha256,
        action_local_ip                     = local_ip,
        action_remote_ip                    = remote_ip_str
```
