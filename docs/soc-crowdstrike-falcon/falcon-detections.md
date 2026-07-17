# Falcon (crowdstrike-falcon) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/crowdstrike-falcon/falcon-detections.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/crowdstrike-falcon/falcon-detections.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `crowdstrike-falcon` |
| product | `Falcon` |
| data_source | `crowdstrike_falcon_event_raw` |
| category | `Endpoint` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `product` | `string` |  | declared |  |
| `severity` | `int` |  | declared |  |
| `severity_name` | `string` |  | declared |  |
| `incident_type` | `string` |  | declared |  |
| `description` | `string` |  | declared |  |
| `parent_process_id` | `string` |  | declared |  |
| `user_name` | `string` |  | declared |  |
| `user_id` | `string` |  | declared |  |
| `device` | `json` |  | declared |  |
| `parent_details` | `json` |  | declared |  |
| `grandparent_details` | `json` |  | declared |  |
| `cmdline` | `string` |  | declared |  |
| `filename` | `string` |  | declared |  |
| `filepath` | `string` |  | declared |  |
| `tactic` | `string` |  | declared |  |
| `technique` | `string` |  | declared |  |
| `rawJSON` | `json` |  | declared |  |
| `local_process_id` | `string` |  | declared |  |
| `sha256` | `string` |  | declared |  |
| `md5` | `string` |  | declared |  |
| `source_account_domain` | `string` |  | declared |  |
| `source_account_sam_account_name` | `string` |  | declared |  |
| `source_account_object_sid` | `string` |  | declared |  |
| `target_account_name` | `string` |  | declared |  |
| `host_names` | `string` |  | declared |  |
| `source_endpoint_host_name` | `string` |  | declared |  |
| `source_endpoint_address_ip4` | `string` |  | declared |  |
| `destination_hosts` | `string` |  | declared |  |
| `target_endpoint_host_name` | `string` |  | declared |  |
| `target_endpoint_sensor_id` | `string` |  | declared |  |
| `name` | `string` |  | declared |  |
| `display_name` | `string` |  | declared |  |
| `tactic_id` | `string` |  | declared |  |
| `technique_id` | `string` |  | declared |  |
| `type` | `string` |  | declared |  |
| `id` | `string` |  | declared |  |
| `cid` | `string` |  | declared |  |
| `source_account_upn` | `string` |  | declared |  |
| `source_account_name` | `string` |  | declared |  |
| `target_account_object_sid` | `string` |  | declared |  |
| `source_hosts` | `string` |  | declared |  |
| `source_endpoint_account_object_guid` | `string` |  | declared |  |
| `source_endpoint_ip_address` | `string` |  | declared |  |
| `source_endpoint_address_ip6` | `string` |  | declared |  |
| `location_country_code` | `string` |  | declared |  |
| `source_ip_asn_organization` | `string` |  | declared |  |
| `sso_application_identifier` | `string` |  | declared |  |
| `sso_application_uri` | `string` |  | declared |  |
| `user_names` | `string` |  | declared |  |
| `country` | `string` |  | declared |  |
| `asn` | `string` |  | declared |  |
| `asn_name` | `string` |  | declared |  |
| `category` | `string` |  | declared |  |
| `mitre_attack` | `string` |  | declared |  |
| `event_summary` | `string` |  | declared |  |

## Modeling Rule — SOC CrowdStrike Falcon Modeling Rule

| Field | Value |
|---|---|
| modeling_rule_id | `SOC_CrowdStrikeFalcon_ModelingRule` |
| modeling_rule_name | `SOC CrowdStrike Falcon Modeling Rule` |
| directory_name | `SOCCrowdStrikeFalconModelingRules` |
| fromversion | `8.3.1` |

### Contributes (Artifacts.*)

Fields populated for downstream lifecycle Artifacts schemas:

- `User`
- `User.UPN`
- `User.SAM`
- `User.SID`
- `User.Domain`
- `Target.User`
- `Target.User.SID`
- `Endpoint.Hostname`
- `Endpoint.DeviceID`
- `Endpoint.OS`
- `Endpoint.IPv4`
- `Target.Hostname`
- `Process.Name`
- `Process.Path`
- `Process.SHA256`
- `Process.MD5`
- `Process.CommandLine`
- `Process.PID`
- `Network.IP`
- `Network.Location`
- `Network.ASN`
- `Application`
- `Alert.Severity`
- `Alert.Category`
- `Alert.Description`
- `Alert.MITRE`
- `Event.Type`
- `Event.Description`
- `Event.ID`
- `Observer.Vendor`
- `Observer.Product`

## Correlation Rules

### SOC CrowdStrike Falcon - Endpoint All Alerts

| Field | Value |
|---|---|
| global_rule_id | `SOC CrowdStrike Falcon - Endpoint All Alerts` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Creates a single XSIAM alert for each CrowdStrike Falcon Endpoint Detection event. Consolidates 15 per-tactic rules from v1.0.14 into one rule using MITRE tactic as the User Defined alert category. Backwards compatible with alert field mappings from all 1.0.14 per-tactic rules.

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| action | `ALERTS` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| execution_mode | `SCHEDULED` |
| is_enabled | `✓` |
| mapping_strategy | `CUSTOM` |
| severity | `User Defined` |
| drilldown_query_timeframe | `ALERT` |
| user_defined_category | `tactic` |
| user_defined_severity | `severity_name` |

#### Suppression

| Field | Value |
|---|---|
| enabled | `✓` |
| duration | `1 hours` |
| fields | `composite_id` |

#### Alert Fields

Issue-field assignments emitted by the correlation rule. The Description column captures intent — when present, this is what downstream playbooks rely on the field meaning.

| Issue Field | Source | Bucket | Description |
|---|---|---|---|
| `mac` | `mac_address` |  |  |
| `domain` | `agent_device_domain` |  |  |
| `userid` | `user_principal` |  |  |
| `vendor` | `vendor` |  |  |
| `agentid` | `agent_id` |  |  |
| `localip` | `action_local_ip` |  |  |
| `product` | `product` |  |  |
| `usersid` | `idr_sid` |  |  |
| `agent_id` | `agent_id` |  |  |
| `deviceou` | `device_ou_arr` |  |  |
| `filehash` | `sha256` |  |  |
| `filename` | `action_file_name` |  |  |
| `filepath` | `action_file_path` |  |  |
| `hostname` | `agent_hostname` |  |  |
| `remoteip` | `action_remote_ip` |  |  |
| `scenario` | `scenario` |  |  |
| `severity` | `severity` |  |  |
| `sourceid` | `aggregate_id` |  |  |
| `username` | `actor_effective_username` |  |  |
| `cgosha256` | `causality_actor_process_image_sha256` |  |  |
| `objective` | `objective` |  |  |
| `processid` | `grandparent_local_process_id` |  |  |
| `_device_id` | `device_id` |  |  |
| `filesha256` | `action_file_sha256` |  |  |
| `processmd5` | `md5` |  |  |
| `alertaction` | `pattern_disposition_description` |  |  |
| `detectionid` | `template_instance_id` |  |  |
| `eventaction` | `ioc_source` |  |  |
| `initiatedby` | `actor_process_image_name` |  |  |
| `dns_requests` | `dns_requests` |  |  |
| `dnsqueryname` | `dns_queries` |  |  |
| `externallink` | `externallink` |  |  |
| `initiatorcmd` | `actor_process_command_line` |  |  |
| `initiatorpid` | `actor_process_os_pid` |  |  |
| `employeeemail` | `idr_email` |  |  |
| `files_written` | `files_written` |  |  |
| `initiatorpath` | `actor_process_image_path` |  |  |
| `mitretacticid` | `mitretacticid` |  |  |
| `agent_hostname` | `agent_hostname` |  |  |
| `dns_query_name` | `dns_queries` |  |  |
| `hostmacaddress` | `mac_address` |  |  |
| `originalrawlog` | `originalrawlog` |  |  |
| `prenatsourceip` | `local_ip` |  |  |
| `user_principal` | `user_principal` |  |  |
| `action_local_ip` | `action_local_ip` |  |  |
| `initiatorsha256` | `actor_process_image_sha256` |  |  |
| `mitretacticname` | `mitretacticname` |  |  |
| `originalalertid` | `originalalertid` |  |  |
| `parentprocessid` | `parent_local_process_id` |  |  |
| `action_file_name` | `action_file_name` |  |  |
| `action_file_path` | `action_file_path` |  |  |
| `action_remote_ip` | `action_remote_ip` |  |  |
| `externalseverity` | `severity_int_raw` |  |  |
| `mitretechniqueid` | `mitretechniqueid` |  |  |
| `network_accesses` | `network_accesses` |  |  |
| `parentprocesscmd` | `parent_process_cmd` |  |  |
| `parentprocessids` | `parent_local_process_id` |  |  |
| `alert_description` | `alert_description` |  |  |
| `deviceexternalips` | `external_ip` |  |  |
| `originalalertname` | `originalalertname` |  |  |
| `parentprocessname` | `parent_process_name` |  |  |
| `parentprocesspath` | `parent_process_path` |  |  |
| `action_file_sha256` | `action_file_sha256` |  |  |
| `external_pivot_url` | `falcon_host_link` |  |  |
| `externalconfidence` | `confidence` |  |  |
| `mitretechniquename` | `mitretechniquename` |  |  |
| `tim_main_indicator` | `ioc_value` |  |  |
| `agent_device_domain` | `agent_device_domain` |  |  |
| `contactemailaddress` | `idr_email` |  |  |
| `employeedisplayname` | `idr_display_name` |  |  |
| `originalalertsource` | `originalalertsource` |  |  |
| `originaldescription` | `alert_description` |  |  |
| `parentprocesssha256` | `parent_process_sha256` |  |  |
| `processcreationtime` | `process_start_time` |  |  |
| `actor_process_os_pid` | `actor_process_os_pid` |  |  |
| `additionalindicators` | `ioc_value` |  |  |
| `grandparentprocessid` | `grandparent_local_process_id` |  |  |
| `postnatdestinationip` | `remote_ips` |  |  |
| `grandparentprocesscmd` | `grandparent_process_cmd` |  |  |
| `grandparentprocessname` | `grandparent_process_name` |  |  |
| `grandparentprocesspath` | `grandparent_process_path` |  |  |
| `actor_effective_username` | `actor_effective_username` |  |  |
| `actor_process_image_name` | `actor_process_image_name` |  |  |
| `actor_process_image_path` | `actor_process_image_path` |  |  |
| `grandparentprocesssha256` | `grandparent_process_sha256` |  |  |
| `actor_process_command_line` | `actor_process_command_line` |  |  |
| `actor_process_image_sha256` | `actor_process_image_sha256` |  |  |
| `action_process_image_sha256` | `sha256` |  |  |
| `pattern_disposition_details` | `pattern_disposition_details` |  |  |
| `xdmsourceprocesscausalityid` | `aggregate_id` |  |  |
| `causality_actor_causality_id` | `aggregate_id` |  |  |
| `causality_actor_process_image_name` | `causality_actor_process_image_name` |  |  |
| `causality_actor_process_image_path` | `causality_actor_process_image_path` |  |  |
| `causality_actor_process_command_line` | `cgo_cmd` |  |  |
| `causality_actor_process_image_sha256` | `causality_actor_process_image_sha256` |  |  |

#### Pre-Alter XQL

```xql
| alter vendor_name = "CrowdStrike", product_name = "Falcon"

| filter product = "epp"

| alter originalrawlog = to_json_string(rawJSON)

| alter severity_int_raw = severity

| alter
        tactic                 = if(tactic = "Malware", "Execution", tactic),
        mitre_tactic           = if(tactic = "Malware", "Execution", tactic),
        mitre_tactic_id        = tactic_id,
        mitre_technique        = technique,
        mitre_technique_id     = technique_id

| alter mitre_ids_str = if(
    technique_id != null and technique != null,
    concat(technique_id, " - ", technique),
    coalesce(technique_id, technique)
  )

| alter
        hostname                     = device->hostname,
        domain                       = device->machine_domain,
        local_ip                     = device->local_ip,
        external_ip                  = device->external_ip,
        mac_address                  = device->mac_address,
        device_id                    = device->device_id,
        device_ou                    = device->ou[],
        parent_process_name          = parent_details->filename,
        parent_process_cmd           = parent_details->cmdline,
        parent_process_path          = parent_details->filepath,
        parent_process_sha256        = parent_details->sha256,
        parent_local_process_id      = parent_details->local_process_id,
        grandparent_process_name     = grandparent_details->filename,
        grandparent_process_cmd      = grandparent_details->cmdline,
        grandparent_process_path     = grandparent_details->filepath,
        grandparent_process_sha256   = grandparent_details->sha256,
        grandparent_local_process_id = grandparent_details->local_process_id

| alter device_ou_arr = arraymap(device_ou, replace("@element", "\"", ""))

| alter cgo_name = if(lowercase(grandparent_process_name) not in ("wininit.exe", "userinit.exe"),
                      grandparent_process_name,
                      coalesce(parent_process_name, filename)),
        cgo_path = if(lowercase(grandparent_process_name) not in ("wininit.exe", "userinit.exe"),
                      grandparent_process_path,
                      coalesce(parent_process_path, filepath)),
        cgo_cmd  = if(lowercase(grandparent_process_name) not in ("wininit.exe", "userinit.exe"),
                      grandparent_process_cmd,
                      coalesce(parent_process_cmd, cmdline))

| alter dns_queries = dns_requests
| alter remote_ips  = network_accesses

| alter alert_name = concat(
    "[Endpoint] ",
    coalesce(user_name, hostname, "Unknown"),
    " - ",
    coalesce(tactic, "Detection"),
    ": ",
    coalesce(technique, name)
  )

| alter alert_description = concat(
    coalesce(description, name),
    " | Host: ",  coalesce(hostname, "Unknown"),
    " | User: ",  coalesce(user_name, "Unknown"),
    " | Severity: ", coalesce(severity_name, "Unknown")
  )

| alter
        vendor                              = vendor_name,
        product                             = product_name,
        originalalertid                     = composite_id,
        originalalertname                   = alert_name,
        originalalertsource                 = "CrowdStrike Falcon",
        externallink                        = falcon_host_link,
        alert_description                   = alert_description,
        severity                            = severity_name,
        mitretacticid                       = mitre_tactic_id,
        mitretacticname                     = mitre_tactic,
        mitretechniqueid                    = mitre_technique_id,
        mitretechniquename                  = mitre_technique,
        agent_hostname                      = hostname,
        agent_id                            = agent_id,
        agent_device_domain                 = domain,
        actor_effective_username            = user_name,
        actor_process_image_name            = filename,
        actor_process_image_path            = filepath,
        actor_process_image_sha256          = sha256,
        actor_process_command_line          = cmdline,
        actor_process_os_pid                = local_process_id,
        causality_actor_process_image_name  = cgo_name,
        causality_actor_process_image_path  = cgo_path,
        causality_actor_process_image_sha256 = grandparent_process_sha256,
        action_file_name                    = filename,
        action_file_path                    = filepath,
        action_file_sha256                  = sha256,
        action_local_ip                     = local_ip,
        action_remote_ip                    = remote_ips
| fields
    device_id, local_ip, user_name, user_principal, cmdline, sha256, domain, hostname, agent_id, pattern_disposition_description, pattern_disposition_details, cgo_cmd, cgo_name, cgo_path, template_instance_id, external_ip, falcon_host_link, mac_address, mitre_tactic_id, mitre_tactic, mitre_technique_id, mitre_technique, mitre_ids_str, tactic_id, tactic, technique_id, technique, objective, composite_id, parent_process_cmd, parent_process_name, parent_local_process_id, parent_process_path, parent_process_sha256, grandparent_process_name, grandparent_process_cmd, grandparent_process_path, grandparent_process_sha256, grandparent_local_process_id, device_ou_arr, process_start_time, local_process_id, md5, scenario, severity_name, aggregate_id, indicator_id, alert_name, alert_description, network_accesses, dns_requests, files_written, originalrawlog, *
```
