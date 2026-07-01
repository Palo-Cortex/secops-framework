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
| `parent_process_id` | `string` |  | declared_unused |  |
| `user_name` | `string` |  | declared |  |
| `device` | `json` |  | declared | hostname, machine_domain, os_version, local_ip, groups, mac_address, device_i... |
| `parent_details` | `json` |  | declared | filename, filepath, cmdline, sha256, local_process_id |
| `local_process_id` | `string` |  | used_undeclared |  |
| `agent_id` | `string` |  | inferred_from_correlation |  |
| `user_principal` | `string` |  | inferred_from_correlation |  |
| `user_id` | `string` |  | inferred_from_correlation |  |
| `cmdline` | `string` |  | inferred_from_correlation |  |
| `filename` | `string` |  | inferred_from_correlation |  |
| `filepath` | `string` |  | inferred_from_correlation |  |
| `sha256` | `string` |  | inferred_from_correlation |  |
| `md5` | `string` |  | inferred_from_correlation |  |
| `process_start_time` | `string` |  | inferred_from_correlation |  |
| `aggregate_id` | `string` |  | inferred_from_correlation |  |
| `composite_id` | `string` |  | inferred_from_correlation |  |
| `template_instance_id` | `string` |  | inferred_from_correlation |  |
| `pattern_disposition_description` | `string` |  | inferred_from_correlation |  |
| `pattern_disposition_details` | `json` |  | inferred_from_correlation |  |
| `falcon_host_link` | `string` |  | inferred_from_correlation |  |
| `confidence` | `int` |  | inferred_from_correlation |  |
| `scenario` | `string` |  | inferred_from_correlation |  |
| `objective` | `string` |  | inferred_from_correlation |  |
| `ioc_value` | `string` |  | inferred_from_correlation |  |
| `ioc_source` | `string` |  | inferred_from_correlation |  |
| `dns_requests` | `json` | ✓ | inferred_from_correlation |  |
| `network_accesses` | `json` | ✓ | inferred_from_correlation |  |
| `files_written` | `json` | ✓ | inferred_from_correlation |  |

## Modeling Rule — SOC CrowdStrike Falcon Modeling Rule

| Field | Value |
|---|---|
| modeling_rule_id | `SOC_CrowdStrikeFalcon_ModelingRule` |
| modeling_rule_name | `SOC CrowdStrike Falcon Modeling Rule` |
| directory_name | `SOCCrowdStrikeFalconModelingRules` |
| fromversion | `8.3.1` |

### Field Mappings

What each XDM field is, where it sources from, what issue field it surfaces on, and why the mapping is shaped the way it is.

| XDM Path | Expression | Sources | Issue Field | Description |
|---|---|---|---|---|
| `xdm.alert.severity` | `concat(to_string(severity), " - ", severity_name)` | `severity, severity_name` | `severity` | Composite — vendor int + name pair joined for analyst readability. |
| `xdm.event.original_event_type` | `incident_type` | `incident_type` | `original_event_type` |  |
| `xdm.event.type` | `incident_type` | `incident_type` | `event_type` | Same source as original_event_type — duplicate mapping, intentional. |
| `xdm.event.description` | `description` | `description` | `alert_description` |  |
| `xdm.source.host.hostname` | `device->hostname` | `device` | `hostname` |  |
| `xdm.source.host.fqdn` | `device->machine_domain` | `device` | `hostfqdn` | machine_domain is being mapped to fqdn here AND to user.domain below. In Falcon's schema it's the AD domain — fqdn would be hostname + machine_domain concatenated. Flag for review. |
| `xdm.source.host.os_family` | `device->os_version` | `device` | `hostos` | os_version is the OS version string (e.g., "Windows 10 Pro"); os_family should be the family enum. Should likely use XDM_CONST.OS_FAMILY_* via if() chain. |
| `xdm.source.ipv4` | `device->local_ip` | `device` | `hostip` |  |
| `xdm.source.user.username` | `user_name` | `user_name` | `username` |  |
| `xdm.source.user.domain` | `device->machine_domain` | `device` | `userdomain` |  |
| `xdm.source.user.groups` | `device->groups[]` | `device` | `usergroups` |  |
| `xdm.source.process.pid` | `to_integer(local_process_id)` | `local_process_id` | `initiatorpid` |  |
| `xdm.source.process.name` | `parent_details->filename` | `parent_details` | `initiatedby` | Currently mapping PARENT process name into source.process slot. |
| `xdm.source.process.executable.path` | `parent_details->filepath` | `parent_details` | `initiatorpath` |  |
| `xdm.source.process.executable.sha256` | `parent_details->sha256` | `parent_details` | `initiatorsha256` |  |
| `xdm.source.process.command_line` | `parent_details->cmdline` | `parent_details` | `initiatorcmd` |  |

### Contributes (Artifacts.*)

Fields populated for downstream lifecycle Artifacts schemas:

- `Endpoint.Hostname`
- `Endpoint.FQDN`
- `Endpoint.OSFamily`
- `Network.IP`
- `User`
- `Process.PID`
- `Process.Name`
- `Process.Path`
- `Process.SHA256`
- `Process.CommandLine`

## Correlation Rules

### SOC CrowdStrike Falcon - Endpoint All Alerts (non-CIE)

| Field | Value |
|---|---|
| global_rule_id | `SOC CrowdStrike Falcon - Endpoint All Alerts (non-CIE)` |
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
| execution_mode | `REAL_TIME` |
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

| alter ids_join_key = lowercase(coalesce(user_id, ""))

| alter actor_effective_username = lowercase(coalesce(if(user_principal contains "@", user_principal, null), if(user_name contains "@", user_name, null), user_name))
| alter idr_email = if(user_principal contains "@", lowercase(user_principal), if(user_name contains "@", lowercase(user_name), null)), idr_upn = user_principal, idr_sid = null, idr_netbios = null, idr_display_name = null
| alter email = idr_email
```

### CrowdStrike Falcon - IDP All Alerts (non-CIE)

| Field | Value |
|---|---|
| global_rule_id | `CrowdStrike Falcon - IDP All Alerts (non-CIE)` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Creates an XSIAM alert for each CrowdStrike Identity Protection (IDP) alerts

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| action | `ALERTS` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| execution_mode | `REAL_TIME` |
| is_enabled | `✓` |
| mapping_strategy | `CUSTOM` |
| severity | `User Defined` |
| drilldown_query_timeframe | `ALERT` |
| user_defined_category | `tactic` |
| user_defined_severity | `severity` |

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
| `localip` | `action_local_ip` |  |  |
| `product` | `product` |  |  |
| `rawjson` | `rawjson` |  |  |
| `usersid` | `idr_sid` |  |  |
| `agent_id` | `agent_id` |  |  |
| `filehash` | `sha256` |  |  |
| `hostname` | `agent_hostname` |  |  |
| `remoteip` | `action_remote_ip` |  |  |
| `scenario` | `scenario` |  |  |
| `severity` | `severity_name` |  |  |
| `sourceid` | `aggregate_id` |  |  |
| `username` | `actor_effective_username` |  |  |
| `objective` | `objective` |  |  |
| `_device_id` | `device_id` |  |  |
| `filesha256` | `sha256` |  |  |
| `processmd5` | `md5` |  |  |
| `alertaction` | `pattern_disposition` |  |  |
| `detectionid` | `template_instance_id` |  |  |
| `eventaction` | `idp_policy_rule_action` |  |  |
| `initiatedby` | `actor_process_image_name` |  |  |
| `dnsqueryname` | `dns_queries` |  |  |
| `dst_agent_id` | `dst_agent_id_v` |  |  |
| `dst_hostname` | `dst_hostname_v` |  |  |
| `dst_username` | `dst_user_v` |  |  |
| `externallink` | `falcon_host_link` |  |  |
| `initiatorcmd` | `actor_process_command_line` |  |  |
| `employeeemail` | `idr_email` |  |  |
| `initiatorpath` | `actor_process_image_path` |  |  |
| `mitretacticid` | `tactic_id` |  |  |
| `agent_hostname` | `agent_hostname` |  |  |
| `dns_query_name` | `dns_queries` |  |  |
| `locationregion` | `location_country_code` |  |  |
| `originalrawlog` | `originalrawlog` |  |  |
| `samaccountname` | `src_account_name` |  |  |
| `sourceInstance` | `mirror_instance` |  |  |
| `user_principal` | `user_principal` |  |  |
| `action_local_ip` | `action_local_ip` |  |  |
| `initiatorsha256` | `actor_process_image_sha256` |  |  |
| `mitretacticname` | `tactic` |  |  |
| `originalalertid` | `composite_id` |  |  |
| `action_file_name` | `filename` |  |  |
| `action_file_path` | `filepath` |  |  |
| `action_remote_ip` | `action_remote_ip` |  |  |
| `destinationemail` | `dst_account_name` |  |  |
| `externalseverity` | `severity` |  |  |
| `mitretechniqueid` | `technique_id` |  |  |
| `originalalertname` | `originalalertname` |  |  |
| `action_file_sha256` | `sha256` |  |  |
| `action_local_ip_v6` | `source_endpoint_address_ip6` |  |  |
| `external_pivot_url` | `falcon_host_link` |  |  |
| `externalconfidence` | `confidence` |  |  |
| `mitretechniquename` | `technique` |  |  |
| `tim_main_indicator` | `ioc_value` |  |  |
| `agent_device_domain` | `agent_device_domain` |  |  |
| `contactemailaddress` | `idr_email` |  |  |
| `employeedisplayname` | `idr_display_name` |  |  |
| `originalalertsource` | `originalalertsource` |  |  |
| `originaldescription` | `alert_description` |  |  |
| `processcreationtime` | `process_start_time` |  |  |
| `actor_process_os_pid` | `local_process_id` |  |  |
| `additionalindicators` | `ioc_value` |  |  |
| `actor_effective_username` | `actor_effective_username` |  |  |
| `actor_process_image_name` | `filename` |  |  |
| `actor_process_image_path` | `filepath` |  |  |
| `actor_process_command_line` | `cmdline` |  |  |
| `actor_process_image_sha256` | `sha256` |  |  |
| `xdmsourceprocesscausalityid` | `causality_id` |  |  |
| `causality_actor_causality_id` | `causality_id` |  |  |
| `causality_actor_process_image_name` | `causality_actor_process_image_name` |  |  |
| `causality_actor_process_image_path` | `causality_actor_process_image_path` |  |  |
| `causality_actor_process_command_line` | `cgo_cmd` |  |  |
| `causality_actor_process_image_sha256` | `causality_actor_process_image_sha256` |  |  |

#### Pre-Alter XQL

```xql
| alter vendor_name = "CrowdStrike", product_name = "Falcon Identity Protection"

| filter product = "idp"

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

| alter src_account_name = source_account_name,
        src_account_upn  = source_account_upn,
        src_account_sid  = source_account_object_sid,
        src_host         = source_endpoint_host_name,
        src_ip           = source_endpoint_address_ip4,
        src_sensor_id    = source_endpoint_sensor_id,
        dst_account_name = target_account_name,
        dst_account_sid  = target_endpoint_account_object_sid,
        dst_host         = target_endpoint_host_name,
        dst_sensor_id    = target_endpoint_sensor_id,
        idp_logon_domain = logon_domain

| alter dst_ip = arrayindex(regextract(to_json_string(network_accesses), "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"), 0)

| alter user_name      = coalesce(user_name, src_account_name),
        user_principal = coalesce(user_principal, src_account_upn),
        hostname       = coalesce(hostname, src_host),
        domain         = coalesce(domain, idp_logon_domain),
        local_ip       = coalesce(local_ip, src_ip),
        agent_id       = coalesce(agent_id, src_sensor_id)

| alter hostname = arrayindex(split(hostname, "."), 0)

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
| alter remote_ips  = coalesce(dst_ip, network_accesses)

| alter alert_name = concat(
    "[Identity] ",
    coalesce(user_name, hostname, "Unknown"),
    " - ",
    coalesce(tactic, "Detection"),
    ": ",
    coalesce(technique, name)
  )

| alter idp_context = concat(
    "Source: ", coalesce(src_account_name, "Unknown"),
    " @ ", coalesce(src_host, "Unknown"), " (", coalesce(src_ip, "n/a"), ")",
    " -> Target: ", coalesce(dst_account_name, "n/a"),
    " @ ", coalesce(dst_host, "n/a"),
    " | App: ", "n/a",
    " | Policy: ", coalesce(idp_policy_rule_name, "n/a"),
    " (", coalesce(idp_policy_rule_action, "no action"), ")",
    " | MFA: ", coalesce(idp_policy_mfa_factor_type, idp_policy_mfa_provider, "n/a")
  )

| alter alert_description = concat(
    coalesce(description, name),
    " | Host: ",  coalesce(hostname, "Unknown"),
    " | User: ",  coalesce(user_name, "Unknown"),
    " | Severity: ", coalesce(severity_name, "Unknown"),
    " | ", idp_context
  )

| alter
        vendor                              = vendor_name,
        product                             = product_name,
        originalalertid                     = composite_id,
        originalalertname                   = alert_name,
        originalalertsource                 = "CrowdStrike Falcon Identity Protection",
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
        action_remote_ip                    = remote_ips,
        causality_id                        = aggregate_id,
        dst_agent_id_v                      = dst_sensor_id,
        dst_hostname_v                      = dst_host,
        dst_user_v                          = dst_account_name
| fields
    device_id, local_ip, user_name, user_principal, cmdline, sha256, domain, hostname, agent_id, pattern_disposition_description, pattern_disposition_details, cgo_cmd, cgo_name, cgo_path, template_instance_id, external_ip, falcon_host_link, mac_address, mitre_tactic_id, mitre_tactic, mitre_technique_id, mitre_technique, mitre_ids_str, tactic_id, tactic, technique_id, technique, objective, composite_id, parent_process_cmd, parent_process_name, parent_local_process_id, parent_process_path, parent_process_sha256, grandparent_process_name, grandparent_process_cmd, grandparent_process_path, grandparent_process_sha256, grandparent_local_process_id, device_ou_arr, process_start_time, local_process_id, md5, scenario, severity_name, aggregate_id, indicator_id, alert_name, alert_description, network_accesses, dns_requests, files_written, originalrawlog, src_account_name, src_account_upn, src_account_sid, src_host, src_ip, src_sensor_id, dst_account_name, dst_account_sid, dst_host, dst_ip, dst_sensor_id, idp_logon_domain, idp_context, idp_policy_rule_name, idp_policy_rule_action, idp_policy_rule_trigger, idp_policy_mfa_provider, idp_policy_mfa_factor_type, privileges, added_privileges, ldap_search_query_attack, pattern_disposition, causality_id, dst_agent_id_v, dst_hostname_v, dst_user_v, *

| alter socfw_event_time = _time,
        socfw_insert_time = _insert_time

| alter ids_join_key = lowercase(coalesce(source_account_object_sid, src_account_sid))

| alter actor_effective_username = lowercase(coalesce(source_account_upn, if(user_principal contains "@", user_principal, null), source_account_name, user_name))
| alter idr_email = coalesce(lowercase(source_account_upn), if(user_principal contains "@", lowercase(user_principal), null)), idr_upn = coalesce(source_account_upn, user_principal), idr_sid = source_account_object_sid, idr_netbios = null, idr_display_name = null
| alter email = idr_email
```

### CrowdStrike Falcon - Shield SaaS All Alerts (non-CIE)

| Field | Value |
|---|---|
| global_rule_id | `CrowdStrike Falcon - Shield SaaS All Alerts (non-CIE)` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Creates an XSIAM alert for each CrowdStrike Falcon Shield SaaS Alert

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| action | `ALERTS` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| execution_mode | `REAL_TIME` |
| is_enabled | `✓` |
| mapping_strategy | `CUSTOM` |
| severity | `User Defined` |
| drilldown_query_timeframe | `ALERT` |
| user_defined_category | `category` |
| user_defined_severity | `severity_name` |

#### Suppression

| Field | Value |
|---|---|
| enabled | `✓` |
| duration | `2 hours` |
| fields | `composite_id` |

#### Alert Fields

Issue-field assignments emitted by the correlation rule. The Description column captures intent — when present, this is what downstream playbooks rely on the field meaning.

| Issue Field | Source | Bucket | Description |
|---|---|---|---|
| `userid` | `user_principal` |  |  |
| `rawjson` | `rawjson` |  |  |
| `usersid` | `idr_sid` |  |  |
| `rawevent` | `rawjson` |  |  |
| `severity` | `severity_name` |  |  |
| `username` | `actor_effective_username` |  |  |
| `externallink` | `falcon_host_link` |  |  |
| `employeeemail` | `idr_email` |  |  |
| `mitretacticid` | `mitre_tactic_id` |  |  |
| `samaccountname` | `crowdstrike_original_user_name` |  |  |
| `sourceInstance` | `mirror_instance` |  |  |
| `action_local_ip` | `local_ip` |  |  |
| `mitretacticname` | `mitre_tactic` |  |  |
| `originalalertid` | `composite_id` |  |  |
| `externalseverity` | `severity` |  |  |
| `mitretechniqueid` | `mitre_ids_str` |  |  |
| `external_pivot_url` | `falcon_host_link` |  |  |
| `mitretechniquename` | `mitre_ids_str` |  |  |
| `contactemailaddress` | `idr_email` |  |  |
| `employeedisplayname` | `idr_display_name` |  |  |
| `originalalertsource` | `correlation_rule_id` |  |  |
| `actor_effective_username` | `actor_effective_username` |  |  |
| `causality_actor_causality_id` | `cid` |  |  |

#### Pre-Alter XQL

```xql
| filter product = "saas-security"
| alter vendor_name = "CrowdStrike", product_name = "Falcon SaaS"
| filter display_name not in ("Anonymized IP")

| alter alert_name = display_name

| alter mitre_json          = json_extract_array(to_json_string(mitre_attack), "$")
| alter mitre_tech_ids      = arraymap(mitre_json, json_extract_scalar("@element", "$.technique_id"))
| alter mitre_tech_names    = arraymap(mitre_json, json_extract_scalar("@element", "$.technique"))
| alter mitre_tactic_ids    = arraymap(mitre_json, json_extract_scalar("@element", "$.tactic_id"))
| alter mitre_tactic_names  = arraymap(mitre_json, json_extract_scalar("@element", "$.tactic"))
| alter mitre_ids_str       = arraystring(arraydistinct(mitre_tech_ids), ",")
| alter mitre_tech_name_str = arraystring(arraydistinct(mitre_tech_names), ",")
| alter mitre_tactic_id     = arrayindex(arraydistinct(mitre_tactic_ids), 0)
| alter mitre_tactic        = arrayindex(arraydistinct(mitre_tactic_names), 0)

| alter tmp_user_names  = json_extract_array(to_json_string(user_names), "$")
| alter tmp_user_arr0   = arrayindex(tmp_user_names, 0)
| alter tmp_user_quoted = arrayindex(regextract(coalesce(event_summary, description, ""), "(?i)\\buser\\s+\"([^\"]+)\""), 0)
| alter tmp_user_email  = arrayindex(regextract(coalesce(event_summary, description, ""), "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"), 0)
| alter tmp_user_token  = arrayindex(regextract(coalesce(event_summary, description, ""), "(?i)\\buser\\s+([A-Za-z0-9._%+@-]+)"), 0)
| alter user_name = coalesce(user_name, tmp_user_arr0, tmp_user_quoted, tmp_user_email, tmp_user_token)
| alter crowdstrike_original_user_name = user_name
| alter actor_effective_username = user_name

| alter local_ip = arrayindex(regextract(coalesce(event_summary, description, ""), "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"), 0)

| alter idu_join_key = lowercase(if(user_name contains "@", user_name, null))

| alter actor_effective_username = lowercase(coalesce(if(user_name contains "@", user_name, null), user_name))
| alter idr_email = if(user_name contains "@", lowercase(user_name), null), idr_upn = user_name, idr_sid = null, idr_netbios = null, idr_display_name = null
| alter email = idr_email
```
