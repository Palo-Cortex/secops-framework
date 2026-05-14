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

### SOC CrowdStrike Falcon - Endpoint Alerts

| Field | Value |
|---|---|
| global_rule_id | `SOC CrowdStrike Falcon - Endpoint Alerts` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Creates a single XSIAM alert for each CrowdStrike Falcon Endpoint Detection event. Consolidates 15 per-tactic rules from v1.0.14 into one rule using MITRE tactic as the User Defined alert category. Backwards compatible with alert field mappings from all 1.0.14 per-tactic rules.

**Tags:** `SOCFramework`, `Passthrough`, `Endpoint`, `CrowdStrike`

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
| user_defined_severity | `severity_name` |
| is_enabled | `✓` |
| drilldown_query_timeframe | `ALERT` |
| severity | `User Defined` |

#### Suppression

| Field | Value |
|---|---|
| enabled | `✓` |
| duration | `1 hours` |
| fields | `composite_id` |

composite_id is CrowdStrike Falcon's unique identifier per detection event.

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
| `_device_id` | `device_id` | `computed` |  |
| `mac` | `mac_address` | `computed` |  |
| `prenatsourceip` | `local_ip` | `computed` |  |
| `postnatdestinationip` | `remote_ips` | `computed` |  |
| `deviceexternalips` | `external_ip` | `computed` |  |
| `deviceou` | `device_ou_arr` | `computed` |  |
| `userid` | `user_principal` | `raw` |  |
| `user_principal` | `user_principal` | `raw` |  |
| `usersid` | `user_id` | `raw` |  |
| `action_process_image_sha256` | `sha256` | `raw` |  |
| `filehash` | `sha256` | `raw` |  |
| `processmd5` | `md5` | `raw` |  |
| `processcreationtime` | `process_start_time` | `raw` |  |
| `parentprocessname` | `parent_process_name` | `computed` |  |
| `parentprocesscmd` | `parent_process_cmd` | `computed` |  |
| `parentprocesspath` | `parent_process_path` | `computed` |  |
| `parentprocesssha256` | `parent_process_sha256` | `computed` |  |
| `parentprocessid` | `parent_local_process_id` | `computed` |  |
| `parentprocessids` | `parent_local_process_id` | `computed` |  |
| `grandparentprocessname` | `grandparent_process_name` | `computed` |  |
| `grandparentprocesscmd` | `grandparent_process_cmd` | `computed` |  |
| `grandparentprocesspath` | `grandparent_process_path` | `computed` |  |
| `grandparentprocesssha256` | `grandparent_process_sha256` | `computed` |  |
| `grandparentprocessid` | `grandparent_local_process_id` | `computed` |  |
| `processid` | `grandparent_local_process_id` | `computed` |  |
| `causality_actor_causality_id` | `aggregate_id` | `raw` |  |
| `causality_actor_process_command_line` | `cgo_cmd` | `computed` |  |
| `sourceid` | `aggregate_id` | `raw` |  |
| `dns_query_name` | `dns_queries` | `computed` |  |
| `dns_requests` | `dns_requests` | `raw` |  |
| `network_accesses` | `network_accesses` | `raw` |  |
| `files_written` | `files_written` | `raw` |  |
| `additionalindicators` | `ioc_value` | `raw` |  |
| `tim_main_indicator` | `ioc_value` | `raw` |  |
| `eventaction` | `ioc_source` | `raw` |  |
| `originaldescription` | `alert_description` | `computed` |  |
| `detectionid` | `template_instance_id` | `raw` |  |
| `alertaction` | `pattern_disposition_description` | `raw` |  |
| `pattern_disposition_details` | `pattern_disposition_details` | `raw` |  |
| `external_pivot_url` | `falcon_host_link` | `raw` |  |
| `externalconfidence` | `confidence` | `raw` |  |
| `externalseverity` | `severity_int_raw` | `computed` |  |
| `scenario` | `scenario` | `raw` |  |
| `objective` | `objective` | `raw` |  |
| `originalrawlog` | `originalrawlog` | `computed` |  |
| `agentid` | `agent_id` | `computed` |  |
| `hostname` | `agent_hostname` | `computed` |  |
| `domain` | `agent_device_domain` | `computed` |  |
| `hostmacaddress` | `mac_address` | `computed` |  |
| `initiatedby` | `actor_process_image_name` | `computed` |  |
| `initiatorpath` | `actor_process_image_path` | `computed` |  |
| `initiatorsha256` | `actor_process_image_sha256` | `computed` |  |
| `initiatorcmd` | `actor_process_command_line` | `computed` |  |
| `initiatorpid` | `actor_process_os_pid` | `computed` |  |
| `xdmsourceprocesscausalityid` | `aggregate_id` | `raw` |  |
| `cgosha256` | `causality_actor_process_image_sha256` | `computed` |  |
| `filename` | `action_file_name` | `computed` |  |
| `filepath` | `action_file_path` | `computed` |  |
| `filesha256` | `action_file_sha256` | `computed` |  |
| `localip` | `action_local_ip` | `computed` |  |
| `remoteip` | `action_remote_ip` | `computed` |  |
| `username` | `actor_effective_username` | `computed` |  |
| `dnsqueryname` | `dns_queries` | `computed` |  |

#### Pre-Alter XQL

```xql
// Vendor / product (required for SOCProductCategoryMap routing)
| alter vendor_name = "CrowdStrike", product_name = "Falcon"

// Filter to EPP detection events only
| filter product = "epp"

// Capture the full raw event as JSON before any transformations
| alter originalrawlog = to_json_string(rawJSON)

// Preserve the raw integer severity BEFORE downstream stages reassign
// 'severity' to the readable string. externalseverity issue field reads this.
| alter severity_int_raw = severity

// XSIAM MITRE Normalization
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

// ============================================================
// CANONICAL CORE NORMALIZATION
// Produces the 29 canonical core columns every vendor pack must
// expose. Column names match issue field names in alert_fields.
// Foundation, Universal Command, and SOC Framework dashboards
// all read from this normalized surface.
// ============================================================
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
```
