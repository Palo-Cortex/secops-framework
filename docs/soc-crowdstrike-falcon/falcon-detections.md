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
| `source_account_name` | `string` |  | confirmed |  |
| `source_account_upn` | `string` |  | confirmed |  |
| `source_account_object_sid` | `string` |  | confirmed |  |
| `source_endpoint_host_name` | `string` |  | confirmed |  |
| `source_endpoint_address_ip4` | `string` |  | confirmed |  |
| `source_endpoint_address_ip6` | `string` |  | confirmed |  |
| `source_endpoint_sensor_id` | `string` |  | confirmed |  |
| `target_account_name` | `string` |  | confirmed |  |
| `target_account_object_sid` | `string` |  | confirmed |  |
| `target_endpoint_host_name` | `string` |  | confirmed |  |
| `target_endpoint_sensor_id` | `string` |  | confirmed |  |
| `logon_domain` | `string` |  | confirmed |  |
| `destination_ips` | `json` |  | confirmed |  |
| `sso_application_identifier` | `string` |  | confirmed |  |
| `sso_application_uri` | `string` |  | confirmed |  |
| `idp_policy_rule_name` | `string` |  | confirmed |  |
| `idp_policy_rule_action` | `string` |  | confirmed |  |
| `idp_policy_rule_trigger` | `string` |  | confirmed |  |
| `idp_policy_mfa_provider` | `string` |  | confirmed |  |
| `idp_policy_mfa_factor_type` | `string` |  | confirmed |  |
| `display_name` | `string` |  | confirmed |  |
| `tactic` | `string` |  | confirmed |  |
| `tactic_id` | `string` |  | confirmed |  |
| `technique` | `string` |  | confirmed |  |
| `technique_id` | `string` |  | confirmed |  |
| `location_country_code` | `string` |  | confirmed |  |
| `pattern_disposition` | `string` |  | confirmed |  |

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
| `xdm.source.host.hostname` | `coalesce(device->hostname, source_endpoint_host_name)` | `device, source_endpoint_host_name` | `hostname` | epp device struct; idp flat source endpoint column. |
| `xdm.source.host.fqdn` | `device->machine_domain` | `device` | `hostfqdn` | machine_domain is being mapped to fqdn here AND to user.domain below. In Falcon's schema it's the AD domain — fqdn would be hostname + machine_domain concatenated. Flag for review. |
| `xdm.source.host.os_family` | `device->os_version` | `device` | `hostos` | os_version is the OS version string (e.g., "Windows 10 Pro"); os_family should be the family enum. Should likely use XDM_CONST.OS_FAMILY_* via if() chain. |
| `xdm.source.ipv4` | `coalesce(device->local_ip, source_endpoint_address_ip4)` | `device, source_endpoint_address_ip4` | `hostip` |  |
| `xdm.source.user.username` | `coalesce(user_name, source_account_name)` | `user_name, source_account_name` | `username` |  |
| `xdm.source.user.domain` | `coalesce(device->machine_domain, logon_domain)` | `device, logon_domain` | `userdomain` |  |
| `xdm.source.user.groups` | `device->groups[]` | `device` | `usergroups` |  |
| `xdm.source.user.upn` | `coalesce(user_principal, source_account_upn)` | `user_principal, source_account_upn` | `userupn` |  |
| `xdm.source.user.identifier` | `source_account_object_sid` | `source_account_object_sid` | `usersid` |  |
| `xdm.target.user.username` | `target_account_name` | `target_account_name` | `targetuser` |  |
| `xdm.target.user.identifier` | `target_account_object_sid` | `target_account_object_sid` | `targetusersid` |  |
| `xdm.target.host.hostname` | `target_endpoint_host_name` | `target_endpoint_host_name` | `targethostname` |  |
| `xdm.target.agent.identifier` | `target_endpoint_sensor_id` | `target_endpoint_sensor_id` | `targetagentid` |  |
| `xdm.source.agent.identifier` | `coalesce(agent_id, source_endpoint_sensor_id)` | `agent_id, source_endpoint_sensor_id` | `agentid` | Falcon aid; epp flat agent_id, idp source sensor id — same value space. |
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

### SOC CrowdStrike Falcon - IDP Alerts

| Field | Value |
|---|---|
| global_rule_id | `SOC CrowdStrike Falcon - IDP Alerts` |
| subtype | `passthrough` |
| fromversion | `8.0.0` |

Creates an XSIAM alert for each CrowdStrike Identity Protection (IDP) detection. SINGLE consolidated rule: all MITRE tactics, all severities, vendor severity passed through unmodified. Replaces the per-tactic v1 fleet (Initial Access / Credential Access / ...) -- user_defined_category on tactic preserves per-tactic categorization without per-tactic rules, mirroring the epp consolidation. Two-sided identity contract: source principal/endpoint mapped to the standard grouping fields, target side to dst_agent_id / dst hostname / destination username so lateral-movement detections group with both the attacking endpoint's EPP alerts and the victim host. Sensor ids are Falcon aids — the same values the epp rule emits in agent_id, closing the endpoint↔IDP agent pivot. cid is the Falcon customer (tenant) id and must NEVER be used as a grouping key: it is identical on every event in the environment.

**Tags:** `SOCFramework`, `Detection`, `Identity`, `CrowdStrikeIDP`

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| action | `ALERTS` |
| execution_mode | `SCHEDULED` |
| mapping_strategy | `CUSTOM` |
| user_defined_category | `tactic` |
| user_defined_severity | `alert_severity` |
| is_enabled | `✓` |
| drilldown_query_timeframe | `ALERT` |
| severity | `User Defined` |

#### Suppression

| Field | Value |
|---|---|
| enabled | `✓` |
| duration | `1 hours` |
| fields | `composite_id` |

composite_id is CrowdStrike's per-detection unique identifier.

#### Alert Fields

Issue-field assignments emitted by the correlation rule. The Description column captures intent — when present, this is what downstream playbooks rely on the field meaning.

| Issue Field | Source | Bucket | Description |
|---|---|---|---|
| `vendor` | `vendor` | `computed` |  |
| `product` | `product` | `computed` |  |
| `severity` | `severity` | `computed` |  |
| `alert_description` | `alert_description` | `computed` |  |
| `originalalertid` | `originalalertid` | `computed` |  |
| `originalalertname` | `originalalertname` | `computed` |  |
| `originalalertsource` | `originalalertsource` | `computed` |  |
| `externallink` | `externallink` | `computed` |  |
| `mitretacticid` | `mitretacticid` | `computed` |  |
| `mitretacticname` | `mitretacticname` | `computed` |  |
| `mitretechniqueid` | `mitretechniqueid` | `computed` |  |
| `mitretechniquename` | `mitretechniquename` | `computed` |  |
| `agent_hostname` | `agent_hostname` | `computed` |  |
| `agent_id` | `agent_id` | `computed` |  |
| `agent_device_domain` | `agent_device_domain` | `computed` |  |
| `actor_effective_username` | `actor_effective_username` | `computed` |  |
| `action_local_ip` | `action_local_ip` | `computed` |  |
| `action_remote_ip` | `action_remote_ip` | `computed` |  |
| `causality_actor_causality_id` | `causality_id` | `computed` |  |
| `xdmsourceprocesscausalityid` | `causality_id` | `computed` |  |
| `user_principal` | `user_principal` | `raw` |  |
| `dst_agent_id` | `dst_sensor_id` | `computed` |  |
| `dst_hostname` | `dst_host` | `computed` |  |
| `dst_username` | `dst_account_name` | `computed` |  |
| `username` | `actor_effective_username` | `computed` |  |
| `hostname` | `agent_hostname` | `computed` |  |
| `domain` | `agent_device_domain` | `computed` |  |
| `agentid` | `agent_id` | `computed` |  |
| `localip` | `action_local_ip` | `computed` |  |
| `remoteip` | `action_remote_ip` | `computed` |  |
| `usersid` | `src_account_sid` | `computed` |  |
| `socfwidentitysourceaccount` | `src_account_name` | `computed` |  |
| `socfwidentitysourcesid` | `src_account_sid` | `computed` |  |
| `socfwidentitysourcehost` | `src_host` | `computed` |  |
| `socfwidentitysourceip` | `src_ip` | `computed` |  |
| `socfwidentitytargetaccount` | `dst_account_name` | `computed` |  |
| `socfwidentitytargetsid` | `dst_account_sid` | `computed` |  |
| `socfwidentitytargethost` | `dst_host` | `computed` |  |
| `socfwidentityssoapp` | `sso_application_identifier` | `raw` |  |
| `socfwidentitypolicyrule` | `idp_policy_rule_name` | `raw` |  |
| `socfwidentitypolicyaction` | `idp_policy_rule_action` | `raw` |  |
| `socfwidentitypolicytrigger` | `idp_policy_rule_trigger` | `raw` |  |
| `socfwidentitymfaprovider` | `idp_policy_mfa_provider` | `raw` |  |
| `socfwidentitymfafactor` | `idp_policy_mfa_factor_type` | `raw` |  |
| `scenario` | `scenario` | `raw` |  |
| `objective` | `objective` | `raw` |  |
| `externalconfidence` | `confidence` | `raw` |  |
| `locationregion` | `location_country_code` | `raw` |  |
| `alertaction` | `pattern_disposition` | `raw` |  |
| `employeedisplayname` | `display_name` | `raw` |  |
| `alert_name` | `alert_name` | `computed` |  |

#### Pre-Alter XQL

```xql
| alter vendor_name = "CrowdStrike", product_name = "Falcon Identity Protection"

| filter product = "idp"
| filter timestamp_diff(time_frame_end(), _time, "MINUTE") <= 15

// Severity passthrough -- vendor severity unmodified. (The per-tactic v1
// fleet demoted Medium->Low; tenant-level tuning like that belongs in
// Issue Exclusions or per-tenant overrides, not framework content.)
| alter alert_severity = severity_name

// IDP-specific extraction (flat source_*/target_* columns). Coalesce
// with the epp-shaped fields so one rule body serves whichever columns
// the event populates.
| alter src_account_name = source_account_name,
        src_account_upn  = source_account_upn,
        src_account_sid  = source_account_object_sid,
        src_host         = source_endpoint_host_name,
        src_ip           = source_endpoint_address_ip4,
        src_ip_v6        = source_endpoint_address_ip6,
        src_sensor_id    = source_endpoint_sensor_id,
        dst_account_name = target_account_name,
        dst_account_sid  = target_account_object_sid,
        dst_host         = target_endpoint_host_name,
        dst_sensor_id    = target_endpoint_sensor_id,
        idp_logon_domain = logon_domain

// destination_ips is a json array; first IPv4 for the remote-ip pivot
| alter dst_ip = arrayindex(regextract(to_json_string(destination_ips), "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"), 0)

// Username normalization: lowercase full principal, UPN preferred.
| alter user_canon = lowercase(coalesce(user_principal, source_account_upn, user_name, source_account_name))

// Identity context for layout richness: who -> what -> where
| alter idp_context = concat(
    "Source: ", coalesce(src_account_name, "Unknown"),
    " @ ", coalesce(src_host, "Unknown"), " (", coalesce(src_ip, "n/a"), ")",
    " -> Target: ", coalesce(dst_account_name, "n/a"),
    " @ ", coalesce(dst_host, "n/a"),
    " | App: ", coalesce(sso_application_identifier, sso_application_uri, "n/a"),
    " | Policy: ", coalesce(idp_policy_rule_name, "n/a"),
    " (", coalesce(idp_policy_rule_action, "no action"), ")",
    " | MFA: ", coalesce(idp_policy_mfa_factor_type, idp_policy_mfa_provider, "n/a")
  )

| alter alert_name = concat(
    "[Identity] ",
    coalesce(user_canon, display_name, src_host, "Unknown"),
    " - ", coalesce(tactic, "Detection"),
    ": ", coalesce(technique, name)),
  alert_description = concat(
    coalesce(description, name),
    " | Severity: ", coalesce(severity_name, "Unknown"),
    " | ", idp_context)

| alter
        vendor                   = vendor_name,
        product                  = product_name,
        originalalertid          = composite_id,
        originalalertname        = alert_name,
        originalalertsource      = "CrowdStrike Falcon Identity Protection",
        externallink             = falcon_host_link,
        severity                 = severity_name,
        mitretacticid            = tactic_id,
        mitretacticname          = tactic,
        mitretechniqueid         = technique_id,
        mitretechniquename       = technique,
        agent_hostname           = coalesce(src_host, device -> hostname),
        agent_id                 = coalesce(src_sensor_id, agent_id),
        agent_device_domain      = coalesce(idp_logon_domain, device -> machine_domain),
        actor_effective_username = user_canon,
        action_local_ip          = coalesce(src_ip, device -> local_ip),
        action_remote_ip         = dst_ip,
        causality_id             = aggregate_id
```
