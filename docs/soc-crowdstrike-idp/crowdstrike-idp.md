# Falcon IDP (crowdstrike-idp) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/crowdstrike-idp/crowdstrike-idp.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/crowdstrike-idp/crowdstrike-idp.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `crowdstrike-idp` |
| product | `Falcon IDP` |
| data_source | `crowdstrike_falcon_event_raw` |
| category | `Identity` |

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

## Correlation Rules

### SOC CrowdStrike Falcon - IDP All Alerts

| Field | Value |
|---|---|
| global_rule_id | `SOC CrowdStrike Falcon - IDP All Alerts` |
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
| execution_mode | `SCHEDULED` |
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
```
