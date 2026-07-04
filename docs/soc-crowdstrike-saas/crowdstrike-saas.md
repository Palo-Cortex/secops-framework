# Falcon SaaS (crowdstrike-saas) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/crowdstrike-saas/crowdstrike-saas.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/crowdstrike-saas/crowdstrike-saas.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `crowdstrike-saas` |
| product | `Falcon SaaS` |
| data_source | `crowdstrike_falcon_event_raw` |
| category | `Cloud` |

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

### SOC CrowdStrike Falcon - SaaS All Alerts

| Field | Value |
|---|---|
| global_rule_id | `SOC CrowdStrike Falcon - SaaS All Alerts` |
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
| `usersid` | `idr_sid` |  |  |
| `rawevent` | `originalrawlog` |  |  |
| `severity` | `severity_name` |  |  |
| `username` | `actor_effective_username` |  |  |
| `externallink` | `falcon_host_link` |  |  |
| `employeeemail` | `idr_email` |  |  |
| `mitretacticid` | `mitre_tactic_id` |  |  |
| `samaccountname` | `original_user_name` |  |  |
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
| `originalalertsource` | `originalalertsource` |  |  |
| `actor_effective_username` | `actor_effective_username` |  |  |
| `causality_actor_causality_id` | `cid` |  |  |

#### Pre-Alter XQL

```xql
| filter product = "saas-security"
| alter vendor_name = "CrowdStrike", product_name = "Falcon SaaS"
| alter originalalertsource = "CrowdStrike Falcon SaaS Security"
| alter originalrawlog = to_json_string(rawJSON)
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
| alter actor_effective_username = user_name

| alter local_ip = arrayindex(regextract(coalesce(event_summary, description, ""), "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"), 0)
```
