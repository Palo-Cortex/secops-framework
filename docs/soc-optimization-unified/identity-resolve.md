# Directory Sync (pan-cie) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/pan-cie/identity-resolve.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/pan-cie/identity-resolve.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `pan-cie` |
| product | `Directory Sync` |
| data_source | `pan_dss_raw` |
| category | `Identity` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `sid` | `string` |  | declared |  |
| `on_prem_sid` | `string` |  | declared |  |
| `netbios_and_sam_account_name` | `string` |  | declared |  |
| `upn` | `string` |  | declared |  |
| `email` | `string` |  | declared |  |
| `sam_account_name` | `string` |  | declared |  |
| `display_name` | `string` |  | declared |  |
| `domain_name` | `string` |  | declared |  |
| `type` | `string` |  | declared |  |
| `dns_host_name` | `string` |  | declared |  |
| `name` | `string` |  | declared |  |
| `os` | `string` |  | declared |  |
| `guid` | `string` |  | declared |  |
| `other_mails` | `string` | ✓ | declared |  |
| `proxy_addresses` | `string` | ✓ | declared |  |
| `agent_id` | `string` |  | declared |  |
| `service_principal_names` | `string` | ✓ | declared |  |
| `user_account_control` | `int` |  | declared |  |
| `last_logon_timestamp` | `datetime` |  | declared |  |
| `department` | `string` |  | declared |  |
| `title` | `string` |  | declared |  |
| `company_name` | `string` |  | declared |  |
| `manager_raw` | `string` |  | declared |  |
| `country` | `string` |  | declared |  |
| `record_generated_time` | `datetime` |  | declared |  |

## Correlation Rules

### SOC IdentityResolve

| Field | Value |
|---|---|
| global_rule_id | `SOC IdentityResolve` |
| subtype |  |
| fromversion | `6.10.0` |

Builds the socfw_identity_map identity-resolution dataset from Cloud Identity Engine data (pan_dss_raw). Runs daily and keeps one canonical row per identity, keyed by SAM / GUID / SID / on-prem SID, with email-first values and a recipient_type classification. Feeds the optional CIE identity-enrichment overlay in the SOC Framework vendor packs. Bind @PRIMARY_MAIL_DOMAIN to your primary mail domain and set is_enabled true to activate CIE enrichment.

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| action | `DATASET` |
| alert_category | `null` |
| alert_domain | `null` |
| execution_mode | `SCHEDULED` |
| mapping_strategy | `CUSTOM` |
| is_enabled |  |
| drilldown_query_timeframe | `null` |
| severity | `null` |

#### Pre-Alter XQL

```xql
| alter email = lowercase(email), upn = lowercase(upn), sam_account_name = lowercase(sam_account_name)
| alter domain_rank = if(upn contains "@PRIMARY_MAIL_DOMAIN", 0, 1)
| alter identity_key = coalesce(sam_account_name, guid, sid, on_prem_sid)
| dedup identity_key by asc domain_rank, desc record_generated_time
| alter spn_str = arraystring(service_principal_names, ",")
| alter acct_disabled = if(user_account_control != null and bitwise_and(user_account_control, 2) = 2, true, false)
| alter recipient_type = if(spn_str != null and spn_str != "", "service", acct_disabled, "shared", "person")
```
