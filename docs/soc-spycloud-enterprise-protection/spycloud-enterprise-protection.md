# Enterprise Protection (spycloud) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/spycloud/spycloud-enterprise-protection.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/spycloud/spycloud-enterprise-protection.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `spycloud` |
| product | `Enterprise Protection` |
| data_source | `spycloudenterpriseprotectionfeed_generic_alert_raw` |
| category | `Cloud` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `document_id` | `string` |  | declared |  |
| `source_id` | `float` |  | declared |  |
| `log_id` | `string` |  | declared |  |
| `origin_id` | `string` |  | declared |  |
| `severity` | `float` |  | declared |  |
| `breach_category` | `string` |  | declared |  |
| `breach_title` | `string` |  | declared |  |
| `spycloud_publish_date` | `int` |  | declared |  |
| `email` | `string` |  | declared |  |
| `email_domain` | `string` |  | declared |  |
| `email_username` | `string` |  | declared |  |
| `username` | `string` |  | declared |  |
| `domain` | `string` |  | declared |  |
| `password_type` | `string` |  | declared |  |
| `infected_machine_id` | `string` |  | declared |  |
| `infected_path` | `string` |  | declared |  |
| `infected_time` | `datetime` |  | declared |  |
| `user_hostname` | `string` |  | declared |  |
| `user_os` | `string` |  | declared |  |
| `user_sys_domain` | `string` |  | declared |  |
| `user_sys_registered_owner` | `string` |  | declared |  |
| `ip_addresses` | `json` | ✓ | declared |  |
| `av_softwares` | `json` | ✓ | declared |  |
| `user_browser` | `string` |  | declared |  |
| `country_code` | `string` |  | declared |  |
| `target_domain` | `string` |  | declared |  |
| `target_subdomain` | `string` |  | declared |  |
| `target_url` | `string` |  | declared |  |

## Modeling Rule — SOC SpyCloud Enterprise Protection Modeling Rule

| Field | Value |
|---|---|
| modeling_rule_id | `SOC_SpyCloudEP_ModelingRule` |
| modeling_rule_name | `SOC SpyCloud Enterprise Protection Modeling Rule` |
| directory_name | `SOCSpyCloudEPModelingRules` |
| fromversion | `6.10.0` |

### Field Mappings

What each XDM field is, where it sources from, what issue field it surfaces on, and why the mapping is shaped the way it is.

| XDM Path | Expression | Sources | Issue Field | Description |
|---|---|---|---|---|
| `xdm.event.id` | `to_string(document_id)` | `document_id` | `originalalertid` |  |
| `xdm.event.type` | `breach_category` | `breach_category` |  |  |
| `xdm.alert.original_alert_id` | `to_string(document_id)` | `document_id` |  |  |
| `xdm.alert.name` | `breach_title` | `breach_title` | `originalalertname` |  |
| `xdm.alert.severity` | `to_string(severity)` | `severity` | `severity` |  |
| `xdm.alert.category` | `breach_category` | `breach_category` |  |  |

## Correlation Rules

### SOC SpyCloud - Infostealer Credential Exposure

| Field | Value |
|---|---|
| global_rule_id | `SOC SpyCloud - Infostealer Credential Exposure` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Creates an XSIAM alert for each SpyCloud Enterprise Protection infostealer record (spycloudenterpriseprotectionfeed_generic_alert_raw, breach_category = infostealer): a corporate credential harvested from an infected device. Canonicalizes the exposed email as the identity pivot, maps the infected host, its IP and the stealer path to the endpoint/network pivots, and injects DS:SpyCloud/Enterprise Protection so Foundation routes the alert. Credential material and personal data in the feed are never read.

**Tags:** `SOCFramework`, `Passthrough`, `Cloud`, `Identity`, `SpyCloud`

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| action | `ALERTS` |
| execution_mode | `SCHEDULED` |
| mapping_strategy | `CUSTOM` |
| user_defined_category | `sc_category` |
| user_defined_severity | `severity` |
| is_enabled | `✓` |
| drilldown_query_timeframe | `ALERT` |
| severity | `User Defined` |

#### Suppression

| Field | Value |
|---|---|
| enabled | `✓` |
| duration | `24 hours` |
| fields | `originalalertid` |

document_id is SpyCloud's per-record unique id. A record can be
republished; 24h suppression keeps one issue per record per day.

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
| `actor_process_image_path` | `actor_process_image_path` | `computed` |  |
| `action_local_ip` | `action_local_ip` | `computed` |  |
| `dns_query_name` | `dns_query_name` | `computed` |  |
| `user_principal` | `user_principal` | `computed` |  |
| `userid` | `user_principal` | `computed` |  |
| `username` | `actor_effective_username` | `computed` |  |
| `hostname` | `agent_hostname` | `computed` |  |
| `agentid` | `agent_id` | `computed` |  |
| `domain` | `agent_device_domain` | `computed` |  |
| `localip` | `action_local_ip` | `computed` |  |
| `initiatorpath` | `actor_process_image_path` | `computed` |  |
| `socfwidentityuserdisplayname` | `idr_display_name` | `cie` |  |
| `spycloud_breach_category` | `spycloud_breach_category` | `computed` |  |
| `spycloud_breach_title` | `spycloud_breach_title` | `computed` |  |
| `spycloud_severity` | `spycloud_severity` | `computed` |  |
| `spycloud_document_id` | `spycloud_document_id` | `computed` |  |
| `spycloud_source_id` | `spycloud_source_id` | `computed` |  |
| `spycloud_publish_date` | `spycloud_publish_date` | `computed` |  |
| `spycloud_target_domain` | `spycloud_target_domain` | `computed` |  |
| `spycloud_target_url` | `spycloud_target_url` | `computed` |  |
| `spycloud_infected_host` | `spycloud_infected_host` | `computed` |  |
| `spycloud_infected_machine` | `spycloud_infected_machine` | `computed` |  |
| `spycloud_infected_path` | `spycloud_infected_path` | `computed` |  |
| `spycloud_infected_time` | `spycloud_infected_time` | `computed` |  |
| `spycloud_user_os` | `spycloud_user_os` | `computed` |  |
| `spycloud_av_software` | `spycloud_av_software` | `computed` |  |
| `spycloud_password_type` | `spycloud_password_type` | `computed` |  |
| `spycloud_country` | `spycloud_country` | `computed` |  |
| `tags` | `alert_tags` | `computed` |  |
| `alert_name` | `alert_name` | `computed` |  |

#### Pre-Alter XQL

```xql
// Vendor / product (required for SOCProductCategoryMap routing)
| alter vendor_name = "SpyCloud", product_name = "Enterprise Protection"

// Scope: infostealer records only (see header)
| filter breach_category = "infostealer"

| alter sc_category = "Credential Exposure"

// SpyCloud severity (2 / 5 / 20 / 25) → XSIAM ladder
| alter sc_sev = to_float(severity)
| alter severity = if(
        sc_sev >= 25, "Critical",
        sc_sev >= 20, "High",
        sc_sev >= 5,  "Medium",
        "Low"
    )

// Infected device IP (first of the array), timestamps
| alter
        sc_ip_first      = arrayindex(ip_addresses -> [], 0),
        sc_infected_time = infected_time,
        sc_av            = arraystring(av_softwares -> [], ", ")
// Array elements keep their JSON quotes; regextract pulls the bare IPv4.
// NOTE: XQL regex escapes are single-backslash; "\\d" never matches.
| alter sc_ipv4 = arrayindex(regextract(sc_ip_first, "([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"), 0)

// ---- Identity: the exposed corporate email, email-first.
| alter exposed_email = lowercase(coalesce(email, if(username contains "@", username, null)))
| alter user_principal = exposed_email
| alter user_name      = coalesce(exposed_email, username)
| alter display_name   = user_sys_registered_owner
| alter actor_effective_username = coalesce(exposed_email, lowercase(username))

// Title: [Cloud] {email} - Credential Exposure: {breach}
| alter alert_name = concat(
        "[Cloud] ",
        coalesce(exposed_email, username, "Unknown"),
        " - Credential Exposure: ",
        coalesce(breach_title, "Infostealer")
    )

| alter alert_description = concat(
        "SpyCloud infostealer record: a credential for ",
        coalesce(exposed_email, username, "an unknown account"),
        " was harvested from an infected device.",
        " | Target: ",    coalesce(target_domain, "Unknown"),
        " | Host: ",      coalesce(user_hostname, infected_machine_id, "Unknown"),
        " | OS: ",        coalesce(user_os, "-"),
        " | Stealer path: ", coalesce(infected_path, "-"),
        " | Infected: ",  coalesce(to_string(sc_infected_time), "-"),
        " | AV: ",        coalesce(sc_av, "-"),
        " | Password type: ", coalesce(password_type, "-"),
        " | Severity: ",  coalesce(severity, "Unknown")
    )

// ============================================================
// CANONICAL CORE NORMALIZATION
// ============================================================
| alter
        vendor                               = vendor_name,
        product                              = product_name,
        originalalertid                      = document_id,
        originalalertname                    = coalesce(breach_title, "Infostealer credential exposure"),
        originalalertsource                  = "SpyCloud - Enterprise Protection",
        externallink                         = null,
        severity                             = severity,
        mitretacticid                        = "TA0006",
        mitretacticname                      = "Credential Access",
        mitretechniqueid                     = "T1555",
        mitretechniquename                   = "Credentials from Password Stores",
        agent_hostname                       = user_hostname,
        agent_id                             = infected_machine_id,
        agent_device_domain                  = user_sys_domain,
        actor_process_image_name             = null,
        actor_process_image_path             = infected_path,
        actor_process_image_sha256           = null,
        actor_process_command_line           = null,
        actor_process_os_pid                 = null,
        causality_actor_process_image_name   = null,
        causality_actor_process_image_path   = null,
        causality_actor_process_image_sha256 = null,
        action_file_name                     = null,
        action_file_path                     = null,
        action_file_sha256                   = null,
        action_local_ip                      = sc_ipv4,
        action_remote_ip                     = null,
        dns_query_name                       = target_domain

// SpyCloud extensions (no credential material, no PII)
| alter
        spycloud_breach_category   = breach_category,
        spycloud_breach_title      = breach_title,
        spycloud_severity          = severity,
        spycloud_document_id       = document_id,
        spycloud_source_id         = to_string(source_id),
        spycloud_publish_date      = spycloud_publish_date,
        spycloud_target_domain     = target_domain,
        spycloud_target_url        = target_url,
        spycloud_infected_host     = user_hostname,
        spycloud_infected_machine  = infected_machine_id,
        spycloud_infected_path     = infected_path,
        spycloud_infected_time     = sc_infected_time,
        spycloud_user_os           = user_os,
        spycloud_av_software       = sc_av,
        spycloud_password_type     = password_type,
        spycloud_country           = country_code

// Tag injection — DS:SpyCloud/Enterprise Protection → ds_spycloud_enterprise_protection
| alter alert_tags = arraycreate("DS:SpyCloud/Enterprise Protection", "DOM:Security")
```
