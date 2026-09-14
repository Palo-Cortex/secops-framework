# Guardian (nozomi-networks) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/nozomi-networks/nozomi-guardian-alerts.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/nozomi-networks/nozomi-guardian-alerts.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `nozomi-networks` |
| product | `Guardian` |
| data_source | `nozomi_networks_generic_alert_raw` |
| category | `Network` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `id` | `string` |  | declared |  |
| `type_id` | `string` |  | declared |  |
| `type_name` | `string` |  | declared |  |
| `name` | `string` |  | declared |  |
| `description` | `string` |  | declared |  |
| `threat_name` | `string` |  | declared |  |
| `risk` | `string` |  | declared |  |
| `severity` | `float` |  | declared |  |
| `status` | `string` |  | declared |  |
| `ack` | `boolean` |  | declared |  |
| `is_security` | `boolean` |  | declared |  |
| `is_incident` | `boolean` |  | declared |  |
| `trigger_id` | `string` |  | declared |  |
| `trigger_type` | `string` |  | declared |  |
| `ti_source` | `string` |  | declared |  |
| `appliance_host` | `string` |  | declared |  |
| `capture_device` | `string` |  | declared |  |
| `bpf_filter` | `string` |  | declared |  |
| `time` | `float` |  | declared |  |
| `created_time` | `float` |  | declared |  |
| `closed_time` | `float` |  | declared |  |
| `record_created_at` | `float` |  | declared |  |
| `record_updated_at` | `float` |  | declared |  |
| `ip_src` | `string` |  | declared |  |
| `ip_dst` | `string` |  | declared |  |
| `mac_src` | `string` |  | declared |  |
| `mac_dst` | `string` |  | declared |  |
| `port_src` | `float` |  | declared |  |
| `port_dst` | `float` |  | declared |  |
| `protocol` | `string` |  | declared |  |
| `transport_protocol` | `string` |  | declared |  |
| `id_src` | `string` |  | declared |  |
| `id_dst` | `string` |  | declared |  |
| `label_src` | `string` |  | declared |  |
| `label_dst` | `string` |  | declared |  |
| `zone_src` | `string` |  | declared |  |
| `zone_dst` | `string` |  | declared |  |
| `src_roles` | `string` |  | declared |  |
| `dst_roles` | `string` |  | declared |  |
| `properties` | `json` |  | declared |  |
| `parents` | `json` |  | declared |  |

## Modeling Rule — SOC Nozomi Guardian Modeling Rule

| Field | Value |
|---|---|
| modeling_rule_id | `SOC_NozomiGuardian_ModelingRule` |
| modeling_rule_name | `SOC Nozomi Guardian Modeling Rule` |
| directory_name | `SOCNozomiGuardianModelingRules` |
| fromversion | `6.10.0` |

### Field Mappings

What each XDM field is, where it sources from, what issue field it surfaces on, and why the mapping is shaped the way it is.

| XDM Path | Expression | Sources | Issue Field | Description |
|---|---|---|---|---|
| `xdm.event.id` | `to_string(id)` | `id` | `originalalertid` |  |
| `xdm.event.type` | `type_name` | `type_name` |  |  |
| `xdm.alert.original_alert_id` | `to_string(id)` | `id` |  |  |
| `xdm.alert.name` | `name` | `name` | `originalalertname` |  |
| `xdm.alert.description` | `description` | `description` | `alert_description` |  |
| `xdm.alert.severity` | `to_string(risk)` | `risk` | `severity` | Raw Nozomi risk (0-10). The correlation rule maps it to the XSIAM ladder. |
| `xdm.alert.category` | `type_name` | `type_name` |  |  |
| `xdm.alert.subcategory` | `threat_name` | `threat_name` |  |  |
| `xdm.source.ipv4` | `ip_src` | `ip_src` | `action_remote_ip` |  |
| `xdm.target.ipv4` | `ip_dst` | `ip_dst` | `action_local_ip` |  |
| `xdm.target.port` | `to_integer(port_dst)` | `port_dst` | `action_remote_port` |  |

### Contributes (Artifacts.*)

Fields populated for downstream lifecycle Artifacts schemas:

- `Network.RemoteIP`
- `Network.LocalIP`
- `Network.RemotePort`

## Correlation Rules

### SOC Nozomi Guardian - Security Alerts

| Field | Value |
|---|---|
| global_rule_id | `SOC Nozomi Guardian - Security Alerts` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Reshapes Nozomi Networks Guardian security alerts (nozomi_networks_generic_alert_raw) into properly-formed XSIAM alerts for the SOC Framework Network category. Maps the OT 5-tuple to the canonical network pivots, the Nozomi risk score to XSIAM severity, MITRE Enterprise (ICS as fallback) from the properties payload, and injects DS:Nozomi Networks/Guardian and DOM:Security so Foundation Product Classification routes the alert.

**Tags:** `SOCFramework`, `Passthrough`, `Network`, `OT`, `NozomiNetworks`

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| action | `ALERTS` |
| execution_mode | `SCHEDULED` |
| mapping_strategy | `CUSTOM` |
| user_defined_category | `nz_category` |
| user_defined_severity | `severity` |
| is_enabled | `✓` |
| drilldown_query_timeframe | `ALERT` |
| severity | `User Defined` |

#### Suppression

| Field | Value |
|---|---|
| enabled | `✓` |
| duration | `1 hours` |
| fields | `originalalertid` |

originalalertid sources from Nozomi's per-alert `id`. Hourly suppression
absorbs re-polls of an alert still `open` before it is acknowledged.

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
| `mitretacticid` | `mitretacticid` | `mitre` |  |
| `mitretacticname` | `mitretacticname` | `mitre` |  |
| `mitretechniqueid` | `mitretechniqueid` | `mitre` |  |
| `mitretechniquename` | `mitretechniquename` | `mitre` |  |
| `action_local_ip` | `action_local_ip` | `computed` |  |
| `action_remote_ip` | `action_remote_ip` | `computed` |  |
| `action_remote_port` | `action_remote_port` | `computed` |  |
| `action_local_port` | `action_local_port` | `computed` |  |
| `dns_query_name` | `dns_query_name` | `computed` |  |
| `localip` | `action_local_ip` | `computed` |  |
| `remoteip` | `action_remote_ip` | `computed` |  |
| `nozomi_type_id` | `nozomi_type_id` | `computed` |  |
| `nozomi_type_name` | `nozomi_type_name` | `computed` |  |
| `nozomi_threat_name` | `nozomi_threat_name` | `computed` |  |
| `nozomi_risk` | `nozomi_risk` | `computed` |  |
| `nozomi_is_incident` | `nozomi_is_incident` | `computed` |  |
| `nozomi_trigger_type` | `nozomi_trigger_type` | `computed` |  |
| `nozomi_ti_source` | `nozomi_ti_source` | `computed` |  |
| `nozomi_src_label` | `nozomi_src_label` | `computed` |  |
| `nozomi_dst_label` | `nozomi_dst_label` | `computed` |  |
| `nozomi_src_mac` | `nozomi_src_mac` | `computed` |  |
| `nozomi_dst_mac` | `nozomi_dst_mac` | `computed` |  |
| `nozomi_src_zone` | `nozomi_src_zone` | `computed` |  |
| `nozomi_dst_zone` | `nozomi_dst_zone` | `computed` |  |
| `nozomi_protocol` | `nozomi_protocol` | `computed` |  |
| `nozomi_appliance` | `nozomi_appliance` | `computed` |  |
| `nozomi_indicator` | `nozomi_indicator` | `computed` |  |
| `nozomi_malicious_ip` | `nozomi_malicious_ip` | `computed` |  |
| `nozomi_solution` | `nozomi_solution` | `computed` |  |
| `nozomi_rule_name` | `nozomi_rule_name` | `computed` |  |
| `nozomi_ics_technique_id` | `nozomi_ics_technique_id` | `computed` |  |
| `tags` | `alert_tags` | `computed` |  |
| `alert_name` | `alert_name` | `computed` |  |

#### Pre-Alter XQL

```xql
// Vendor / product (required for SOCProductCategoryMap routing)
| alter vendor_name = "Nozomi Networks", product_name = "Guardian"

// Scope: security alerts only (operational / asset-change alerts are
// is_security = false on Guardian and belong to OT ops, not the SOC).
| filter is_security = true

// Numeric helpers
| alter
        nz_risk      = to_float(risk),
        nz_port_src  = to_integer(port_src),
        nz_port_dst  = to_integer(port_dst)

// Risk (0-10) → XSIAM severity ladder
| alter severity = if(
        nz_risk >= 9, "Critical",
        nz_risk >= 7, "High",
        nz_risk >= 4, "Medium",
        "Low"
    )

// Category from Nozomi's alert type
| alter nz_category = coalesce(type_name, "Network")

// ---- properties payload (JSON string) ----
| alter
        mitre_ent_id     = json_extract_scalar(properties, "$.mitre_attack_enterprise.techniques[0].id"),
        mitre_ent_name   = json_extract_scalar(properties, "$.mitre_attack_enterprise.techniques[0].name"),
        mitre_ent_tactic = json_extract_scalar(properties, "$.mitre_attack_enterprise.techniques[0].tactic"),
        mitre_ics_id     = json_extract_scalar(properties, "$.mitre_attack_for_ics.techniques[0].id"),
        mitre_ics_name   = json_extract_scalar(properties, "$.mitre_attack_for_ics.techniques[0].name"),
        mitre_ics_tactic = json_extract_scalar(properties, "$.mitre_attack_for_ics.techniques[0].tactic"),
        nz_indicator     = json_extract_scalar(properties, "$.malicious_indicator"),
        nz_mal_domain    = json_extract_scalar(properties, "$.details_malicious_domain.value"),
        nz_mal_ip        = json_extract_scalar(properties, "$.details_malicious_ip.value"),
        nz_cause         = json_extract_scalar(properties, "$.cause"),
        nz_solution      = json_extract_scalar(properties, "$.solution"),
        nz_rule_name     = json_extract_scalar(properties, "$.rule_name")

// MITRE: Enterprise first, ICS as fallback. Tactic name → TA id via the
// same normalised if-chain the Defender contracts use (+ ICS tactics).
| alter
        mitre_technique_id   = coalesce(mitre_ent_id, mitre_ics_id),
        mitre_technique_name = coalesce(mitre_ent_name, mitre_ics_name),
        mitre_tactic_name    = coalesce(mitre_ent_tactic, mitre_ics_tactic)
| alter tac_norm = replace(replace(replace(replace(lowercase(coalesce(mitre_tactic_name, "")), " ", ""), "-", ""), "_", ""), ".", "")
| alter mitre_tactic_id = if(
        tac_norm contains "reconnaissance",       "TA0043",
        tac_norm contains "resourcedevelopment",  "TA0042",
        tac_norm contains "initialaccess",        "TA0001",
        tac_norm contains "execution",            "TA0002",
        tac_norm contains "persistence",          "TA0003",
        tac_norm contains "privilegeescalation",  "TA0004",
        tac_norm contains "defenseevasion",       "TA0005",
        tac_norm contains "credentialaccess",     "TA0006",
        tac_norm contains "discovery",            "TA0007",
        tac_norm contains "lateralmovement",      "TA0008",
        tac_norm contains "collection",           "TA0009",
        tac_norm contains "commandandcontrol",    "TA0011",
        tac_norm contains "exfiltration",         "TA0010",
        tac_norm contains "impact",               "TA0040",
        tac_norm contains "inhibitresponse",      "TA0107",
        tac_norm contains "impairprocesscontrol", "TA0106",
        tac_norm contains "evasion",              "TA0103",
        null)

// Domain pivot: malicious domain indicator when the alert carries one
| alter dns_name = coalesce(nz_mal_domain, if(nz_indicator ~= "^[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", nz_indicator, null))

// Title: [Network] {src} → {dst} - {type}: {threat|name}
| alter alert_name = concat(
        "[Network] ",
        coalesce(ip_src, label_src, "Unknown"),
        " → ",
        coalesce(ip_dst, label_dst, "Unknown"),
        " - ",
        coalesce(type_name, "Security Alert"),
        ": ",
        coalesce(threat_name, name, "Anomaly")
    )

| alter alert_description = concat(
        coalesce(description, name, "Nozomi Guardian security alert"),
        " | Source: ",      coalesce(ip_src, "Unknown"), " (", coalesce(label_src, zone_src, "-"), ")",
        " | Destination: ", coalesce(ip_dst, "Unknown"), " (", coalesce(label_dst, zone_dst, "-"), ")",
        " | Port: ",        coalesce(to_string(nz_port_dst), "-"),
        " | Protocol: ",    coalesce(protocol, transport_protocol, "-"),
        " | Risk: ",        coalesce(risk, "-"),
        " | Trigger: ",     coalesce(trigger_type, "-"),
        " | TI: ",          coalesce(ti_source, "-"),
        " | Cause: ",       coalesce(nz_cause, "")
    )

// ============================================================
// CANONICAL CORE NORMALIZATION
// Endpoint-shaped columns stay null for network alerts.
// Direction convention matches Check Point NDR: the source node
// (Nozomi's attacker side) → action_remote_ip, destination → local.
// ============================================================
| alter
        vendor              = vendor_name,
        product             = product_name,
        originalalertid     = id,
        originalalertname   = coalesce(name, type_name),
        originalalertsource = "Nozomi Networks - Guardian",
        externallink        = null,
        severity            = severity,
        mitretacticid       = mitre_tactic_id,
        mitretacticname     = mitre_tactic_name,
        mitretechniqueid    = mitre_technique_id,
        mitretechniquename  = mitre_technique_name,
        action_local_ip     = ip_dst,
        action_remote_ip    = ip_src,
        action_remote_port  = nz_port_dst,
        action_local_port   = nz_port_src,
        dns_query_name      = dns_name

// Nozomi-specific extensions
| alter
        nozomi_type_id          = type_id,
        nozomi_type_name        = type_name,
        nozomi_threat_name      = threat_name,
        nozomi_risk             = risk,
        nozomi_is_incident      = is_incident,
        nozomi_trigger_type     = trigger_type,
        nozomi_ti_source        = ti_source,
        nozomi_src_label        = label_src,
        nozomi_dst_label        = label_dst,
        nozomi_src_mac          = mac_src,
        nozomi_dst_mac          = mac_dst,
        nozomi_src_zone         = zone_src,
        nozomi_dst_zone         = zone_dst,
        nozomi_protocol         = coalesce(protocol, transport_protocol),
        nozomi_appliance        = appliance_host,
        nozomi_indicator        = nz_indicator,
        nozomi_malicious_ip     = nz_mal_ip,
        nozomi_solution         = nz_solution,
        nozomi_rule_name        = nz_rule_name,
        nozomi_ics_technique_id = mitre_ics_id

// Tag injection — load-bearing for routing (DS:Nozomi Networks/Guardian →
// ds_nozomi_networks_guardian in SOCProductCategoryMap_V3 → Network).
| alter alert_tags = arraycreate("DS:Nozomi Networks/Guardian", "DOM:Security")
```
