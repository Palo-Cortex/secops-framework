# NDR (check-point-ndr) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/checkpoint-ndr/ndr-generic-alerts.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/checkpoint-ndr/ndr-generic-alerts.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `check-point-ndr` |
| product | `NDR` |
| data_source | `checkpointndr_generic_alert_raw` |
| category | `Network` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `insight` | `string` |  | declared |  |
| `type` | `string` |  | declared |  |
| `id` | `string` |  | declared |  |
| `count` | `string` |  | declared |  |
| `probability` | `string` |  | declared |  |
| `filter` | `string` |  | declared |  |
| `from` | `string` |  | declared |  |
| `to` | `string` |  | declared |  |
| `domain` | `string` |  | declared |  |
| `targetdomain` | `string` |  | declared |  |
| `data` | `string` |  | declared |  |
| `externalid` | `string` |  | declared |  |
| `editable` | `string` |  | declared |  |
| `mdr` | `string` |  | declared |  |
| `user` | `string` |  | declared |  |
| `updated` | `string` |  | declared |  |
| `created` | `string` |  | declared |  |
| `_alert_data` | `string` |  | declared |  |

## Modeling Rule — SOC Check Point NDR Modeling Rule

| Field | Value |
|---|---|
| modeling_rule_id | `SOC_CheckPointNDR_ModelingRule` |
| modeling_rule_name | `SOC Check Point NDR Modeling Rule` |
| directory_name | `SOCCheckPointNDRModelingRules` |
| fromversion | `6.10.0` |

### Field Mappings

What each XDM field is, where it sources from, what issue field it surfaces on, and why the mapping is shaped the way it is.

| XDM Path | Expression | Sources | Issue Field | Description |
|---|---|---|---|---|
| `xdm.event.id` | `to_string(id)` | `id` | `originalalertid` |  |
| `xdm.event.type` | `type` | `type` |  |  |
| `xdm.alert.original_alert_id` | `to_string(id)` | `id` |  |  |
| `xdm.alert.name` | `insight` | `insight` | `originalalertname` |  |
| `xdm.alert.description` | `json_extract_scalar(_alert_data, "$.alert_description")` | `_alert_data` | `alert_description` |  |
| `xdm.alert.severity` | `json_extract_scalar(_alert_data, "$.severity")` | `_alert_data` | `severity` | Raw Check Point severity (SEV_0X0_X). The correlation rule's pre_alter does the standard severity-string mapping; this XDM field preserves the raw vendor value for analytics. |
| `xdm.alert.category` | `arrayindex(split(insight, "."), 0)` | `insight` |  | First dot-segment of insight: "Behavioral" / "Threat" / "Reputation" / "Anomaly" — Check Point's top-level alert family. |
| `xdm.alert.subcategory` | `arrayindex(split(insight, "."), 1)` | `insight` |  | Second dot-segment: "Geo" / "Port" / etc. — the analytic dimension within the family. |
| `xdm.source.ipv4` | `arrayindex(json_extract_array(_alert_data, "$.sourceips"), 0)` | `_alert_data` | `action_remote_ip` |  |
| `xdm.target.ipv4` | `arrayindex(json_extract_array(_alert_data, "$.destinationips"), 0)` | `_alert_data` | `action_local_ip` |  |
| `xdm.target.port` | `to_integer(arrayindex(json_extract_array(_alert_data, "$.dstports"), 0))` | `_alert_data` | `action_remote_port` |  |

### Contributes (Artifacts.*)

Fields populated for downstream lifecycle Artifacts schemas:

- `Network.RemoteIP`
- `Network.LocalIP`
- `Network.RemotePort`

## Correlation Rules

### SOC CheckPoint NDR - Behavioral Alerts

| Field | Value |
|---|---|
| global_rule_id | `SOC CheckPoint NDR - Behavioral Alerts` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Reshapes Check Point NDR Behavioral alerts (from checkpointndr_generic_alert_raw) into properly-formed XSIAM alerts. Replaces the OEM-default rule, which produced empty alert_fields and missing DS tags, causing SOC Framework playbooks to hang on unclassified alerts. Extracts source/destination IPs, derives category from the insight prefix, maps Check Point's SEV_0X0_X severity ladder to XSIAM severity, and injects DS:Check Point/NDR and DOM:Security tags so Foundation Product Classification routes the alert into the Network category.

**Tags:** `SOCFramework`, `Passthrough`, `Network`, `Check Point`

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| action | `ALERTS` |
| execution_mode | `REAL_TIME` |
| mapping_strategy | `CUSTOM` |
| user_defined_category | `cp_category` |
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

originalalertid sources from the dataset's `id` column —
Check Point NDR's per-alert unique identifier. Hourly
suppression handles cases where the same alert re-fires
on subsequent polling cycles before being closed.

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
| `externalconfidence` | `originalalertconfidence` | `computed` |  |
| `checkpoint_protection` | `checkpoint_protection` | `computed` |  |
| `checkpoint_subcategory` | `checkpoint_subcategory` | `computed` |  |
| `checkpoint_bytes_sent` | `checkpoint_bytes_sent` | `computed` |  |
| `tags` | `alert_tags` | `computed` |  |

#### Pre-Alter XQL

```xql
// Vendor / product (required for SOCProductCategoryMap routing)
| alter vendor_name = "Check Point", product_name = "NDR"

// Scope to Behavioral.* insights. Other top-level types
// (Threat.*, Reputation.*, Anomaly.*) get their own rule entries
// with matching filters when samples appear.
| filter type = "Behavioral"

// Top-level columns are already parsed — rename for readability.
// `from` / `to` are XQL keywords; backtick-quote when referencing.
| alter
        cp_insight     = insight,
        cp_type        = type,
        cp_id          = id,
        cp_filter      = `filter`,
        cp_probability = to_integer(probability),
        cp_domain      = domain

// Extract scalar fields from the _alert_data payload
| alter
        alert_name_raw          = json_extract_scalar(_alert_data, "$.alert_name"),
        alert_description_raw   = json_extract_scalar(_alert_data, "$.alert_description"),
        severity_raw            = json_extract_scalar(_alert_data, "$.severity"),
        alert_action_status     = json_extract_scalar(_alert_data, "$.alert_action_status"),
        external_link           = json_extract_scalar(_alert_data, "$.externallink"),
        cp_alert_source         = json_extract_scalar(_alert_data, "$.alert_source"),
        bytes_sent              = to_integer(json_extract_scalar(_alert_data, "$.sentbytes")),
        bytes_received          = to_integer(json_extract_scalar(_alert_data, "$.receivedbytes"))

// Extract IP / port arrays from _alert_data; first element is the
// actionable IOC. For inbound NDR alerts (Behavioral.Geo, Behavioral.Port):
//   sourceips[0]      = external attacker  → action_remote_ip
//   destinationips[0] = target / asset     → action_local_ip
| alter
        source_ips    = json_extract_array(_alert_data, "$.sourceips"),
        dest_ips      = json_extract_array(_alert_data, "$.destinationips"),
        dst_ports_arr = json_extract_array(_alert_data, "$.dstports")

| alter
        src_ip   = arrayindex(source_ips, 0),
        dst_ip   = arrayindex(dest_ips, 0),
        dst_port = arrayindex(dst_ports_arr, 0)

// Extract enrichment from data.statistics. top_protection_name may
// be empty for Behavioral subtypes that don't have a Threat
// Prevention signature association (e.g. Behavioral.Geo.*).
| alter
        protection_name  = arrayindex(json_extract_array(data, "$.statistics.top_protection_name"), 0),
        total_src_count  = to_integer(json_extract_scalar(data, "$.statistics.total_src")),
        total_dst_count  = to_integer(json_extract_scalar(data, "$.statistics.total_dst"))

// Severity mapping: Check Point SEV_0X0_X → XSIAM standard.
// Today only SEV_020_LOW and SEV_030_MEDIUM observed in this PoV;
// full ladder included for resilience.
| alter severity = if(
        severity_raw = "SEV_050_CRITICAL", "Critical",
        severity_raw = "SEV_040_HIGH",     "High",
        severity_raw = "SEV_030_MEDIUM",   "Medium",
        severity_raw = "SEV_020_LOW",      "Low",
        severity_raw = "SEV_010_INFO",     "Informational",
        "Low"
    )

// Category derivation from the insight string structure.
//   Behavioral.Geo.Mexico        → cp_category=Behavioral, cp_subcategory=Geo
//   Behavioral.Port.11211.InnoDB → cp_category=Behavioral, cp_subcategory=Port
| alter
        cp_category    = arrayindex(split(cp_insight, "."), 0),
        cp_subcategory = arrayindex(split(cp_insight, "."), 1)

// Default category fallback when insight is empty or malformed
| alter cp_category = coalesce(cp_category, "Network")

// MITRE — empty for Behavioral alerts. Columns must exist for the
// four MITRE alert_fields entries required by the passthrough
// subtype validator.
| alter
        mitretacticid       = null,
        mitretacticname     = null,
        mitretechniqueid    = null,
        mitretechniquename  = null

// Build readable alert name following the Falcon / ProofPoint
// pattern: [Category] {actor} - {phase}: {detail}.
//
// For NDR alerts, the "actor" is the source→destination connection
// (visible directionality at a glance), the "phase" is Check Point's
// analytic dimension (Geo / Port / etc. — second insight segment),
// and the "detail" is the Threat Prevention signature name when
// associated, falling back to the full insight string when not.
//
//   Behavioral.Geo.Mexico (no protection_name):
//     [Network] 177.245.208.115 → 198.140.5.229 - Geo: Behavioral.Geo.Mexico
//
//   Behavioral.Port.11211.InnoDB (with protection_name):
//     [Network] 65.49.1.94 → 192.189.186.36 - Port: Memcached Web-Servers Network Flood Denial of Service
| alter alert_name = concat(
        "[Network] ",
        coalesce(src_ip, "Unknown"),
        " → ",
        coalesce(dst_ip, "Unknown"),
        " - ",
        coalesce(cp_subcategory, "Behavioral"),
        ": ",
        coalesce(protection_name, cp_insight, "Anomaly")
    )

// Build alert description: Check Point's original text (preserved
// for analyst context — note that it sometimes references different
// IPs than sourceips/destinationips because it describes the
// originating behavioral pattern while the alert is a narrowed
// slice per the filter expression) plus a piped fact-list of the
// actionable IOCs and key metadata. Pattern matches Falcon's
// description format.
| alter alert_description = concat(
        coalesce(alert_description_raw, "Check Point NDR Behavioral alert"),
        " | Source: ",       coalesce(src_ip,                     "Unknown"),
        " | Destination: ",  coalesce(dst_ip,                     "Unknown"),
        " | Port: ",         coalesce(to_string(dst_port),        "Unknown"),
        " | Severity: ",     coalesce(severity,                   "Unknown"),
        " | Confidence: ",   coalesce(to_string(cp_probability),  "0"),
        " | Bytes Sent: ",   coalesce(to_string(bytes_sent),      "0")
    )

// ============================================================
// CANONICAL CORE NORMALIZATION
// Endpoint-shaped columns (agent_*, actor_*, parent_process_*)
// stay null for network alerts. Network-shaped columns drive
// Foundation_-_Normalize_Network_V3.
// ============================================================
| alter
        vendor              = vendor_name,
        product             = product_name,
        originalalertid     = cp_id,
        originalalertname   = cp_insight,
        originalalertsource = "Check Point - NDR",
        externallink        = external_link,
        alert_description   = alert_description,
        severity            = severity,
        action_local_ip     = dst_ip,
        action_remote_ip    = src_ip,
        action_remote_port  = dst_port

// Check Point NDR-specific extensions preserved for analyst
// context and downstream enrichment.
| alter
        originalalertconfidence = cp_probability,
        originalalertfilter     = cp_filter,
        checkpoint_protection   = protection_name,
        checkpoint_subcategory  = cp_subcategory,
        checkpoint_total_src    = total_src_count,
        checkpoint_total_dst    = total_dst_count,
        checkpoint_bytes_sent   = bytes_sent

// Tag injection — load-bearing for routing.
// Foundation Product Classification reads issue.tags, filters for
// entries containing DS:, lowercases and normalizes non-alnum
// characters to underscore. "DS:Check Point/NDR" becomes
// ds_check_point_ndr, which keys into SOCProductCategoryMap_V3
// → category: Network. Without this, downstream Workflow routing
// has no category to dispatch to and the playbook stalls.
| alter alert_tags = arraycreate("DS:Check Point/NDR", "DOM:Security")
```
