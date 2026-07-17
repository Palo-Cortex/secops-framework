# Cortex Xpanse (cortex-xpanse) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/cortex-xpanse/cortex-xpanse-posture.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/cortex-xpanse/cortex-xpanse-posture.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `cortex-xpanse` |
| product | `Cortex Xpanse` |
| data_source | `issues` |
| category | `Posture` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `xdm.issue.id` | `string` |  | declared |  |
| `xdm.issue.external_id` | `string` |  | declared |  |
| `xdm.issue.name` | `string` |  | declared |  |
| `xdm.issue.description` | `string` |  | declared |  |
| `xdm.issue.severity` | `string` |  | declared |  |
| `xdm.issue.platform_severity` | `string` |  | declared |  |
| `xdm.issue.status.progress` | `string` |  | declared |  |
| `xdm.issue.domain` | `string` |  | declared |  |
| `xdm.issue.category` | `string` |  | declared |  |
| `xdm.issue.type` | `string` |  | declared |  |
| `xdm.issue.detection.method` | `string` |  | declared |  |
| `xdm.issue.detection.rule_id` | `string` |  | declared |  |
| `xdm.issue.observation_time` | `datetime` |  | declared |  |
| `xdm.issue.last_modified` | `datetime` |  | declared |  |
| `xdm.issue.asset_ids` | `string` | ✓ | declared |  |
| `xdm.issue.normalized_fields` | `string` |  | declared |  |
| `xdm.issue.extended_fields` | `string` |  | declared |  |
| `xdm.issue.remediation` | `string` |  | declared |  |
| `xdm.issue.impact` | `string` |  | declared |  |
| `original_tags` | `string` | ✓ | declared |  |

## Modeling Rule — Cortex Xpanse Issue Modeling Rule

| Field | Value |
|---|---|
| modeling_rule_id | `CortexXpanse_ModelingRule` |
| modeling_rule_name | `Cortex Xpanse Issue Modeling Rule` |
| directory_name | `CortexXpanse_ModelingRule` |
| fromversion | `6.10.0` |

### Field Mappings

What each XDM field is, where it sources from, what issue field it surfaces on, and why the mapping is shaped the way it is.

| XDM Path | Expression | Sources | Issue Field | Description |
|---|---|---|---|---|
| `xdm.alert.original_alert_id` | `xdm.issue.id` | `xdm.issue.id` | `originalalertid` |  |
| `xdm.alert.severity` | `xdm.issue.severity` | `xdm.issue.severity` | `severity` |  |

### Contributes (Artifacts.*)

Fields populated for downstream lifecycle Artifacts schemas:

- `Alert.OriginalID`
- `Alert.Severity`

## Correlation Rules

### SOC Cortex Xpanse Posture Finding

| Field | Value |
|---|---|
| global_rule_id | `SOC Cortex Xpanse Posture Finding` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Creates an XSIAM passthrough alert for each Cortex Xpanse attack-surface issue, normalized to the SOC Framework Posture lifecycle contract. Routes via SOCProductCategoryMap_V3 (ds_panw_asm: Posture) to the Posture category, dispatching through EP_Posture -> SOC_Posture -> SOC_Misconfig_{Identify,Plan,Execute,Verify} phase playbooks. The lifecycle's Identify-phase context (Identify.finding_acknowledged, Identify.misconfig_summary) is set by SOC_Misconfig_Identify at execution time via its Set tasks - not preloaded on this alert.

**Tags:** `SOCFramework`, `Passthrough`, `Posture`, `Cortex Xpanse`

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| action | `ALERTS` |
| execution_mode | `REAL_TIME` |
| mapping_strategy | `CUSTOM` |
| user_defined_category | `issue_type` |
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

xdm.issue.id is unique per Cortex Xpanse issue and stable across
re-scans until remediation.

#### Alert Fields

Issue-field assignments emitted by the correlation rule. The Description column captures intent — when present, this is what downstream playbooks rely on the field meaning.

| Issue Field | Source | Bucket | Description |
|---|---|---|---|
| `vendor` | `vendor_name` | `computed` |  |
| `product` | `product_name` | `computed` |  |
| `severity` | `severity` | `computed` |  |
| `alert_description` | `alert_description` | `computed` |  |
| `originalalertid` | `originalalertid` | `computed` |  |
| `originalalertname` | `originalalertname` | `computed` |  |
| `alert_name` | `alert_name` | `computed` |  |
| `alertcategory` | `issue_type` | `computed` |  |
| `recommendation` | `remediation` | `computed` |  |
| `impact` | `impact` | `computed` |  |

#### Pre-Alter XQL

```xql
| filter xdm.issue.detection.method = "XPANSE"
| alter
    vendor_name  = "Palo Alto Networks",
    product_name = "Cortex Xpanse",
    severity     = lowercase(xdm.issue.severity),
    finding_id   = xdm.issue.id,
    finding_name = xdm.issue.name,
    finding_description = xdm.issue.description,
    issue_type     = coalesce(xdm.issue.detection.rule_id, "Unclassified"),
    issue_category = xdm.issue.category,
    issue_status   = xdm.issue.status.progress,
    remediation    = xdm.issue.remediation,
    impact         = xdm.issue.impact,
    asset_id_primary = arrayindex(xdm.issue.asset_ids, 0)
// Bracket-quote JSONPath syntax required - the keys inside
// xdm.issue.normalized_fields are LITERAL dotted strings
// (e.g., "xdm.target.host.ipv4_addresses"), not nested objects.
// Verified in tenant: '$.xdm.target.host.ipv4_addresses[0]' returns
// null; "$['xdm.target.host.ipv4_addresses'][0]" returns the IP.
| alter
    target_ipv4_raw = json_extract_scalar(xdm.issue.normalized_fields, "$['xdm.target.host.ipv4_addresses'][0]"),
    target_country  = json_extract_scalar(xdm.issue.normalized_fields, "$['xdm.source.location.country'][0]")
// Identify-phase context (Identify.finding_acknowledged,
// Identify.misconfig_summary) is populated by SOC_Misconfig_Identify
// at execution time via its Set tasks. Not preloaded on the alert -
// those are playbook context keys, not alert fields.
| alter
    originalalertid   = finding_id,
    originalalertname = finding_name,
    alert_name = concat("[Posture] Cortex Xpanse | ", coalesce(issue_type, "Finding"), " | ", coalesce(finding_name, "Unspecified target")),
    alert_description = coalesce(finding_description, "Cortex Xpanse attack-surface posture finding")
```
