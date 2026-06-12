# Wiz Cloud (wiz) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/wiz-cloud/wiz-finding.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/wiz-cloud/wiz-finding.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `wiz` |
| product | `Wiz Cloud` |
| data_source | `wiz_generic_alert_raw` |
| category | `Cloud` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `_alert_data` | `string` |  | declared |  |
| `entitysnapshot` | `string` |  | declared |  |
| `sourcerule` | `string` |  | declared |  |
| `severity` | `string` |  | declared |  |
| `status` | `string` |  | declared |  |
| `type` | `string` |  | declared |  |

## Modeling Rule — Wiz Findings Modeling Rule

| Field | Value |
|---|---|
| modeling_rule_id | `Wiz_ModelingRule` |
| modeling_rule_name | `Wiz Findings Modeling Rule` |
| directory_name | `Wiz_ModelingRule` |
| fromversion | `6.10.0` |

### Field Mappings

What each XDM field is, where it sources from, what issue field it surfaces on, and why the mapping is shaped the way it is.

| XDM Path | Expression | Sources | Issue Field | Description |
|---|---|---|---|---|
| `xdm.event.type` | `type` | `type` | `eventtype` |  |
| `xdm.alert.name` | `json_extract_scalar(sourcerule, "$.name")` | `sourcerule` | `alertname` |  |
| `xdm.alert.description` | `json_extract_scalar(sourcerule, "$.description")` | `sourcerule` | `eventdescription` |  |
| `xdm.alert.severity` | `severity` | `severity` | `severity` |  |
| `xdm.alert.category` | `type` | `type` | `alertcategory` |  |
| `xdm.alert.original_alert_id` | `json_extract_scalar(sourcerule, "$.id")` | `sourcerule` | `originalalertid` |  |
| `xdm.observer.vendor` | `"Wiz"` |  | `observervendor` |  |
| `xdm.observer.product` | `"Wiz Cloud"` |  | `observerproduct` |  |

### Contributes (Artifacts.*)

Fields populated for downstream lifecycle Artifacts schemas:

- `Event.Type`
- `Alert.Name`
- `Alert.Description`
- `Alert.Severity`
- `Alert.Category`
- `Alert.OriginalID`
- `Vendor`
- `Product`

## Correlation Rules

### SOC Wiz Finding

| Field | Value |
|---|---|
| global_rule_id | `SOC Wiz Finding` |
| subtype | `passthrough` |
| fromversion | `8.0.0` |

Creates an XSIAM passthrough alert for each Wiz finding, normalized to the SOC Framework Cloud-category contract and routed through NIST IR.

**Tags:** `SOCFramework`, `Passthrough`, `Cloud`, `Wiz`

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| action | `ALERTS` |
| execution_mode | `REAL_TIME` |
| mapping_strategy | `CUSTOM` |
| user_defined_category | `finding_type` |
| user_defined_severity | `severity` |
| is_enabled | `✓` |
| drilldown_query_timeframe | `ALERT` |
| severity | `User Defined` |

#### Suppression

| Field | Value |
|---|---|
| enabled | `✓` |
| duration | `1 hours` |
| fields | `finding_id` |

Wiz Control id (wc-id-…) scopes dedup to a single finding.

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
| `agent_hostname` | `agent_hostname` | `computed` |  |
| `hostname` | `agent_hostname` | `computed` |  |
| `cloudprovider` | `cloud_provider` | `computed` |  |
| `cloudaccount` | `cloud_account` | `computed` |  |
| `cloudregion` | `cloud_region` | `computed` |  |
| `resourcename` | `resource_name` | `computed` |  |
| `resourcetype` | `resource_type` | `computed` |  |
| `resourceid` | `resource_id` | `computed` |  |
| `alertcategory` | `finding_type` | `computed` |  |
| `findingstatus` | `finding_status` | `computed` |  |
| `recommendation` | `recommendation` | `computed` |  |

#### Pre-Alter XQL

```xql
| filter _alert_data != null
| alter
    vendor_name  = "Wiz",
    product_name = "Wiz Cloud",
    severity = lowercase(severity),
    finding_type   = type,
    finding_status = status,
    finding_id     = json_extract_scalar(sourcerule, "$.id"),
    finding_name   = json_extract_scalar(sourcerule, "$.name"),
    alert_description = coalesce(
        json_extract_scalar(sourcerule, "$.description"),
        json_extract_scalar(to_json_string(_alert_data), "$.alert_description")),
    recommendation = json_extract_scalar(sourcerule, "$.resolutionRecommendation"),
    cloud_provider = json_extract_scalar(entitysnapshot, "$.cloudPlatform"),
    cloud_account  = coalesce(
        json_extract_scalar(entitysnapshot, "$.subscriptionExternalId"),
        json_extract_scalar(entitysnapshot, "$.subscriptionName")),
    cloud_region   = json_extract_scalar(entitysnapshot, "$.region"),
    resource_name  = json_extract_scalar(entitysnapshot, "$.name"),
    resource_type  = coalesce(
        json_extract_scalar(entitysnapshot, "$.nativeType"),
        json_extract_scalar(entitysnapshot, "$.type")),
    resource_id    = coalesce(
        json_extract_scalar(entitysnapshot, "$.externalId"),
        json_extract_scalar(entitysnapshot, "$.id"))
// Conditional hostname pivot: when the resource is a compute
// instance, resource_name is the VM hostname -- a posture finding then
// groups with EDR runtime detections on the same host. Null for non-compute
// (buckets, IAM) so no junk pivots. DELIBERATELY the only grouping field:
// posture findings must not be aggressively glued into IR cases.
// Heuristic regex over nativeType -- tighten to exact tenant values via:
//   dataset = wiz_generic_alert_raw | alter rt = coalesce(...nativeType, ...type) | comp count() by rt
| alter agent_hostname = if(
    lowercase(coalesce(resource_type, "")) ~= "virtualmachine|instance|vm|compute|ec2",
    resource_name, null)
| alter
    originalalertid     = finding_id,
    originalalertname   = finding_name,
    alert_name = concat(
        "[Cloud] ",
        coalesce(cloud_provider, "Cloud"), " | ",
        coalesce(resource_type, "Resource"), " | ",
        coalesce(finding_name, "Finding"))
```
