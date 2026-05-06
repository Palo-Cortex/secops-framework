# SOC Check Point NDR Integration Enhancement

Enhancements for **Check Point NDR** (Network Detection & Response) telemetry used by the SOC Framework on Cortex XSIAM.

## What this pack provides

Replaces the OEM-default correlation rule that ships with the Check Point NDR integration. The default rule produced alerts with empty `alert_fields`, no source-data tags, and a broken severity mapping — causing SOC Framework playbooks to hang on unclassified alerts because Foundation Product Classification had no `DS:` tag to match against.

This pack ships one correlation rule:

- **SOC CheckPoint NDR - Behavioral Alerts** — Reads `checkpointndr_generic_alert_raw`, extracts source/destination IPs from the `_alert_data` payload, maps Check Point's `SEV_0X0_X` severity ladder to XSIAM standard severities, derives alert category from the `insight` prefix (e.g., `Behavioral.Geo.Mexico` → category `Behavioral`), and injects `DS:Check Point/NDR` and `DOM:Security` tags so the alert routes cleanly into the SOC Framework's Network category.

## Dependencies

- `soc-optimization-unified` — The corresponding `ds_check_point_ndr` entry must be present in `SOCProductCategoryMap_V3` for Network-category routing to work. That list update ships with this pack as a sibling change.
- Check Point NDR integration installed and configured on the tenant. The dataset `checkpointndr_generic_alert_raw` must be receiving events.

## Routing

Alerts produced by this rule carry:
- `tags: ["DS:Check Point/NDR", "DOM:Security"]`
- `originalalertsource: "Check Point - NDR"`
- `vendor: "Check Point"`, `product: "NDR"`

Foundation Product Classification normalizes `DS:Check Point/NDR` → `ds_check_point_ndr`, which keys into `SOCProductCategoryMap_V3` to set `SOCFramework.Product.category = Network`. Downstream the alert dispatches into `SOC NIST IR (800-61)_V3 → SOC Network Analysis_V3`.

## Severity mapping

| Check Point | XSIAM |
|---|---|
| `SEV_010_INFO` | Informational |
| `SEV_020_LOW` | Low |
| `SEV_030_MEDIUM` | Medium |
| `SEV_040_HIGH` | High |
| `SEV_050_CRITICAL` | Critical |

Today only Low and Medium are observed in PoV traffic; full ladder included for resilience.

## Behavioral alert subtypes covered

The rule handles all `Behavioral.*` insight types observed:

- `Behavioral.Geo.<Country>` — geo-anomaly detections (no `top_protection_name`)
- `Behavioral.Port.<Port>.<Service>` — port-anomaly detections (`top_protection_name` populated when a Threat Prevention signature matches)

If `Threat.*`, `Reputation.*`, or other top-level `insight` types appear later, add additional rule entries to `schemas/vendors/checkpoint-ndr/ndr-generic-alerts.yaml` and regenerate.

## Field semantics — source vs. destination

Inbound NDR alerts (which is all we've observed for Behavioral) follow perimeter-IPS conventions:

- `sourceips[0]` = external attacker → mapped to `action_remote_ip` (the IP the SOC Framework will block in Containment)
- `destinationips[0]` = target / internal asset → mapped to `action_local_ip`

This is intentionally inverse of Endpoint-source alerts where `action_local_ip` is the agent host. Foundation_-_Normalize_Network_V3 reads these consistently.

## Known caveat — alert description vs. structured IPs

The Check Point NDR alert description text occasionally references different IPs than the `sourceips` / `destinationips` fields, because the description describes the *originating behavioral pattern* while the alert is a narrowed slice (per the `filter` expression). The structured IPs are the actionable IOCs; the description is preserved as analyst context but should not be parsed for IPs to act on.
