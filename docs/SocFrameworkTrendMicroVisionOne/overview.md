# SOC Trend Micro Enhancement for Cortex XSIAM — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `SocFrameworkTrendMicroVisionOne` |
| Version | `1.1.3` |
| Category | End Point |
| Pack Path | `Packs/SocFrameworkTrendMicroVisionOne` |
| Manifest | [`Packs/SocFrameworkTrendMicroVisionOne/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/SocFrameworkTrendMicroVisionOne/xsoar_config.json) |

## Schemas

Reference documentation for the schemas this pack defines.

- [Vision One (trend-vision-one)](trend-micro-vision-one-v3.md)

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [SOC Trend Micro Vision One Enhancement - Manual Steps](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/SocFrameworkTrendMicroVisionOne/POST_CONFIG_README.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `SocFrameworkTrendMicroVisionOne.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/SocFrameworkTrendMicroVisionOne-v1.1.3/SocFrameworkTrendMicroVisionOne-v1.1.3.zip) |

## Marketplace Dependencies

Marketplace packs the installer ensures are present on the tenant.

| ID | Name | Version |
|---|---|---|
| `TrendMicroVisionOne` |  | `latest` |

## Integration Instances

Integration brand instances the installer configures. Credentials and propagation labels are always tenant-specific — only the scaffolding ships in the pack.

| Instance Name | Brand | Category | Enabled |
|---|---|---|---|
| `Trend Micro Vision One V3_instance_1` | `Trend Micro Vision One V3` | Data Enrichment & Threat Intelligence | true |
