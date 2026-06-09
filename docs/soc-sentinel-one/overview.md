# soc sentinel one — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `soc-sentinel-one` |
| Version | `1.0.0` |
| Category | Endpoint |
| Pack Path | `Packs/soc-sentinel-one` |
| Manifest | [`Packs/soc-sentinel-one/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-sentinel-one/xsoar_config.json) |

## Schemas

Reference documentation for the schemas this pack defines.

- [SentinelOne Singularity (sentinelone)](sentinelone-threat.md)

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [soc-sentinel-one - Manual Steps](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-sentinel-one/POST_CONFIG_README.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `soc-sentinel-one.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-sentinel-one-v1.0.0/soc-sentinel-one-v1.0.0.zip) |

## Marketplace Dependencies

Marketplace packs the installer ensures are present on the tenant.

| ID | Name | Version |
|---|---|---|
| `MarketplacePackId` |  | `latest` |

## Integration Instances

Integration brand instances the installer configures. Credentials and propagation labels are always tenant-specific — only the scaffolding ships in the pack.

| Instance Name | Brand | Category | Enabled |
|---|---|---|---|
| `soc-sentinel-one_instance_1` | `Integration Brand Name` | Category | true |
