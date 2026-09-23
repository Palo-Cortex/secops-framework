# SOC Darktrace NDR — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `soc-darktrace-ndr` |
| Version | `1.0.0` |
| Category | Network Security |
| Pack Path | `Packs/soc-darktrace-ndr` |
| Manifest | [`Packs/soc-darktrace-ndr/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-darktrace-ndr/xsoar_config.json) |

## Schemas

Reference documentation for the schemas this pack defines.

- [Darktrace (darktrace)](darktrace-model-breaches.md)

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [soc-darktrace-ndr - Manual Steps](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-darktrace-ndr/POST_CONFIG_README.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `soc-darktrace-ndr.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-darktrace-ndr-v1.0.0/soc-darktrace-ndr-v1.0.0.zip) |

## Marketplace Dependencies

Marketplace packs the installer ensures are present on the tenant.

| ID | Name | Version |
|---|---|---|
| `MarketplacePackId` |  | `latest` |

## Integration Instances

Integration brand instances the installer configures. Credentials and propagation labels are always tenant-specific — only the scaffolding ships in the pack.

| Instance Name | Brand | Category | Enabled |
|---|---|---|---|
| `soc-darktrace-ndr_instance_1` | `Integration Brand Name` | Category | true |
