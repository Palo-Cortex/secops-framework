# SOC Darktrace Email — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `soc-darktrace-email` |
| Version | `1.1.0` |
| Category | Email Security |
| Pack Path | `Packs/soc-darktrace-email` |
| Manifest | [`Packs/soc-darktrace-email/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-darktrace-email/xsoar_config.json) |

## Schemas

Reference documentation for the schemas this pack defines.

- [Darktrace Email (darktrace-email)](darktrace-email.md)

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [soc-darktrace-email - Manual Steps](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-darktrace-email/POST_CONFIG_README.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `soc-darktrace-email.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-darktrace-email-v1.1.0/soc-darktrace-email-v1.1.0.zip) |

## Marketplace Dependencies

Marketplace packs the installer ensures are present on the tenant.

| ID | Name | Version |
|---|---|---|
| `MarketplacePackId` |  | `latest` |

## Integration Instances

Integration brand instances the installer configures. Credentials and propagation labels are always tenant-specific — only the scaffolding ships in the pack.

| Instance Name | Brand | Category | Enabled |
|---|---|---|---|
| `soc-darktrace-email_instance_1` | `Integration Brand Name` | Category | true |
