# SOC Nozomi Networks Guardian — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `soc-nozomi-guardian` |
| Version | `1.1.2` |
| Category | Network Security |
| Pack Path | `Packs/soc-nozomi-guardian` |
| Manifest | [`Packs/soc-nozomi-guardian/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-nozomi-guardian/xsoar_config.json) |

## Schemas

Reference documentation for the schemas this pack defines.

- [Guardian (nozomi-networks)](nozomi-guardian-alerts.md)

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [soc-nozomi-guardian - Manual Steps](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-nozomi-guardian/POST_CONFIG_README.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `soc-nozomi-guardian.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-nozomi-guardian-v1.1.2/soc-nozomi-guardian-v1.1.2.zip) |

## Marketplace Dependencies

Marketplace packs the installer ensures are present on the tenant.

| ID | Name | Version |
|---|---|---|
| `MarketplacePackId` |  | `latest` |

## Integration Instances

Integration brand instances the installer configures. Credentials and propagation labels are always tenant-specific — only the scaffolding ships in the pack.

| Instance Name | Brand | Category | Enabled |
|---|---|---|---|
| `soc-nozomi-guardian_instance_1` | `Integration Brand Name` | Category | true |
