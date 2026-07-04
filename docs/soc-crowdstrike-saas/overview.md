# SOC CrowdStrike Falcon SaaS Integration Enhancement for Cortex XSIAM — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `soc-crowdstrike-saas` |
| Version | `1.0.0` |
| Category | Cloud IR |
| Pack Path | `Packs/soc-crowdstrike-saas` |
| Manifest | [`Packs/soc-crowdstrike-saas/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-crowdstrike-saas/xsoar_config.json) |

## Schemas

Reference documentation for the schemas this pack defines.

- [Falcon SaaS (crowdstrike-saas)](crowdstrike-saas.md)

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [SOC CrowdStrike Falcon SaaS - Manual Steps](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-crowdstrike-saas/POST_CONFIG_README.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `soc-crowdstrike-saas.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-crowdstrike-saas-v1.0.0/soc-crowdstrike-saas-v1.0.0.zip) |

## Marketplace Dependencies

Marketplace packs the installer ensures are present on the tenant.

| ID | Name | Version |
|---|---|---|
| `MarketplacePackId` |  | `latest` |

## Integration Instances

Integration brand instances the installer configures. Credentials and propagation labels are always tenant-specific — only the scaffolding ships in the pack.

| Instance Name | Brand | Category | Enabled |
|---|---|---|---|
| `soc-crowdstrike-saas_instance_1` | `Integration Brand Name` | Category | true |
