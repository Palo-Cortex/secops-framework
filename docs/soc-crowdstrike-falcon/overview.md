# SOC CrowdStrike Falcon Integration Enhancement for Cortex XSIAM2 — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `soc-crowdstrike-falcon` |
| Version | `1.1.12` |
| Category | Endpoint |
| Pack Path | `Packs/soc-crowdstrike-falcon` |
| Manifest | [`Packs/soc-crowdstrike-falcon/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-crowdstrike-falcon/xsoar_config.json) |

## Schemas

Reference documentation for the schemas this pack defines.

- [Falcon (crowdstrike-falcon)](falcon-detections.md)

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [SOC Crowdstrike Falcon Enhancement - Manual Steps](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-crowdstrike-falcon/POST_CONFIG_README.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `soc-crowdstrike-falcon.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-crowdstrike-falcon-v1.1.12/soc-crowdstrike-falcon-v1.1.12.zip) |

## Marketplace Dependencies

Marketplace packs the installer ensures are present on the tenant.

| ID | Name | Version |
|---|---|---|
| `CrowdStrikeFalcon` | CrowdStrike Falcon | `latest` |

## Integration Instances

Integration brand instances the installer configures. Credentials and propagation labels are always tenant-specific — only the scaffolding ships in the pack.

| Instance Name | Brand | Category | Enabled |
|---|---|---|---|
| `CrowdstrikeFalcon_Detections_Incidents` | `CrowdStrikeFalcon` | Endpoint | false |
