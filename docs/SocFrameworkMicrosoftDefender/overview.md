# SOC Microsoft Defender for Endpoint Integration Enhancement — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `SocFrameworkMicrosoftDefender` |
| Version | `1.2.8` |
| Category | End Point |
| Pack Path | `Packs/SocFrameworkMicrosoftDefender` |
| Manifest | [`Packs/SocFrameworkMicrosoftDefender/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/SocFrameworkMicrosoftDefender/xsoar_config.json) |

## Schemas

Reference documentation for the schemas this pack defines.

- [Microsoft Defender for Endpoint (microsoft-defender)](microsoft-defender-alerts.md)

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [SOC Microsoft Defender EP - Manual Steps](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/SocFrameworkMicrosoftDefender/POST_CONFIG_README.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `SocFrameworkMicrosoftDefender.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/SocFrameworkMicrosoftDefender-v1.2.8/SocFrameworkMicrosoftDefender-v1.2.8.zip) |

## Marketplace Dependencies

Marketplace packs the installer ensures are present on the tenant.

| ID | Name | Version |
|---|---|---|
| `MicrosoftDefenderAdvancedThreatProtection` | Microsoft Defender Advanced Threat Protection | `latest` |

## Integration Instances

Integration brand instances the installer configures. Credentials and propagation labels are always tenant-specific — only the scaffolding ships in the pack.

| Instance Name | Brand | Category | Enabled |
|---|---|---|---|
| `Microsoft_Graph_Security_Alerts` | `Microsoft Graph` | Endpoint | false |
| `Microsoft_Defender_ATP_Commands` | `Microsoft Defender Advanced Threat Protection` | Endpoint | false |
