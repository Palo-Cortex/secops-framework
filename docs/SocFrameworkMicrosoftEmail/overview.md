# SOC Microsoft Defender for Office 365 Integration Enhancement — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `SocFrameworkMicrosoftEmail` |
| Version | `1.0.5` |
| Category | Email Security |
| Pack Path | `Packs/SocFrameworkMicrosoftEmail` |
| Manifest | [`Packs/SocFrameworkMicrosoftEmail/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/SocFrameworkMicrosoftEmail/xsoar_config.json) |

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `soc-microsoft-defender-email.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-microsoft-defender-email-v1.0.0/soc-microsoft-defender-email-v1.0.0.zip) |

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
