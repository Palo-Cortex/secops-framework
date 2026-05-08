# SOC Proofpoint TAP Integration Enhancement for Cortex XSIAM2 — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `SocFrameworkProofPointTap` |
| Version | `1.4.2` |
| Category | Forensics & Malware Analysis |
| Pack Path | `Packs/SocFrameworkProofPointTap` |
| Manifest | [`Packs/SocFrameworkProofPointTap/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/SocFrameworkProofPointTap/xsoar_config.json) |

## Schemas

Reference documentation for the schemas this pack defines.

- [TAP (proofpoint-tap)](proofpoint-tap-threats.md)

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [SOC Proofpoint TAP - Manual Steps](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/SocFrameworkProofPointTap/POST_CONFIG_README.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `SocFrameworkProofPointTap.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/SocFrameworkProofPointTap-v1.4.2/SocFrameworkProofPointTap-v1.4.2.zip) |

## Marketplace Dependencies

Marketplace packs the installer ensures are present on the tenant.

| ID | Name | Version |
|---|---|---|
| `ProofpointTAP` | Proofpoint TAP | `latest` |

## Integration Instances

Integration brand instances the installer configures. Credentials and propagation labels are always tenant-specific — only the scaffolding ships in the pack.

| Instance Name | Brand | Category | Enabled |
|---|---|---|---|
| `Proofpoint TAP v2` | `Proofpoint TAP v2` | Email | false |
