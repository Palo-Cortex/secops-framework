# SOC Framework Posture Lifecycle — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `soc-framework-posture` |
| Version | `1.0.1` |
| Category | Utilities |
| Pack Path | `Packs/soc-framework-posture` |
| Manifest | [`Packs/soc-framework-posture/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-framework-posture/xsoar_config.json) |

## Schemas

Reference documentation for the schemas this pack defines.

- [SOCFrameworkDedupContract_POSTURE](SOCFrameworkDedupContract_POSTURE.md)
- [SOCFrameworkEnrichmentMap_POSTURE](SOCFrameworkEnrichmentMap_POSTURE.md)
- [SOCFrameworkNormalizeMap_POSTURE](SOCFrameworkNormalizeMap_POSTURE.md)
- [SOCFrameworkPhaseContract_POSTURE](SOCFrameworkPhaseContract_POSTURE.md)

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [SOC Framework Posture Lifecycle - Manual Steps](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-framework-posture/POST_CONFIG_README.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `soc-framework-posture.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-framework-posture-v1.0.1/soc-framework-posture-v1.0.1.zip) |

## Integration Instances

Integration brand instances the installer configures. Credentials and propagation labels are always tenant-specific — only the scaffolding ships in the pack.

| Instance Name | Brand | Category | Enabled |
|---|---|---|---|
| `socfw_posture_execution` | `System XQL HTTP Collector` | Utilities | true |

## Exported Playbooks

Playbooks this pack exposes for use by other packs or directly from the tenant.

- `EP_Posture`
