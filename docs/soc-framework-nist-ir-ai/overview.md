# SOC Framework NIST IR (800-61) - AI Analysis — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `soc-framework-nist-ir-ai` |
| Version | `1.0.1` |
| Category | Utilities |
| Pack Path | `Packs/soc-framework-nist-ir-ai` |
| Manifest | [`Packs/soc-framework-nist-ir-ai/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-framework-nist-ir-ai/xsoar_config.json) |

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [SOC Framework NIST IR - AI Analysis - Install & Settings](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-framework-nist-ir-ai/README.md)
- [SOCFWCaseAnalysis - AI Prompt configuration and body](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-framework-nist-ir-ai/SOCFWCaseAnalysis.prompt.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `soc-framework-nist-ir-ai.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-framework-nist-ir-ai-v1.0.1/soc-framework-nist-ir-ai-v1.0.1.zip) |

## Jobs

Scheduled or triggered jobs the installer creates on the tenant.

### SOC Case Analysis

Runs NIST IR Detection & Analysis once per case instead of once per issue. Selects security cases that have settled, collapses each to its distinct alert shapes, and produces one verdict into SOCFramework.Analysis.AI. Thresholds configured in SOCOptimizationConfig_V3 under 'Case Analysis JOB'.

| Field | Value |
|---|---|
| Playbook | `JOB - SOC Case Analysis` |
| Recurrent | ✓ |
| Schedule | every 10 minutes daily |
| Owner | `abarone@paloaltonetworks.com` |
