# SOC Framework (DEPRECATED) — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `SocFrameworkOptimization` |
| Version | `2.1.48` |
| Category | Use Case |
| Pack Path | `Packs/SocFrameworkOptimization` |
| Manifest | [`Packs/SocFrameworkOptimization/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/SocFrameworkOptimization/xsoar_config.json) |

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [SOC Framework - Manual Steps](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/SocFrameworkOptimization/POST_CONFIG_README.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `soc-optimization.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-optimization-v2.1.48/soc-optimization-v2.1.48.zip) |

## Marketplace Dependencies

Marketplace packs the installer ensures are present on the tenant.

| ID | Name | Version |
|---|---|---|
| `Base` | Base | `latest` |
| `CommonScripts` | Common Scripts | `latest` |
| `CommonPlaybooks` | Common Playbooks | `latest` |
| `DemistoRESTAPI` | Cortex REST API | `latest` |
| `Whois` | Whois | `latest` |
| `Unit42ThreatIntelligencebyPaloAltoNetworks` | Unit 42 Threat Intelligence by Palo Alto Networks | `latest` |

## Lookup Datasets

### `value_tags`

| Field | Value |
|---|---|
| Type | `lookup` |
| Source | [file](https://raw.githubusercontent.com/Palo-Cortex/soc-optimization/refs/heads/main/Lookup/value_tags.json) |

**Schema:**

| Column | Type |
|---|---|
| `Product` | `text` |
| `TaskName` | `text` |
| `Time` | `text` |
| `ScriptID` | `text` |
| `Tag` | `text` |
| `PlaybookID` | `text` |
| `Category` | `text` |
| `Vendor` | `text` |

## Integration Instances

Integration brand instances the installer configures. Credentials and propagation labels are always tenant-specific — only the scaffolding ships in the pack.

| Instance Name | Brand | Category | Enabled |
|---|---|---|---|
| `PlaybookMetrics` | `System XQL HTTP Collector` | Utilities | true |
| `Whois_instance_SOCFW` | `Whois` | Data Enrichment & Threat Intelligence | true |
| `Unit_42_Intelligence_SOCFW` | `Unit 42 Intelligence` | Data Enrichment & Threat Intelligence | true |

## Jobs

Scheduled or triggered jobs the installer creates on the tenant.

### Auto Triage

This playbook accesses the API for XSIAM and by default must attract starred alerts within 6 hours or they will be closed as low fidelity alerts.

| Field | Value |
|---|---|
| Playbook | `JOB - Triage Alerts V2` |
| Recurrent | ✓ |
| Schedule | every 10 minutes daily |
| Owner | `abarone@paloaltonetworks.com` |

### Collect Playbook Metrics

| Field | Value |
|---|---|
| Playbook | `JOB - Store Playbook Metrics in Dataset V2` |
| Recurrent | ✓ |
| Schedule | every 15 minutes daily |
| Owner | `abarone@paloaltonetworks.com` |
