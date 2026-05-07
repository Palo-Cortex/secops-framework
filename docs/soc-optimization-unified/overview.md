# SOC Framework Unified — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `soc-optimization-unified` |
| Version | `3.7.96` |
| Category | Use Case |
| Pack Path | `Packs/soc-optimization-unified` |
| Manifest | [`Packs/soc-optimization-unified/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-optimization-unified/xsoar_config.json) |

## Schemas

Reference documentation for the schemas this pack defines.

- [SOCFrameworkNormalizeMap_V3](SOCFrameworkNormalizeMap_V3.md)

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [SOC Framework Unified - Manual Steps](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-optimization-unified/POST_CONFIG_README.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `soc-optimization-unified.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-optimization-unified-v3.7.97/soc-optimization-unified-v3.7.97.zip) |
| `soc-framework-nist-ir.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-framework-nist-ir-v1.5.49/soc-framework-nist-ir-v1.5.49.zip) |
| `soc-framework-manager.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-framework-manager-v1.1.1/soc-framework-manager-v1.1.1.zip) |

## Marketplace Dependencies

Marketplace packs the installer ensures are present on the tenant.

| ID | Name | Version |
|---|---|---|
| `CommonPlaybooks` | Common Playbooks | `latest` |
| `CommonScripts` | Common Scripts | `latest` |
| `Whois` | Whois | `latest` |
| `VirusTotal` | VirusTotal | `latest` |
| `rasterize` | Rasterize | `latest` |
| `FiltersAndTransformers` | Filters And Transformers | `latest` |
| `Palo_Alto_Networks_WildFire` | WildFire by Palo Alto Networks | `latest` |
| `Base` | Base | `latest` |
| `DemistoRESTAPI` | Cortex REST API | `latest` |
| `Unit42ThreatIntelligencebyPaloAltoNetworks` | Unit 42 Threat Intelligence by Palo Alto Networks | `latest` |
| `Phishing` | Phishing | `latest` |

## Lookup Datasets

### `value_tags`

| Field | Value |
|---|---|
| Type | `lookup` |
| Source | [file](https://raw.githubusercontent.com/Palo-Cortex/secops-framework/refs/heads/main/Packs/soc-optimization-unified/Lookup/value_tags.json) |

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
| `Whois_instance_SOCFW` | `Whois` | Data Enrichment & Threat Intelligence | true |
| `Rasterize_instance_1` | `Rasterize` | Utilities | true |
| `WildFire-Reports_default_instance` | `WildFire-Reports` | Forensics & Malware Analysis | true |
| `WildFire-v2_default_instance` | `WildFire-v2` | Forensics & Malware Analysis | true |
| `PlaybookMetrics` | `System XQL HTTP Collector` | Utilities | true |
| `socfw_ir_execution` | `System XQL HTTP Collector` | Utilities | true |
| `Unit_42_Intelligence_SOCFW` | `Unit 42 Intelligence` | Data Enrichment & Threat Intelligence | true |

## Jobs

Scheduled or triggered jobs the installer creates on the tenant.

### Auto Triage V3

Automatically closes unstarred cases that exceed the configured age and score thresholds with no analyst activity. Thresholds configured in SOCOptimizationConfig_V3.

| Field | Value |
|---|---|
| Playbook | `JOB - Auto Triage V3` |
| Recurrent | ✓ |
| Schedule | every 10 minutes daily |
| Owner | `abarone@paloaltonetworks.com` |

### Collect Playbook Metrics V3

| Field | Value |
|---|---|
| Playbook | `JOB - Store Playbook Metrics in Dataset V3` |
| Recurrent | ✓ |
| Schedule | every 15 minutes daily |
| Owner | `abarone@paloaltonetworks.com` |

## Exported Playbooks

Playbooks this pack exposes for use by other packs or directly from the tenant.

- `Foundation - Upon Trigger V3`
