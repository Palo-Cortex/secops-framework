# SOC Common Playbooks — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `soc-common-playbooks` |
| Version | `2.7.52` |
| Category | Utility |
| Pack Path | `Packs/soc-common-playbooks` |
| Manifest | [`Packs/soc-common-playbooks/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-common-playbooks/xsoar_config.json) |

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `soc-common-playbooks.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-common-playbooks-v2.7.52/soc-common-playbooks-v2.7.52.zip) |

## Marketplace Dependencies

Marketplace packs the installer ensures are present on the tenant.

| ID | Name | Version |
|---|---|---|
| `Core` | Core - Investigation and Response | `latest` |
| `CommonPlaybooks` | Common Playbooks | `latest` |
| `CommonScripts` | Common Scripts | `latest` |
| `Whois` | Whois | `latest` |
| `VirusTotal` | VirusTotal | `latest` |
| `rasterize` | Rasterize | `latest` |
| `FiltersAndTransformers` | Filters And Transformers | `latest` |
| `Palo_Alto_Networks_WildFire` | WildFire by Palo Alto Networks | `latest` |
| `Base` | Base | `latest` |
| `DemistoRESTAPI` | Cortex REST API | `latest` |

## Integration Instances

Integration brand instances the installer configures. Credentials and propagation labels are always tenant-specific — only the scaffolding ships in the pack.

| Instance Name | Brand | Category | Enabled |
|---|---|---|---|
| `Cortex Core - IR_default_instance` | `Cortex Core - IR` |  | true |
| `Whois_instance_1` | `Whois` | Data Enrichment & Threat Intelligence | true |
| `Rasterize_instance_1` | `Rasterize` | Utilities | true |
| `WildFire-Reports_default_instance` | `WildFire-Reports` | Forensics & Malware Analysis | true |
| `WildFire-v2_default_instance` | `WildFire-v2` | Forensics & Malware Analysis | true |
