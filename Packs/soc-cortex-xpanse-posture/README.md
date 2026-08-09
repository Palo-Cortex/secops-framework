# SOC Cortex Xpanse (Posture Lifecycle)

Vendor pack for Cortex Xpanse attack-surface findings, routed through the SOC Framework's Posture lifecycle on Cortex XSIAM.

## Overview

Cortex Xpanse is a unified-platform-native data source. The Xpanse-XSIAM integration writes attack-surface findings directly to the unified `issues` dataset at platform ingestion with XDM normalization applied. This differs from the third-party vendor pattern where a raw vendor dataset is transformed via modeling rule and then correlated into alerts.

This pack:
- Registers the routing entry `ds_panw_asm: Posture` in `SOCProductCategoryMap_V3` so Foundation Product Classification routes Xpanse findings into the Posture lifecycle
- Provides an operational metrics dashboard for visualizing Xpanse attack-surface findings
- Extends `SOCFrameworkNormalizeMap_POSTURE` with two new categories: `posture_attack_surface` for exposed-service findings and `posture_vulnerability` for CVE-bearing findings

## Prerequisites

- Cortex XSIAM tenant with the Xpanse-XSIAM native integration configured and issue ingest active
- SOC Framework installed and Foundation - Upon Trigger V3 configured
- `soc-framework-posture` pack installed (dependency)
- `soc-optimization-unified` pack installed (dependency)

## Architecture

Xpanse-XSIAM native integration writes records with:
- `xdm.issue.detection.method = XPANSE`
- `xdm.issue.domain = POSTURE`
- `original_tags = [DOM:Posture, DS:PANW/ASM]`

Foundation Product Classification reads the `DS:PANW/ASM` tag from `original_tags`, matches against `SOCProductCategoryMap_V3`, and routes into the Posture lifecycle. Within the lifecycle, the `posture_attack_surface` or `posture_vulnerability` category mapping produces the `SOCFramework.CloudPosture.*` contract that downstream lifecycle playbooks consume.

No correlation rule or modeling rule is required — the platform performs XDM normalization at ingestion, and there is no raw vendor dataset to transform.

## Framework Contract Extensions

Two categories added to `SOCFrameworkNormalizeMap_POSTURE`:

**`posture_attack_surface`** - exposed services, certificates, network protocols
- Fields: `target_ip`, `target_hostname`, `target_port`, `application_protocol`, `certificate_issuer`, `certificate_not_after`, `target_country`
- Dedup: `target_ip` + `target_port`
- Stamps: `finding_class = attack_surface`

**`posture_vulnerability`** - CVE-bearing findings on exposed services
- Fields: `cve_id`, `cvss_score`, `cvss_vector`, `affected_package`, `affected_package_version`, `fixed_version`, `target_ip`, `target_hostname`
- Dedup: `cve_id` + `target_ip`
- Stamps: `finding_class = vulnerability`

## Dashboard

`Cortex Xpanse Posture Metrics` dashboard - six operational panels:

1. Findings by severity (Critical / High / Medium / Low)
2. Findings by action status
3. Findings trend over time (30 days)
4. Top 10 finding types by rule_id
5. Geographic exposure by country
6. Top 10 affected assets

All queries operate against `dataset = issues` filtered by `xdm.issue.detection.method = "XPANSE"`.

## Same pattern applies to

- AI-SPM (AI Security Posture Management)
- CIEM (Cloud Infrastructure Entitlement Management)
- Any future Cortex Cloud source that writes directly to the unified `issues` dataset

## Support

Contact the SOC Framework team for issues, feature requests, or extending this pattern to additional platform-native sources.