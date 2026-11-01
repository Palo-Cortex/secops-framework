<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

--8<-- "Packs/soc-optimization-unified/README.md"

## Manifest

| Field | Value |
|---|---|
| ID | `soc-optimization-unified` |
| Version | `3.31.1` |
| Category | Utility |
| Pack Path | `Packs/soc-optimization-unified` |
| Manifest | [`Packs/soc-optimization-unified/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-optimization-unified/xsoar_config.json) |

## Schemas

Reference documentation for the schemas this pack defines.

- [Directory Sync (pan-cie)](identity-resolve.md)
- [SOCProductCategoryMap_V3](SOCProductCategoryMap_V3.md)

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [SOC Framework Unified - Manual Steps](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-optimization-unified/POST_CONFIG_README.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `soc-optimization-unified.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-optimization-unified-v3.31.1/soc-optimization-unified-v3.31.1.zip) |

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

## Integration Instances

Integration brand instances the installer configures. Credentials and propagation labels are always tenant-specific — only the scaffolding ships in the pack.

| Instance Name | Brand | Category | Enabled |
|---|---|---|---|
| `Whois_instance_SOCFW` | `Whois` | Data Enrichment & Threat Intelligence | true |
| `Rasterize_instance_1` | `Rasterize` | Utilities | true |
| `WildFire-Reports_default_instance` | `WildFire-Reports` | Forensics & Malware Analysis | true |
| `WildFire-v2_default_instance` | `WildFire-v2` | Forensics & Malware Analysis | true |
| `Unit_42_Intelligence_SOCFW` | `Unit 42 Intelligence` | Data Enrichment & Threat Intelligence | true |
| `socfw_ir_execution_writer` | `SOCFWDatasetWriter` | Utilities | true |
| `socfw_case_ledger_writer` | `SOCFWDatasetWriter` | Utilities | true |

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

### SOCFW Analyst Assignment

Refreshes the on-duty roster from the customer's schedule sources, then assigns unassigned open cases to the least-loaded analyst on duty. Ships off; assignment ships shadowed. Set the owner and turn it on with SOCFWConfig.

| Field | Value |
|---|---|
| Playbook | `JOB - SOCFW Analyst Assignment` |
| Recurrent | ✓ |
| Schedule | every 5 minutes daily |
| Owner | `set-owner-with-SOCFWConfig` |

## Exported Playbooks

Playbooks this pack exposes for use by other packs or directly from the tenant.

- `Foundation - Upon Trigger V3`

## Lists

Shipped defaults, read from each list's `_data.json`. Change them on the tenant with `!SOCFWConfig`, never by editing the pack.

??? note "`SOCActionClassMap_V3` — 29 keys"

    Maps SOC Framework action names to action classes for multi-vendor response routing. SOCCommandWrapper reads this to determine which responses.{class} key to look up in SOCProductCategoryMap_V3 whe...

    | Key | Shipped default | Description |
    |---|---|---|
    | `soc-isolate-endpoint` | `endpoint` |  |
    | `soc-deisolate-endpoint` | `endpoint` |  |
    | `soc-kill-process` | `endpoint` |  |
    | `soc-remove-file` | `endpoint` |  |
    | `soc-delete-file` | `endpoint` |  |
    | `soc-file-exists` | `endpoint` |  |
    | `soc-remove-persistence` | `endpoint` |  |
    | `soc-quarantine-files` | `endpoint` |  |
    | `soc-enrich-endpoint` | `endpoint` |  |
    | `soc-disable-user` | `identity` |  |
    | `soc-enable-user` | `identity` |  |
    | `soc-reset-password` | `identity` |  |
    | `soc-revoke-tokens` | `identity` |  |
    | `soc-clear-sessions` | `identity` |  |
    | `soc-enrich-user` | `identity` |  |
    | `soc-quarantine-email` | `email` |  |
    | `soc-retract-email` | `email` |  |
    | `soc-block-sender` | `email` |  |
    | `soc-unblock-sender` | `email` |  |
    | `soc-get-email-forensics` | `email` |  |
    | `soc-get-email-events` | `email` |  |
    | `soc-block-indicators` | `indicator` |  |
    | `soc-enrich-ioc` | `indicator` |  |
    | `soc-enrich-domain` | `indicator` |  |
    | `soc-enrich-ip` | `indicator` |  |
    | `soc-enrich-file` | `indicator` |  |
    | `soc-detonate-file` | `indicator` |  |
    | `soc-notify-user` | `comms` |  |
    | `soc-block-domain` | `indicator` |  |

??? note "`SOCActionTimeMap_V3` — 31 keys"

    Maps each SOC Framework Universal Command action to an estimated analyst time-to-complete (time_minutes) and action classification (action_category). Customer-editable — update time_minutes to refl...

    | Key | Shipped default | Description |
    |---|---|---|
    | `soc-audit-inbox-rules` | `3 min, enrichment` |  |
    | `soc-auto-triage-close` | `10 min, triage` |  |
    | `soc-auto-triage-skip` | `10 min, triage` |  |
    | `soc-block-sender` | `15 min, containment` |  |
    | `soc-clear-sessions` | `15 min, containment` |  |
    | `soc-deisolate-endpoint` | `10 min, recovery` |  |
    | `soc-disable-user` | `15 min, containment` |  |
    | `soc-enable-user` | `10 min, recovery` |  |
    | `soc-enrich-domain` | `3 min, enrichment` |  |
    | `soc-enrich-endpoint` | `3 min, enrichment` |  |
    | `soc-enrich-file` | `3 min, enrichment` |  |
    | `soc-enrich-ioc` | `3 min, enrichment` |  |
    | `soc-enrich-ip` | `3 min, enrichment` |  |
    | `soc-enrich-user` | `3 min, enrichment` |  |
    | `soc-file-exists` | `3 min, enrichment` |  |
    | `soc-get-email-events` | `3 min, enrichment` |  |
    | `soc-isolate-endpoint` | `15 min, containment` |  |
    | `soc-kill-process` | `10 min, eradication` |  |
    | `soc-notify-user` | `2 min, comms` |  |
    | `soc-quarantine-email` | `15 min, containment` |  |
    | `soc-quarantine-files` | `15 min, containment` |  |
    | `soc-remove-file` | `10 min, eradication` |  |
    | `soc-remove-inbox-rules` | `10 min, eradication` |  |
    | `soc-remove-persistence` | `10 min, eradication` |  |
    | `soc-reset-password` | `10 min, eradication` |  |
    | `soc-retract-email` | `15 min, containment` |  |
    | `soc-revoke-tokens` | `15 min, containment` |  |
    | `soc-run-script` | `10 min, eradication` |  |
    | `soc-search-and-delete-email` | `10 min, eradication` |  |
    | `soc-unblock-sender` | `10 min, recovery` |  |
    | `soc-block-domain` | `15 min, containment` |  |

??? note "`SOCExecutionList_V3` — 32 keys"

    | Key | Shipped default | Description |
    |---|---|---|
    | `SOC Endpoint Analysis_V3` | `default` |  |
    | `SOC Endpoint Containment_V3` | `default` |  |
    | `SOC Endpoint Eradication_V3` | `default` |  |
    | `SOC Endpoint Recovery_V3` | `default` |  |
    | `SOC Email Analysis_V3` | `default` |  |
    | `SOC Email Containment_V3` | `default` |  |
    | `SOC Email Eradication_V3` | `default` |  |
    | `SOC Email Recovery_V3` | `default` |  |
    | `SOC Identity Analysis_V3` | `default` |  |
    | `SOC Identity Containment_V3` | `default` |  |
    | `SOC Identity Eradication_V3` | `default` |  |
    | `SOC Identity Recovery_V3` | `default` |  |
    | `SOC Network Analysis_V3` | `default` |  |
    | `SOC Network Containment_V3` | `default` |  |
    | `SOC Network Eradication_V3` | `default` |  |
    | `SOC Network Recovery_V3` | `default` |  |
    | `SOC SaaS Analysis_V3` | `default` |  |
    | `SOC SaaS Containment_V3` | `default` |  |
    | `SOC SaaS Eradication_V3` | `default` |  |
    | `SOC SaaS Recovery_V3` | `default` |  |
    | `SOC Workload Analysis_V3` | `default` |  |
    | `SOC Workload Containment_V3` | `default` |  |
    | `SOC Workload Eradication_V3` | `default` |  |
    | `SOC Workload Recovery_V3` | `default` |  |
    | `SOC PAM Analysis_V3` | `default` |  |
    | `SOC PAM Containment_V3` | `default` |  |
    | `SOC PAM Eradication_V3` | `default` |  |
    | `SOC PAM Recovery_V3` | `default` |  |
    | `SOC Data Analysis_V3` | `default` |  |
    | `SOC Data Containment_V3` | `default` |  |
    | `SOC Data Eradication_V3` | `default` |  |
    | `SOC Data Recovery_V3` | `default` |  |

??? note "`SOCFWConfigModes` — 1 keys"

    Each mode sets every switch listed here, so changing modes leaves nothing behind. Apply one with !SOCFWConfig command=mode mode=<name> owner=<email> apply=yes; mode=default removes these settings a...

    | Key | Shipped default | Description |
    |---|---|---|
    | `modes` | 4 keys |  |

??? note "`SOCFWFeatureFlags` — 6 keys"

    | Key | Shipped default | Description |
    |---|---|---|
    | `sandbox_detonation` | `false` | Full sandbox file detonation via soc-detonate-file. Cortex Core hash prevalence runs regardless as the free baseline. Enable after configuring WildFire, Viru... |
    | `email_authentication` | `false` | SPF/DKIM/DMARC header validation via CheckEmailAuthenticity. Enable when the email source provides raw headers in alert data (Exchange, Gmail, user-reported ... |
    | `email_header_scoring` | `false` | Parse mail infrastructure security scoring headers for supplemental spam and phishing signals. Currently supports Microsoft Exchange/O365 (SCL/BCL/PCL). Enab... |
    | `email_process_original` | `false` | Retrieve and parse original email content via Process Email - Generic v2. Enable when analysts forward suspicious emails to a monitored phishing mailbox. Pro... |
    | `email_indicator_hunting` | `false` | Cross-platform indicator hunting for phishing IOCs. Enable when a hunting-capable platform is connected (e.g., Microsoft Defender 365). Expensive — runs per ... |
    | `email_phishing_ml` | `false` | ML-based phishing content scoring via Phishing - Machine Learning Analysis. Enable after deploying a Phishing ML model. Requires email body content from emai... |

??? note "`SOCFrameworkActions_V3` — 52 keys"

    | Key | Shipped default | Description |
    |---|---|---|
    | `soc-close-issue` | `shadow_mode=true` | Triage — close issue |
    | `soc-close-issue-contained` | `shadow: analyst, ai, automation` | Triage — close issue as true positive, contained |
    | `soc-star-case` | `shadow: ai, automation, issue_emergency; live: analyst` | Triage — star case for analyst attention |
    | `soc-raise-case-severity` | `shadow: analyst, ai, automation` | Triage — raise case severity |
    | `soc-isolate-endpoint` | `shadow: analyst, ai, automation, issue_emergency` | Endpoint containment — isolate host |
    | `soc-deisolate-endpoint` | `shadow: analyst, ai, automation, issue_emergency` | Endpoint recovery — restore host connectivity |
    | `soc-kill-process` | `shadow_mode=true` | Endpoint containment — halt process |
    | `soc-remove-file` | `shadow_mode=true` | Endpoint eradication — remove file |
    | `soc-remove-persistence` | `shadow_mode=true` | Endpoint eradication — remove persistence |
    | `soc-delete-file` | `shadow_mode=true` | Endpoint eradication — delete file |
    | `soc-file-exists` | `shadow_mode=false` | Endpoint investigation — confirm file present |
    | `soc-quarantine-files` | `shadow_mode=true` | Endpoint containment — quarantine file |
    | `soc-disable-user` | `shadow_mode=true` | Identity containment — disable account |
    | `soc-clear-sessions` | `shadow_mode=true` | Identity containment — clear active sessions |
    | `soc-reset-password` | `shadow_mode=true` | Identity eradication — reset credential |
    | `soc-revoke-tokens` | `shadow_mode=true` | Identity containment — revoke tokens |
    | `soc-enable-user` | `shadow_mode=true` | Identity recovery — re-enable account |
    | `soc-enrich-user` | `shadow_mode=false` | Enrichment — user |
    | `soc-enrich-endpoint` | `shadow_mode=false` | Enrichment — endpoint |
    | `soc-enrich-file` | `shadow_mode=false` | Enrichment — file |
    | `soc-enrich-ip` | `shadow_mode=false` | Enrichment — ip |
    | `soc-enrich-domain` | `shadow_mode=false` | Enrichment — domain |
    | `soc-enrich-ioc` | `shadow_mode=false` | Enrichment — ioc |
    | `soc-get-email-clicks` | `shadow_mode=false` | Email investigation — click evidence |
    | `soc-get-email-messages` | `shadow_mode=false` | Email investigation — retrieve messages |
    | `soc-get-email-forensics` | `shadow_mode=false` | Email investigation — message forensics |
    | `soc-retract-email` | `shadow_mode=true` | Email containment — retract delivered message |
    | `soc-quarantine-email` | `shadow_mode=true` | Email containment — quarantine message |
    | `soc-block-sender` | `shadow_mode=true` | Email containment — block sender |
    | `soc-unblock-sender` | `shadow_mode=true` | Email recovery — unblock sender |
    | `soc-audit-inbox-rules` | `shadow_mode=false` | Identity investigation — audit inbox rules |
    | `soc-notify-user` | `shadow_mode=true` | Communication — notify affected user |
    | `soc-detonate-file` | `shadow_mode=false` | Submit file for sandbox analysis and return verdict. Cortex Core hash prevalence is the built-in baseline -- no integration required. Add WildFire, VirusTota... |
    | `soc-remove-inbox-rules` | `shadow_mode=true` | Identity eradication — remove malicious inbox rules |
    | `soc-search-and-delete-email` | `shadow_mode=true` | Email eradication — purge message across mailboxes |
    | `soc-block-indicators` | `shadow_mode=true` | Artifact containment — block file hash |
    | `soc-posture-remediate-compliance` | `shadow_mode=true` |  |
    | `soc-posture-verify-compliance` | `shadow_mode=true` |  |
    | `soc-posture-correct-drift` | `shadow_mode=true` |  |
    | `soc-posture-verify-drift` | `shadow_mode=true` |  |
    | `soc-posture-remediate-misconfig` | `shadow_mode=true` |  |
    | `soc-posture-verify-misconfig` | `shadow_mode=true` |  |
    | `soc-enrich-device-logons` | `shadow_mode=false` | Enrichment — device logons |
    | `soc-enrich-user-manager` | `shadow_mode=false` | Enrichment — user manager |
    | `soc-block-network-indicator` | `shadow_mode=true` | Network containment — block C2 address at every enforcement point |
    | `soc-create-ticket` | `shadow_mode=true` | Ticketing — open incident record |
    | `soc-update-ticket` | `shadow_mode=true` | Ticketing — update incident record |
    | `soc-close-ticket` | `shadow_mode=true` | Ticketing — close incident record |
    | `soc-release-email` | `shadow_mode=true` | Email recovery — release held message |
    | `soc-block-domain` | `shadow_mode=true` | Network containment — block domain at DNS and web proxy |
    | `soc-sync-on-duty` | `shadow_mode=false` | Enrichment — read who is on duty from the customer's schedule sources |
    | `soc-assign-case` | `shadow: analyst, ai, automation, issue_emergency` | Triage — assign a case to an on-duty analyst |

??? note "`SOCFrameworkEnvironment_V3` — 3 keys"

    | Key | Shipped default | Description |
    |---|---|---|
    | `defaults` | 2 keys |  |
    | `tiers` | 3 keys |  |
    | `entries` | `{'name': 'domain_controllers', 'entity_type': 'endpoint', 'match_field': 'hos...` |  |

??? note "`SOCFrameworkPhasePolicy_V3` — 4 keys"

    | Key | Shipped default | Description |
    |---|---|---|
    | `defaults` | 2 keys |  |
    | `authority_levels` | 3 keys |  |
    | `phases` | 4 keys |  |
    | `ticketing` | `true` | Ticket scope is the case. Per-issue tickets rebuild the alert storm that case grouping exists to remove. |

??? note "`SOCOptimizationConfig_V3` — 5 keys"

    | Key | Shipped default | Description |
    |---|---|---|
    | `Triage Incidents JOB` | `TriageWindowHours=6, TriageScoreThreshold=40, TriageMaxBatches=200, TriageBatchSize=100, TriageDomains=security` |  |
    | `Dedup` | `true` |  |
    | `ShadowMode` | `true` |  |
    | `Case Analysis JOB` | `false` |  |
    | `Analyst Assignment JOB` | `AssignmentDomains=security, AssignmentWindow=24 hours, AssignmentCases=starred, AssignmentOnlineOnly=true, AssignmentMaxPerAnalyst=20, AssignmentMethod=least_loaded, AssignmentRoles=Instance Admini...` |  |

??? note "`SOCProductCategoryMap_V3` — 53 keys"

    | Key | Shipped default | Description |
    |---|---|---|
    | `ds_abnormal_security_email_protection` | `Email` | Live DS: Abnormal Security/Email Protection |
    | `ds_abnormalsecurity_abx` | `Email` | legacy alias |
    | `ds_alibaba_actiontrail` | `Workload` |  |
    | `ds_armis` | `Network` | Alias of ds_armis_generic_alert. See canonical key for detail. |
    | `ds_armis_generic_alert` | `Network` | Live DS: Armis. Generic alert collector. OT/IoT, flow-derived detections. No response engine - Armis is enrichment-only via soc-enrich-endpoint -> armis-sear... |
    | `ds_armis_security_activities` | `Network` | DS tag carried by issues from the custom Armis correlation rules. Tags are not dataset names - the dataset behind this one is armis_security_activities_raw. |
    | `ds_aws_cloudtrail` | `Workload` |  |
    | `ds_azure_activity` | `Workload` |  |
    | `ds_check_point_anti_malware` | `Network` |  |
    | `ds_check_point_ndr` | `Network` |  |
    | `ds_nozomi_networks_guardian` | `Network` | Live DS: Nozomi Networks/Guardian |
    | `ds_check_point_new_anti_virus` | `Network` |  |
    | `ds_check_point_smartdefense` | `Network` |  |
    | `ds_check_point_threat_emulation` | `Network` |  |
    | `ds_check_point_vpn_1___firewall_1` | `Network` |  |
    | `ds_cisco_asa_vpn` | `Network` |  |
    | `ds_cisco_ise` | `Identity` |  |
    | `ds_crowdstrike_falcon_event` | `Endpoint` |  |
    | `ds_cyberark` | `Identity` |  |
    | `ds_fortinet_fortigate` | `Network` |  |
    | `ds_gcp_audit` | `Workload` |  |
    | `ds_microsoft_defender_email` | `Email` |  |
    | `ds_microsoft_defender_identity` | `Identity` |  |
    | `ds_microsoft_data_loss_prevention` | `DLP` | Live DS: Microsoft/Data Loss Prevention (Purview, via Graph Security alerts) |
    | `ds_microsoft_graph_generic_alert` | `Email` |  |
    | `ds_msft_azure_ad` | `Identity` |  |
    | `ds_msft_defenderxdr` | `Endpoint` |  |
    | `ds_msft_graph_security_alerts` | `Endpoint` |  |
    | `ds_okta_sso` | `Identity` |  |
    | `ds_okta_systemlog` | `Identity` |  |
    | `ds_paloaltonetworks_Email` | `Email` |  |
    | `ds_paloaltonetworks_cloud_identity_engine_directory` | `Identity` |  |
    | `ds_paloaltonetworks_firewall_threat` | `Network` |  |
    | `ds_paloaltonetworks_firewall_traffic` | `Network` |  |
    | `ds_panw_asm` | `posture_attack_surface` |  |
    | `ds_panw_xdr_agent` | `Endpoint` |  |
    | `ds_proofpoint_tap` | `Email` |  |
    | `ds_proofpoint_tap_v2` | `Email` | Production DS: Proofpoint TAP V2 |
    | `ds_proofpoint_tap_v2_generic_alert` | `Email` |  |
    | `ds_proofpoint_tap_v2_generic_alert_raw` | `Email` |  |
    | `ds_sentinelone_v2` | `Endpoint` |  |
    | `ds_spycloud_enterprise_protection` | `Cloud` | Live DS: SpyCloud/Enterprise Protection (Cloud IR) |
    | `ds_tap_v2_generic_alert` | `Email` |  |
    | `ds_trend_micro_vision_one_v3_generic_alert` | `Endpoint` |  |
    | `ds_wiz` | `Cloud` |  |
    | `ds_zscaler_nssfwlog` | `Network` |  |
    | `ds_zscaler_nssweblog` | `Network` |  |
    | `ds_zscaler_zia` | `Network` |  |
    | `ds_darktrace_darktrace` | `Network` | Darktrace NDR has NO containment capability. The Darktrace Model Breaches integration exposes get-model-breach, get-model-breach-comments, get-model-breach-c... |
    | `ds_darktrace_darktrace_raw` | `Network` | collector dataset alias for darktrace_darktrace_raw. Darktrace NDR has NO containment capability. The Darktrace Model Breaches integration exposes get-model-... |
    | `ds_darktraceemail_generic_alert` | `Email` | Live DS: DarktraceEmail/generic_alert. Containment is darktrace-email-hold-email, keyed on uuid, which is what the rule puts in emailmessageid. Reversal is d... |
    | `ds_darktraceemail_generic_alert_raw` | `Email` | collector dataset alias for darktraceemail_generic_alert_raw |
    | `ds_darktrace_darktrace_email` | `Email` | vendor/product alias emitted by the correlation rule |
