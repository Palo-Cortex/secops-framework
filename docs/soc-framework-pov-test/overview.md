# SOC Framework PoV Test — Overview

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_pack_overviews.py` to regenerate. -->

| Field | Value |
|---|---|
| ID | `soc-framework-pov-test` |
| Version | `1.0.2` |
| Category | Utilities |
| Pack Path | `Packs/soc-framework-pov-test` |
| Manifest | [`Packs/soc-framework-pov-test/xsoar_config.json`](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-framework-pov-test/xsoar_config.json) |

> ⚠️ This pack requires manual post-install steps. See [Manual Steps](#manual-steps) below.

## Manual Steps

Documented post-install steps required to finish configuration.

- [SOC Framework PoV Test - Post Config](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-framework-pov-test/POST_CONFIG_README.md)

## Custom Packs Installed

Additional custom packs the installer pulls in alongside this pack.

| Pack | System | Source |
|---|---|---|
| `soc-framework-pov-test.zip` | `yes` | [release](https://github.com/Palo-Cortex/secops-framework/releases/download/soc-framework-pov-test-v1.0.2/soc-framework-pov-test-v1.0.2.zip) |

## Integration Instances

Integration brand instances the installer configures. Credentials and propagation labels are always tenant-specific — only the scaffolding ships in the pack.

| Instance Name | Brand | Category | Enabled |
|---|---|---|---|
| `socfw_pov_crowdstrike_sender` | `SOCFWPoVSender` | Utilities | true |
| `socfw_pov_tap_sender` | `SOCFWPoVSender` | Utilities | true |

## Jobs

Scheduled or triggered jobs the installer creates on the tenant.

### POV Teardown Reminder V1

Fires on the PoV end date and creates a High severity case with the uninstall checklist. Set the schedule date after installing the pack.

| Field | Value |
|---|---|
| Playbook | `JOB - POV Teardown Reminder V1` |
| Schedule | every 60 minutes daily |
