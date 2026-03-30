# SOCFWPackManager

Install, configure, and maintain SOC Framework content packs directly from the XSIAM Playground. No manual ZIP uploads, no REST API dependency — run `!SOCFWPackManager action=apply pack_id=<id>` and the script handles the rest.

## Dependencies

This script uses the following commands and integrations:

- **SOC Framework Pack Manager integration** (`SOCFWPackManager`) — required for `action=apply`. Stores XSIAM API credentials masked in the integration instance params.

## Script Data

| Name | Description |
| --- | --- |
| Script Type | Python 3 |
| Tags | configuration, Content Management, SOC, SOC_Framework |
| XSIAM | Supported (marketplacev2) |
| Timeout | 30 minutes |

## Inputs

| Argument | Default | Description |
| --- | --- | --- |
| action | apply | Required. `list` — browse the catalog. `apply` — install or update a pack and run its configuration. `configure` — re-run configuration only (no pack reinstall). `sync-tags` — update the `value_tags` lookup dataset. |
| pack_id | — | Pack ID from `pack_catalog.json` (e.g. `soc-optimization-unified`). Required for `apply` and `configure`. |
| catalog_url | GitHub main branch | Override the `pack_catalog.json` URL without touching integration params. |
| include_hidden | False | Allow installing packs marked `visible=false` in the catalog. |
| dry_run | False | Show what would happen without executing. Applies to `apply` and `configure`. |
| install_marketplace | True | Install marketplace dependencies listed in the pack's `xsoar_config.json`. |
| skip_verify | True | Skip pack verification during ZIP install. |
| skip_validation | False | Skip pack validation during ZIP install. |
| apply_configure | True | Run configuration after installing the pack (integration instances, jobs, lookups). |
| overwrite_lookup | False | Overwrite existing lookup datasets during configuration. |
| configure_jobs | True | Apply job definitions from `xsoar_config.json`. |
| configure_integrations | True | Apply integration instance definitions from `xsoar_config.json`. |
| configure_lookups | True | Apply lookup dataset definitions from `xsoar_config.json`. |
| retry_sleep_seconds | 5 | Seconds to wait between retries on transient failures. |
| debug | False | Emit verbose debug output to the war room. |
| filter | — | For `action=list`: case-insensitive text filter on id, display_name, path. |
| limit | 50 | For `action=list`: rows per page. |
| offset | 0 | For `action=list`: row offset for paging. |
| sort_by | id | For `action=list`: column to sort (`id`, `display_name`, `version`, `visible`, `path`). |
| sort_dir | asc | For `action=list`: `asc` or `desc`. |
| fields | id,display_name,version,visible,path | For `action=list`: columns to display (comma-separated). |
| force | False | For `action=sync-tags`: overwrite the `value_tags` lookup regardless of version hash. |

## Outputs

| Path | Type | Description |
| --- | --- | --- |
| SOCFramework.PackInstall.pack_id | String | Pack ID that was processed. |
| SOCFramework.PackInstall.configure_summary.integrations | Unknown | Integration instance configuration results. |
| SOCFramework.PackInstall.configure_summary.jobs | Unknown | Job configuration results. |
| SOCFramework.PackInstall.configure_summary.lookups | Unknown | Lookup dataset configuration results. |

## Usage Examples

### Browse the catalog

```
!SOCFWPackManager action=list
!SOCFWPackManager action=list filter=crowdstrike
```

### Install or update a pack

```
!SOCFWPackManager action=apply pack_id=soc-optimization-unified
!SOCFWPackManager action=apply pack_id=soc-framework-nist-ir
!SOCFWPackManager action=apply pack_id=SocFrameworkCrowdstrikeFalcon
!SOCFWPackManager action=apply pack_id=SocFrameworkProofPointTap
!SOCFWPackManager action=apply pack_id=SocFrameworkTrendMicroVisionOne
```

### Re-run configuration only (no pack reinstall)

```
!SOCFWPackManager action=configure pack_id=SocFrameworkMicrosoftDefender
```

### Update the value_tags lookup

```
!SOCFWPackManager action=sync-tags
!SOCFWPackManager action=sync-tags force=true
```

## Recommended Installation Order

1. `!SOCFWPackManager action=apply pack_id=soc-optimization-unified` — foundation layer
2. `!SOCFWPackManager action=apply pack_id=soc-framework-nist-ir` — NIST IR lifecycle
3. Product packs for the environment (CrowdStrike, Proofpoint, Microsoft Defender, etc.)
4. `!SOCFWPackManager action=sync-tags` — sync value metrics lookup

Product packs require the corresponding Marketplace integration to be installed and configured in the tenant first.

## Design Notes

- **Idempotent** — all actions are safe to re-run. Existing configuration is detected and skipped.
- **No `core-api-*` dependency** — packs install via the content bundle endpoint, which works on all XSIAM tenants regardless of instance role.
- **Version-aware** — `action=sync-tags` stores a content hash in the `SOCFWTagsVersion` XSIAM List after each sync and skips the upload if the data is already current.
- **Credential isolation** — API credentials are stored masked in the SOC Framework Pack Manager integration instance and are never logged or exposed in war room output.
