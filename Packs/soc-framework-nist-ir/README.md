## SOC Framework – Incident Response (NIST)
# SOC Framework Pack Manager

Manage SOC Framework content packs directly from the XSIAM Playground — no manual zip uploads, no REST API dependency.

---

## Quick Start

```
!SOCFWPackManager action=list
!SOCFWPackManager action=apply pack_id=soc-optimization-unified
!SOCFWPackManager action=configure pack_id=SocFrameworkTrendMicroVisionOne
!SOCFWPackManager action=sync-tags
```

---

## Prerequisites

Before running `action=apply`, configure the **SOC Framework Pack Manager** integration instance:

1. Go to **Settings → API Keys** → create a Standard key
2. Copy the **Key**, **Key ID**, and the **API URL** (Settings → API Keys → Copy API URL)
3. Configure the integration instance with these three values

Credentials are stored masked in the integration — never passed as command arguments.

---

## Commands

### `action=list` — Browse the catalog

```
!SOCFWPackManager action=list
```

Shows all available SOC Framework packs with ID, version, and path. Use `filter=` to narrow results.

```
!SOCFWPackManager action=list filter=crowdstrike
```

---

### `action=apply` — Install or update a pack

```
!SOCFWPackManager action=apply pack_id=<pack_id>
```

Downloads the pack zip from GitHub Releases, installs it as system content, then applies all configuration from the pack's `xsoar_config.json` (integration instances, jobs, lookup datasets). Safe to re-run — existing config is detected and skipped.

**Examples:**

```
!SOCFWPackManager action=apply pack_id=soc-optimization-unified
!SOCFWPackManager action=apply pack_id=SocFrameworkTrendMicroVisionOne
!SOCFWPackManager action=apply pack_id=SocFrameworkProofPointTap
```

---

### `action=configure` — Re-run configuration only

```
!SOCFWPackManager action=configure pack_id=<pack_id>
```

Fetches `xsoar_config.json` and runs integration, job, and lookup configuration without reinstalling the pack. Use when configuration has changed, or to recover from a failed config step after a manual install.

```
!SOCFWPackManager action=configure pack_id=SocFrameworkMicrosoftDefender
```

---

### `action=sync-tags` — Update the value_tags lookup

### Description
```
!SOCFWPackManager action=sync-tags
```

The **SOC Framework – Incident Response (NIST)** pack provides a standardized set of incident response workflows aligned with the lifecycle defined in **NIST SP 800-61**. It implements the operational stages of incident response within the SOC Framework, enabling consistent investigation, containment, eradication, recovery, and communication processes across security incidents.
Downloads `value_tags.json` from the SOC Framework repository and updates the `value_tags` lookup dataset. Compares a content hash against the previously stored version — if unchanged, skips the upload and reports the current version. Run after SOC Framework updates to keep the Value Metrics dashboard current.

Rather than building separate playbooks for each threat scenario, this pack organizes response logic around the **incident response lifecycle**. Scenarios such as phishing, endpoint compromise, identity abuse, and other security events enter the workflow and progress through the same structured response phases. This approach promotes consistent analyst workflows, reduces duplicated automation logic, and ensures that containment and recovery actions follow a predictable process.
```
!SOCFWPackManager action=sync-tags force=true   # overwrite regardless of version
```

The playbooks in this pack are designed to operate on standardized artifacts and actions provided by the **SOC Framework Core** pack. Vendor-specific commands are abstracted through framework actions, allowing the same incident response logic to operate across different security products and environments.
Version state is stored in the `SOCFWTagsVersion` XSIAM List (visible at Settings → Advanced → Lists).

### Key Capabilities
---

- Lifecycle-based incident response workflows aligned with **NIST SP 800-61**
- Standardized phases including:
   - **Upon Trigger**
   - **Analysis**
   - **Containment**
   - **Eradication**
   - **Recovery**
   - **Communication**
- Scenario-agnostic workflows that support incidents such as phishing, endpoint compromise, and identity threats
- Integration with the **SOC Framework Core** abstraction layer to execute vendor-specific response actions
- Consistent handling of investigation artifacts and incident context across response phases
## Recommended Installation Order

### Architecture
1. Install the base framework:
   ```
   !SOCFWPackManager action=apply pack_id=soc-optimization-unified
   ```

By separating **incident response methodology** from **vendor integrations and automation primitives**, this pack allows organizations to maintain a consistent incident response process while adapting to changes in security tooling or detection sources.
2. Install the NIST IR lifecycle pack:
   ```
   !SOCFWPackManager action=apply pack_id=soc-framework-nist-ir
   ```

3. Install product enhancement packs for your environment:
   ```
   !SOCFWPackManager action=apply pack_id=SocFrameworkMicrosoftDefender
   !SOCFWPackManager action=apply pack_id=SocFrameworkProofPointTap
   !SOCFWPackManager action=apply pack_id=SocFrameworkTrendMicroVisionOne
   ```

4. Sync the value_tags lookup:
   ```
   !SOCFWPackManager action=sync-tags
   ```

> Product enhancement packs require the corresponding Marketplace integration to be installed and configured in the tenant.

---

## Design Principles

- **No core-api-* dependency** — packs install via the XSIAM content bundle endpoint, which works on all tenants
- **Idempotent** — all actions are safe to re-run; existing config is detected and preserved
- **Composable** — install only the packs relevant to your environment
- **Version-aware** — `sync-tags` tracks content hash across runs; `apply` installs from pinned GitHub Release tags

---

For a complete argument reference, see [README_COMMANDS.md](README_COMMANDS.md).
