# SOC Framework Manager — Post-Install

SOC Framework Manager is now installed and ready to use.

All interactions with the manager are done through the **SOCFWPackManager** command in the Playground.

---

## Basic Usage

### List Available SOC Framework Packs

Use this command to list all available packs from the configured catalog:

`!SOCFWPackManager action=list`

This returns the pack IDs that can be installed or updated.

---

### Apply (Install or Update) a Pack by ID

Use the pack ID from the list command to install or update a pack:

`!SOCFWPackManager action=apply pack_id=<pack_id>`

**Example:**

`!SOCFWPackManager action=apply pack_id=soc-optimization-unified`

---

## Notes
- The `apply` action is designed to be safe to re-run.
- Output will indicate which packs were installed, updated, or skipped.
- Additional options may be available depending on the pack being applied.

---

You can now continue installing SOC Framework packs as needed.

# SOC Framework Manager — Post-Install

SOC Framework Manager is now installed and ready to use.

All interactions with the manager are done through the **SOCFWPackManager** command in the Playground.

---

## Basic Usage

### List Available SOC Framework Packs

Use this command to list all available packs from the configured catalog:

`!SOCFWPackManager action=list`

This returns the pack IDs that can be installed or updated.

---

### Apply (Install or Update) a Pack by ID

Use the pack ID from the list command to install or update a pack:

`!SOCFWPackManager action=apply pack_id=<pack_id>`

**Example:**

`!SOCFWPackManager action=apply pack_id=soc-optimization`

---

## Recommended Installation Order

1. **Install the base framework pack**

   Start by installing the unified base framework:

   `!SOCFWPackManager action=apply pack_id=soc-framework-unified`

2. **Install one or more product enhancement packs**

   After the base framework is installed, install product-specific enhancement packs as needed.

   **Example:**

   `!SOCFWPackManager action=apply pack_id=soc-crowdstrike-falcon`

---

## Important Notes on Marketplace Integrations

Product enhancement packs extend vendor capabilities but **do not replace the vendor’s Marketplace integration**.

Before or alongside installing an enhancement pack, ensure that the corresponding **Marketplace integration is installed and configured** in the tenant.

**Example:**
- `soc-crowdstrike-falcon` → requires the **CrowdStrike Falcon** Marketplace integration to be installed and configured

---

You can now continue installing SOC Framework packs based on your environment and use cases.
