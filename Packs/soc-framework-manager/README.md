# SOC Framework Package Manager

The **SOC Framework Package Manager** provides a simple, repeatable way to install, update, and manage SOC Framework content packs directly from within XSIAM/XSOAR.

It acts as a lightweight installer and orchestrator for SOC Framework packs, removing the need to manually upload zip files or manage complex dependencies by hand.

---

## What This Pack Does

- Installs the **SOCFWPackManager** command
- Allows you to:
    - List available SOC Framework packs
    - Apply (install or update) packs by ID
- Supports a modular, layered installation model:
    - Base framework packs
    - Product-specific enhancement packs
    - Optional extensions over time

This pack **does not automatically configure** integrations, jobs, or tenant settings unless explicitly implemented by the target pack.

---

## How You Use It

All interaction happens through the **SOCFWPackManager** command in the Playground.

### List Available Packs

Use this to see which SOC Framework packs are available for installation:

`!SOCFWPackManager action=list`

---

### Apply a Pack by ID

Use the pack ID from the list command to install or update a pack:

`!SOCFWPackManager action=apply pack_id=<pack_id>`

**Example:**

`!SOCFWPackManager action=apply pack_id=soc-framework-unified`

---

## Recommended Starting Point

For most environments:

1. Install the base framework:
    - `soc-framework-unified`
2. Install one or more product enhancement packs as needed:
    - Example: `soc-crowdstrike-falcon`

Product enhancement packs extend vendor capabilities but **require the corresponding Marketplace integration** to be installed and configured separately.

---

## Design Philosophy

- **Composable** — install only what you need
- **Idempotent** — safe to re-run apply commands
- **Vendor-agnostic** — works alongside existing Marketplace integrations
- **Field-driven** — optimized for real SOC workflows, not static templates

---

For pre-install requirements and post-install usage examples, refer to the accompanying PRE and POST documentation included with this pack.

## Command Reference

For a complete list of supported commands and arguments, see:

➡️ **[SOCFWPackManager Command Reference](README_COMMANDS.md)**
