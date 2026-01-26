# SOCFWPackManager — Command Reference

This document provides a complete reference for all supported **SOCFWPackManager** commands and arguments.

All commands are executed from the **Playground**.

---

## Command Syntax

`!SOCFWPackManager <arguments>`

All behavior is controlled via arguments.

---

## Core Arguments

### `action` (required)
Specifies the operation to perform.

**Supported values:**
- `list`
- `apply`

---

### `pack_id`
Specifies the SOC Framework pack to operate on.

- Required for `action=apply`
- Optional for `action=list` when filtering

**Example:**
`pack_id=soc-framework-unified`

---

### `pre_config_done`
Confirms that required pre-install configuration has been completed.

- Type: `true | false`
- Default: `false`
- Required when applying the SOC Framework Manager pack itself

**Example:**
`pre_config_done=true`

---

## Actions

---

## `action=list`

Lists SOC Framework packs available from the configured catalog.

### Basic Usage
`!SOCFWPackManager action=list`

---

### Filtered Listing (Development & Testing)

You can narrow the list using optional filters.

#### Filter by Pack ID (partial match)
`!SOCFWPackManager action=list pack_id=soc-framework`

#### Filter by Environment (if supported by catalog)
`!SOCFWPackManager action=list environment=main`

`!SOCFWPackManager action=list environment=develop`

#### Filter by Category / Type (if supported)
`!SOCFWPackManager action=list category=enhancement`

> Useful during development when validating which packs are exposed in a given environment.

---

## `action=apply`

Installs or updates a SOC Framework pack by ID.

### Basic Usage
`!SOCFWPackManager action=apply pack_id=<pack_id>`

**Example:**
`!SOCFWPackManager action=apply pack_id=soc-framework-unified`

---

### Apply with Pre-Config Confirmation

Required when installing **SOC Framework Manager** itself.

`!SOCFWPackManager action=apply pack_id=soc-framework-manager pre_config_done=true`

---

### Development & Testing Options

#### Dry Run (no changes applied)
Runs validation and planning logic without installing anything.

`!SOCFWPackManager action=apply pack_id=soc-framework-unified dry_run=true`

---

#### Include Hidden / Dev Packs
Lists or applies packs marked as hidden or development-only.

`!SOCFWPackManager action=list include_hidden=true`

`!SOCFWPackManager action=apply pack_id=soc-framework-unified include_hidden=true`

---

#### Skip Validation (Advanced / Testing)
Skips certain validation steps during development.

`!SOCFWPackManager action=apply pack_id=soc-framework-unified skip_validation=true`

> Intended for development and testing only.

---

#### Retry Behavior (Large Packs / Network Issues)

`retry_count` – Number of retries  
`retry_sleep_seconds` – Delay between retries

**Example:**
`!SOCFWPackManager action=apply pack_id=soc-framework-unified retry_count=5 retry_sleep_seconds=15`

---

## Common Installation Flow

### 1. List available packs
`!SOCFWPackManager action=list`

---

### 2. Install the base framework
`!SOCFWPackManager action=apply pack_id=soc-framework-unified`

---

### 3. Install product enhancement packs
`!SOCFWPackManager action=apply pack_id=soc-crowdstrike-falcon`

> Product enhancement packs require the corresponding **Marketplace integration**
> to be installed and configured separately.

---

## Notes & Best Practices

- `apply` is designed to be **safe to re-run**
- Marketplace integrations are **not installed automatically**
- Behavior varies by pack depending on what automation it provides
- Development flags should not be used in production unless explicitly required

---

This document is intended as a **quick reference**.  
For installation prerequisites, see **README_PRE.md**.
