# Packs

Vendor and data-source packs that plug into the framework. Each pack
contributes coverage for a specific product (an EDR, an identity provider,
an email security gateway, etc.) and inherits the framework's lifecycle
without reimplementing it.

## How a pack works

Every pack does three things:

1. **Models its raw data** — modeling rules and a `_schema.json` that
   teach XSIAM how to parse the vendor's events.
2. **Generates alerts** — correlation rules that fire on the modeled data,
   stamped with the framework's standard `alert_fields`.
3. **Normalizes into the framework namespace** — Foundation playbooks pick
   up the alert and route it through the lifecycle. Pack-specific
   normalization happens in per-product playbooks gated by category.

A pack does *not* re-implement the lifecycle. The framework's phase
playbooks read what the pack produces and run the same Analysis →
Containment → Eradication → Recovery flow regardless of which pack
generated the alert.

## How to read a pack page

Each pack has at least an **Overview** page (auto-generated from its
`xsoar_config.json`) listing what gets installed. Packs with schema files
also have **Schema** pages documenting the modeling rules and correlation
rule alert fields. The right TOC on each page jumps you to the section
you need.

## What's listed below

The left rail lists all visible vendor packs alphabetically by pack id.
Click into any pack for its overview and schema reference.
