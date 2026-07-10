# soc-cortex-xpanse-posture

SOC Framework — Vendor Pack

## Overview

<!-- Describe what this pack detects/responds to. -->

## Pack Contents

<!-- List correlation rules, modeling rules, playbooks, etc. -->

## Dependencies

- `soc-optimization-unified` — Foundation layer (Universal Command, lists, lookups)
- `soc-framework-nist-ir` — NIST IR lifecycle playbooks

## Value Driver Alignment

<!-- Which of VD1/VD2/VD3/VD4 does this pack serve, and which metric proves it? -->

## Shadow Mode

All Containment, Eradication, and Recovery actions ship with `shadow_mode: true`.
To go live: flip `shadow_mode` to `false` in `SOCFrameworkActions_V3` for each action.

## Version History

| Version | Change |
|---------|--------|
| 1.0.0   | Initial release |
