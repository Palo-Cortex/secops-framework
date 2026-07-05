# SOC Wiz Cloud — Vendor Pack

SOC Framework detection and normalization for Wiz / Wiz Defend cloud findings on Cortex XSIAM.
Reshapes each finding into the SOC Framework **Cloud** product category and routes it through
the existing NIST IR lifecycle (SP 800-61) so cloud findings group and respond alongside
endpoint, email, and identity telemetry instead of landing as isolated cloud alerts.

## Overview

Wiz emits cloud security findings — misconfigurations, exposures, identity risks, and (with
Wiz Defend) runtime threats. This pack normalizes them to the framework contract:

- **Cloud normalization** — provider, account, region, resource, and finding surfaced as
  `issue.*` fields for Foundation playbook consumption.
- **Host-axis grouping** — when the resource is a compute instance, `agent_hostname` carries
  the VM hostname, so a Wiz finding groups with EDR runtime detections on the same host. Null
  for non-compute resources (buckets, IAM) so no junk pivots are manufactured.
- **Email-first identity** — user-type entities (accounts, identities, service accounts)
  resolve to a canonical `username`. With CIE enabled, the entity is matched into
  `socfw_identity_map` to recover the real directory email, so a cloud identity finding groups
  with that person's endpoint and email alerts.

## Pack Contents

| Component | Description |
|---|---|
| **Correlation Rule** | `SOC Wiz Finding` — one consolidated rule for Wiz findings. Normalizes the cloud surface, applies `[Cloud] {provider} \| {resource} \| {finding}` naming, carries the host-axis pivot, and resolves identity email-first. Ships an optional CIE (`socfw_identity_map`) enrichment overlay commented-out and **OFF by default**. |
| **Modeling Rule** | `Wiz Findings Modeling Rule` — maps the alert/event/observer XDM surface (`xdm.alert.*`, `xdm.event.*`, `xdm.observer.*`). Cloud provider/account/resource ride the correlation rule's `alert_fields` at `issue.*` (the Data Model has no `xdm.cloud.*` paths). |

## Dependencies

- `soc-optimization-unified` — Foundation layer (Universal Command, lists, lookups)
- `soc-framework-nist-ir` — NIST IR lifecycle playbooks

## Value Driver Alignment

- **VD1 — Reduce Risk** — cloud findings enter the NIST IR lifecycle; cross-source grouping
  collapses a person's or host's related alerts into one case.
- **VD3 — Operational Efficiency** — one consolidated rule, host- and identity-axis grouping,
  and config-finding noise reduction free analyst triage time.

## Identity Enrichment (CIE)

By default the rule resolves identity inline and runs `REAL_TIME`. To resolve cloud identity
entities to real directory users via `socfw_identity_map`, enable the CIE overlay — see
`POST_CONFIG_README.md` Step 3.

## Shadow Mode

All Containment, Eradication, and Recovery actions ship with `shadow_mode: true`.
To go live: flip `shadow_mode` to `false` in `SOCFrameworkActions_V3` for each action.

## Version History

| Version | Change |
|---------|--------|
| 1.0.0   | Initial release |
