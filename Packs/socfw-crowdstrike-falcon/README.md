# SOC CrowdStrike Falcon Integration Enhancement for Cortex XSIAM

This pack supplements the native CrowdStrike Falcon integration within Palo Alto Networks
Cortex XSIAM. It provides SOC Framework-aligned detection rules and data normalization that
replace the default per-tactic correlation rules and feed enriched endpoint telemetry into
the NIST IR lifecycle.

---

## What's Included

| Component | Description |
|---|---|
| **Correlation Rule** | `SOC CrowdStrike Falcon - Endpoint Alerts` — unified rule replacing 15 per-tactic rules. Fires on all EPP detections. Alert category set dynamically from MITRE tactic via `user_defined_category: tactic`. Suppression per `composite_id` / 1hr. |
| **Modeling Rule** | `SOC CrowdStrike Falcon Modeling Rule` — maps raw EPP events to XDM fields including `xdm.source.*`, `xdm.event.*`, `xdm.alert.*`, and `xdm.source.process.*`. Feeds XSIAM analytics and identity stories. |

---

## What Changed from 1.0.14

> **Important — Pack ID Change**
> This pack has a new ID (`socfw-crowdstrike-falcon`). The previous pack (`socfw-crowdstrike-falcon`)
> will remain installed alongside it. This is intentional — it prevents the new pack from
> overwriting layouts, scripts, and correlation rules from the old pack that may still be active.
>
> **Duplicate alert risk:** if old per-tactic rules and the new consolidated rule are both enabled
> at the same time, every CrowdStrike detection will generate two alerts. Before enabling the new
> rule, disable all old rules. See `POST_CONFIG_README.md` Step 2 for the full list.

Version 1.1.0 consolidates the original 15-rule architecture into a single rule:

- **Single correlation rule** replaces 15 per-tactic rules plus a catch-all. XSIAM's `user_defined_category: tactic` feature (not available at the time of 1.0.14) allows dynamic alert categorization from the MITRE tactic field, making per-tactic rules unnecessary
- **No classifier or mapper** — field normalization is handled directly in the correlation rule XQL via `alert_fields`. The `CrowdStrike Falcon` classifier, incoming mapper, and outgoing mapper are not needed and should not be configured on the integration instance
- **Backwards compatible alert_fields** — all alert field mappings from the 1.0.14 per-tactic rules are preserved in the consolidated rule, including CGO fields (`causality_actor_process_*`) and `deviceou`

---

## Prerequisites

- Cortex XSIAM tenant with CrowdStrike Falcon data flowing into `crowdstrike_falcon_event_raw`
- CrowdStrike Falcon marketplace pack installed and integration instance active
- SOC Optimization Framework pack (`soc-optimization-unified`) installed

> **Note:** If using the **CrowdStrike Platform** (Event Stream API) integration instead of
> the standard CrowdStrike Falcon integration, disable Alert Fetch on that instance.
> The correlation rule operates on `crowdstrike_falcon_event_raw` which is populated by the
> standard Falcon integration, not the Platform integration.

---

## Installation

```bash
demisto-sdk upload -i Packs/socfw-crowdstrike-falcon
```

See `POST_CONFIG_README.md` for required manual steps after installation, including
disabling old per-tactic rules and enabling the consolidated rule.

---

## Analyst Benefits

- **Dynamic MITRE categorization** — alert category set from the actual tactic value; no hardcoded per-tactic rule maintenance
- **Cross-source case grouping** — `actor_effective_username`, `action_file_sha256`, `dns_query_name`, and `action_remote_ip` enable XSIAM to group related endpoint and email alerts into the same case automatically
- **NIST IR lifecycle integration** — endpoint alerts route through `Foundation_-_Product_Classification_V3` into the full Analysis → Containment → Eradication → Recovery chain

---

## Related Resources

- [SOC Optimization Framework](https://github.com/Palo-Cortex/secops-framework)
- [CrowdStrike Falcon API Documentation](https://falcon.crowdstrike.com/support/documentation)
- [Cortex XSIAM Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsiam)
