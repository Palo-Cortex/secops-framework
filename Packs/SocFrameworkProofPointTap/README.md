# SOC Proofpoint TAP Integration Enhancement for Cortex XSIAM

This pack supplements the native Proofpoint TAP v2 integration within Palo Alto Networks
Cortex XSIAM. It provides SOC Framework-aligned detection rules and data normalization that
replace the default Proofpoint correlation rule, reduce alert volume to actionable signals
only, and feed enriched email threat data into the NIST IR lifecycle.

---

## What's Included

| Component | Description |
|---|---|
| **Correlation Rule** | `SOC Proofpoint TAP - Threat Detected` — unified rule covering messages delivered and clicks permitted. Fires on active/malicious threat status only. Suppression per GUID/24hr. Populates `socfw*` fields for Foundation playbook consumption. |
| **Modeling Rule** | `SOC ProofpointTAP Modeling Rule` — maps raw TAP events to XDM fields including `xdm.email.*`, `xdm.alert.*`, `xdm.source.*`, and `xdm.target.url`. Feeds XSIAM network stories and identity analytics. |

---

## What Changed from 1.0.x

> **Important — Pack ID Change**
> This pack has a new ID (`socfw-proofpoint-tap`). The previous pack (`soc-proofpoint-tap`)
> will remain installed alongside it. This is intentional — it prevents the new pack from
> overwriting layouts and correlation rules from the old pack that may still be active.
>
> **Duplicate alert risk:** if old Proofpoint rules and the new consolidated rule are both
> enabled at the same time, every TAP detection will generate two alerts. Before enabling
> the new rule, disable all old rules. See `POST_CONFIG_README.md` Step 2 for the full list.

Version 1.3.0 consolidates and simplifies the original two-rule, two-instance architecture:

- **Single integration instance** — one `Proofpoint TAP v2` instance with `Events to fetch: All` replaces the separate Clicks Permitted and Messages Delivered instances
- **No classifier or mapper** — field normalization is handled directly in the correlation rule XQL via `alert_fields` mappings. The `Proofpoint TAP Classifier` and incoming mapper are not needed and should not be configured
- **No custom incident fields** — `proofpointtap*` custom fields replaced by `socfw*` fields read natively by `Foundation_-_Normalize_Email_V3`

---

## Analyst Benefits

- **Reduced alert volume** — threat status filter eliminates benign deliveries before alert creation; only `active` or `malicious` threats generate alerts
- **Cross-source case grouping** — `actor_effective_username` (recipient), `action_file_sha256` (attachment hash), `dns_query_name`, and `action_remote_ip` enable XSIAM to group related email and endpoint alerts into the same case automatically
- **NIST IR lifecycle integration** — `socfw*` fields feed `Foundation_-_Normalize_Email_V3` directly, enabling the full Analysis → Containment → Eradication → Recovery chain without manual triage
- **XDM story stitching** — `xdm.source.ipv4 = clickIP` and `xdm.source.user.username = recipient` feed XSIAM network and identity story engines across sources

---

## Requirements

- Cortex XSIAM tenant with Proofpoint TAP v2 data flowing into `proofpoint_tap_v2_generic_alert_raw`
- SOC Optimization Framework pack (`soc-optimization-unified`) installed

---

## Installation

```bash
demisto-sdk upload -i Packs/SocFrameworkProofPointTap
```

See `POST_CONFIG_README.md` for required manual steps after installation.

---

## Related Resources

- [SOC Optimization Framework](https://github.com/Palo-Cortex/secops-framework)
- [Proofpoint TAP API Documentation](https://threatinsight.proofpoint.com)
- [Cortex XSIAM Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsiam)
