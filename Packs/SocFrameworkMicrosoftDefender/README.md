# SOC Microsoft Defender for Endpoint Integration Enhancement

This pack supplements the native Microsoft Graph Security Alerts integration within
Cortex XSIAM for Microsoft Defender for Endpoint telemetry. It provides a SOC Framework-aligned
correlation rule and XDM modeling rule feeding enriched endpoint alerts into the NIST IR lifecycle.

---

## What's Included

| Component | Description |
|---|---|
| **Correlation Rule** | `SOC Microsoft Graph Defender EndPoint` — unified rule for MDE alerts from `msft_graph_security_alerts_raw`. Fires on `microsoftDefenderForEndpoint` serviceSource, excludes resolved alerts. Evidence extracted inline via XQL. Suppression per `providerAlertId` / 1hr. |
| **Modeling Rule** | `MSGraphMDE_ModelingRule` — maps raw MDE alert fields to XDM fields including `xdm.event.*`, `xdm.alert.*`, and `xdm.observer.*`. Scoped to `serviceSource = "microsoftDefenderForEndpoint"`. |

---

## Prerequisites

- Cortex XSIAM tenant with Microsoft Graph Security Alerts data flowing into `msft_graph_security_alerts_raw`
- Office 365 Data Source configured with **Microsoft Graph Alerts v2** alert fetch enabled
- Microsoft Defender Advanced Threat Protection marketplace pack installed (for automation commands)
- SOC Optimization Framework pack (`soc-optimization-unified`) installed
- `ds_msft_graph_security_alerts` entry in `SOCProductCategoryMap_V3` with `"Microsoft Defender for Endpoint": "Endpoint"` in `product_map`

---

## Installation

```bash
demisto-sdk upload -i Packs/soc-microsoft-defender
```

See `POST_CONFIG_README.md` for required manual steps after installation.

---

## Cross-Source Grouping

MDE alerts group with Proofpoint TAP and other email sources via shared alert fields:

- `agent_hostname` — device hostname from deviceEvidence
- `actor_effective_username` — UPN from processEvidence or userEvidence
- `action_remote_ip` — remote IP from ipEvidence (C2 / lateral movement)
- `actor_process_image_sha256` — SHA256 of initiating process

MDE alerts group with other MDE alerts from the same Microsoft Security Graph incident via
`incidentId` mapped to the `cid` grouping key.

---

## NIST IR Lifecycle

Endpoint alerts route through `Foundation_-_Product_Classification_V3` into the full
Analysis → Containment → Eradication → Recovery chain. All C/E/R actions execute in
Shadow Mode by default. See `SOCExecutionList_V3` for shadow mode configuration.

---

## Related Resources

- [SOC Optimization Framework](https://github.com/Palo-Cortex/secops-framework)
- [Microsoft Graph Security Alerts API](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview)
- [Cortex XSIAM Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsiam)
