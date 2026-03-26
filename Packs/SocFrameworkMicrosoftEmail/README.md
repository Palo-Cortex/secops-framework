# SOC Microsoft Defender for Office 365 Integration Enhancement

This pack supplements the native Microsoft Graph Security Alerts integration within
Cortex XSIAM for Microsoft Defender for Office 365 telemetry. It provides a SOC Framework-aligned
correlation rule and XDM modeling rule feeding enriched email threat alerts into the NIST IR lifecycle.

---

## What's Included

| Component | Description |
|---|---|
| **Correlation Rule** | `SOC MDO365 - Email Threat Detected` — fires on `microsoftDefenderForOffice365` serviceSource, high/medium severity, InitialAccess and LateralMovement categories. Maps to `fw_email_*` and `socfwemailthreat*` alert fields consumed by Foundation. Suppression per `emailmessageid` / 24hr. |
| **Modeling Rule** | `MSGraphMDO365_ModelingRule` — maps raw MDO365 email threat alert fields to XDM. Scoped to `serviceSource = "microsoftDefenderForOffice365"`. |

---

## Prerequisites

- Cortex XSIAM tenant with Microsoft Graph Security Alerts data flowing into `msft_graph_security_alerts_raw`
- Microsoft Graph (O365 Data Source) integration instance configured with **Microsoft Graph Alerts v2** alert fetch enabled
- SOC Optimization Framework pack (`soc-optimization-unified`) installed
- `ds_msft_graph_security_alerts` entry in `SOCProductCategoryMap_V3` with `"Microsoft Defender for Office 365": "Email"` in `product_map`

---

## Installation

```bash
demisto-sdk upload -i Packs/soc-microsoft-defender-email
```

See `POST_CONFIG_README.md` for required manual steps after installation.

---

## Cross-Source Grouping

MDO365 email alerts group with Proofpoint TAP via the shared `fw_email_*` field namespace —
both rules write to the same alert fields, enabling the XSIAM grouping engine to correlate
email threats across vendors into a single case.

MDO365 alerts also group with MDE endpoint alerts via `incidentId` when both are correlated
by the Microsoft Security Graph (same incident on the Microsoft side).

---

## NIST IR Lifecycle

Email alerts route through `Foundation_-_Product_Classification_V3` into the full
Analysis → Containment → Eradication → Recovery chain. All C/E/R actions execute in
Shadow Mode by default. See `SOCExecutionList_V3` for shadow mode configuration.

---

## Related Resources

- [SOC Optimization Framework](https://github.com/Palo-Cortex/secops-framework)
- [Microsoft Graph Security Alerts API](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview)
- [Cortex XSIAM Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsiam)
