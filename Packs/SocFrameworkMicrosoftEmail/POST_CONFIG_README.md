# SOC Microsoft Defender for Office 365 — Post-Installation Steps

---

## Step 1 — Configure the Microsoft Graph Integration Instance

1. Navigate to **Settings → Configurations → Data Collection → Automation & Feed Integrations**
2. Find the Microsoft Graph (O365 Data Source) instance and open its configuration
3. Enable **Fetch events using Microsoft Graph Alerts v2**
4. Leave **Classifier** and **Mapper (incoming)** empty
5. Click **Test**, then **Save & Exit**
6. Confirm the instance is **enabled**

> If the `soc-microsoft-defender` (Endpoint) pack is also installed, this step is already
> complete — both packs share the same integration instance.

---

## Step 2 — Enable the SOC Framework Correlation Rule

1. Navigate to **Detection & Threat Intel → Correlations**
2. Locate **SOC MDO365 - Email Threat Detected** and right-click → **Enable**

> Fires on high/medium MDO365 alerts in InitialAccess and LateralMovement categories.
> Suppression per `emailmessageid` / 24hr to prevent duplicate alerts from Microsoft
> auto-remediation sequences.

---

## Step 3 — Verify SOCProductCategoryMap_V3

Run in a playground war room:
```
!core-api-post uri="/lists/v2/get_indicator_by_value"
body={"list_name": "SOCProductCategoryMap_V3", "value": "ds_msft_graph_security_alerts"}
```

Confirm `product_map` includes `"Microsoft Defender for Office 365": "Email"`.

---

## Step 4 — Verify the Modeling Rule

1. Navigate to **Settings → Configurations → Data Management → Data Model Rules**
2. Confirm **MSGraphMDO365_ModelingRule** is listed and active
3. Validate:

```xql
datamodel dataset in("msft_graph_security_alerts_raw")
| filter xdm.observer.product = "Microsoft Defender for Office 365"
| fields xdm.event.id, xdm.alert.name, xdm.alert.severity,
         xdm.event.original_event_type, xdm.observer.product
| limit 5
```
