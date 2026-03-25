# SOC Microsoft Defender for Endpoint — Post-Installation Steps

---

## Step 1 — Configure the Microsoft Graph Integration Instance

1. Navigate to **Settings → Configurations → Data Collection → Automation & Feed Integrations**
2. Find the Microsoft Graph (O365 Data Source) instance and open its configuration
3. Enable **Fetch events using Microsoft Graph Alerts v2**
4. Leave **Classifier** and **Mapper (incoming)** empty
5. Click **Test**, then **Save & Exit**
6. Confirm the instance is **enabled**

---

## Step 2 — Disable Old MDE Correlation Rules

1. Navigate to **Detection & Threat Intel → Correlations**
2. Filter for `Microsoft` or `Defender`
3. Disable any non-SOC rules to prevent duplicate alerts

---

## Step 3 — Enable the SOC Framework Correlation Rule

1. Navigate to **Detection & Threat Intel → Correlations**
2. Locate **SOC Microsoft Graph Defender EndPoint** and right-click → **Enable**

> Fires on all MDE alerts (`serviceSource = "microsoftDefenderForEndpoint"`), excludes
> resolved alerts, and names alerts as `[Endpoint] {hostname} | {category} | {technique}`.
> Suppression per `providerAlertId` / 1hr.

---

## Step 4 — Verify SOCProductCategoryMap_V3

Run in a playground war room:
```
!core-api-post uri="/lists/v2/get_indicator_by_value"
body={"list_name": "SOCProductCategoryMap_V3", "value": "ds_msft_graph_security_alerts"}
```

Confirm `product_map` includes `"Microsoft Defender for Endpoint": "Endpoint"`.

---

## Step 5 — Verify the Modeling Rule

1. Navigate to **Settings → Configurations → Data Management → Data Model Rules**
2. Confirm **MSGraphMDE_ModelingRule** is listed and active
3. Validate:

```xql
datamodel dataset in("msft_graph_security_alerts_raw")
| filter xdm.observer.product = "Microsoft Defender for Endpoint"
| fields xdm.event.id, xdm.alert.name, xdm.alert.severity,
         xdm.event.original_event_type, xdm.observer.product
| limit 5
```
