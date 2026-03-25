# SOC Proofpoint TAP - Post-Installation Steps

This pack deploys the SOC Framework correlation and modeling rules for Proofpoint TAP v2.
The steps below must be completed after installation before alerts will flow correctly.

---

## Step 1 — Configure the Proofpoint TAP Integration Instance

The pack installs a pre-configured `Proofpoint TAP v2` integration instance with the
correct settings. You only need to supply credentials and enable it.

1. Navigate to **Settings → Configurations → Data Collection → Automation & Feed Integrations**
2. Find the `Proofpoint TAP v2` instance and open its configuration
3. Fill in the following fields:
   - **Server URL** — defaults to `https://tap-api-v2.proofpoint.com` (change only if required)
   - **Service Principal** — your TAP API service principal
   - **Password** — your TAP API service secret
4. Leave **Classifier** and **Mapper (incoming)** empty — field normalization is handled
   by the correlation rule and modeling rule, not a mapper
5. Click **Test** to verify connectivity
6. Click **Save & Exit**
7. **Enable** the instance

> **One instance is sufficient.** The integration is configured to fetch all event types
> (messages delivered and clicks permitted) from a single instance. Do not create separate
> instances per event type.

---

## Step 2 — Disable the System Proofpoint Correlation Rule

The Proofpoint TAP marketplace pack installs a system-generated correlation rule that will
conflict with the SOC Framework rule and produce duplicate alerts.

1. Navigate to **Detection & Threat Intel → Correlations**
2. Filter the **Name** column for `Proofpoint`
3. Locate **Proofpoint TAP v2 Alerts (automatically generated)**
4. Right-click → **Disable**

> Disable any other pre-existing Proofpoint correlation rules that are currently enabled.
> The SOC Framework rule replaces all of them.

---

## Step 3 — Enable the SOC Framework Correlation Rule

The SOC Framework rule ships disabled to allow side-by-side validation before cutover.

1. Navigate to **Detection & Threat Intel → Correlations**
2. Filter the **Name** column for `SOC Proofpoint`
3. Locate **SOC Proofpoint TAP - Threat Detected**
4. Right-click → **Enable**

> **What this rule does:** fires on `messages delivered` and `clicks permitted` events where
> the threat status is `active` or `malicious`. Benign deliveries are filtered out before
> alert generation. Suppression is per `GUID` with a 24-hour window.

---

## Step 4 — Verify the Modeling Rule

The modeling rule normalizes raw TAP events into XDM fields used by XSIAM analytics,
network stories, and identity stories.

1. Navigate to **Settings → Configurations → Data Management → Data Model Rules**
2. Confirm **SOC ProofpointTAP Modeling Rule** is listed and active
3. Run a quick validation query in XQL Search:

```xql
datamodel dataset in("proofpoint_tap_v2_generic_alert_raw")
| fields xdm.event.id, xdm.email.sender, xdm.email.recipients, xdm.source.user.username,
         xdm.alert.original_threat_name, xdm.email.delivery_timestamp
| limit 5
```

If rows return with populated fields, the modeling rule is working correctly.

---

## Step 5 — (Recommended) Configure Starred Alerts

Incidents not marked with a star are auto-triaged by `JOB_-_Triage_Incidents`. Configure
a starring rule so high-fidelity click events reach analysts for manual review.

1. Navigate to **Incident Response → Automation → Incident Configuration → Starred Alerts**
2. Create a new rule:
   - **Configuration Name:** `Proofpoint Clicks Permitted`
   - **Alert Filter:** `alert domain = Security AND alert name contains Click Permitted AND tags = DS:Proofpoint TAP v2`

---

## What Is Not Required

The following items from older versions of this pack are **no longer needed** and should
not be configured:

| Old Requirement | Status | Reason |
|---|---|---|
| Two separate integration instances (Clicks / Messages) | Removed | Single instance with `Events to fetch: All` replaces both |
| Classifier (`Proofpoint TAP Classifier`) | Removed | Field mapping handled natively in correlation rule via `alert_fields` |
| Mapper (incoming) | Removed | No incident field mapping required; `socfw*` fields populated directly |
| Layout rules | Removed | Not included in this pack version |
| Custom incident fields (`proofpointtap*`) | Removed | Replaced by `socfw*` fields read by Foundation playbooks |
