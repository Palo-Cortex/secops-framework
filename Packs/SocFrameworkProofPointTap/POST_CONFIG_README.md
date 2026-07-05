# SOC Proofpoint TAP - Post-Installation Steps

> **Warning — Duplicate Alerts**
> This pack (`socfw-proofpoint-tap`) installs alongside the previous pack
> (`soc-proofpoint-tap`) — it does not replace it. If any old Proofpoint correlation
> rules are still enabled when the new consolidated rule is enabled, every TAP detection
> will generate two alerts. Complete Step 2 (disable old rules) before Step 3
> (enable new rule).

This pack deploys the SOC Framework correlation and modeling rules for Proofpoint TAP v2.
The steps below must be completed after installation before alerts will flow correctly.

---

## Step 1 — Configure the Proofpoint TAP Integration Instance

The pack installs a pre-configured `Proofpoint TAP v2` integration instance with the
correct settings. You only need to supply credentials and enable it.

1. Navigate to **Settings → Configurations → Data Collection → Data Sources & Integrations**
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
> (messages delivered and clicks permitted) from a single instance.

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

XSIAM imports pack correlation rules **disabled** by default, regardless of pack settings.

1. Navigate to **Detection & Threat Intel → Correlations**
2. Filter the **Name** column for `SOC Proofpoint`
3. Locate **`SOC Proofpoint TAP - Threat Detected All Alerts`**
4. Right-click → **Enable**

> **What this rule does:** fires on `messages delivered` and `clicks permitted` events where
> the threat status is `active` or `malicious`. Benign deliveries are filtered out before
> alert generation. Suppression is per `GUID` with a 24-hour window. Identity resolves
> **email-first** — the recipient is normalized to a canonical, unquoted email that matches
> CrowdStrike `user_name` for cross-source case grouping. CIE enrichment is optional (Step 5).

---

## Step 4 — Verify

Confirm the recipient resolves to a clean, unquoted email — this is the cross-source grouping
key that must match CrowdStrike `user_name`:

```xql
dataset = proofpoint_tap_v2_generic_alert_raw
| filter type in ("messages delivered", "clicks permitted")
| alter recipient_upn = arrayindex(regextract(to_string(recipient), "([\w.%+-]+@[\w.-]+)"), 0)
| fields recipient_upn
| limit 10
```

- `recipient_upn` reads as a bare `user@domain` (no surrounding quotes). Quoted values will
  not group against endpoint sources.
- New issues land under **Cases**, routed to the **Email** product category and NIST IR
  lifecycle.

The modeling rule maps `senderIP → xdm.source.ipv4`; all other email context (sender,
recipients, subject, message-id, attachments, threat data) rides the correlation rule's
`alert_fields` at `issue.*`, not XDM. Confirm it is active under **Settings → Configurations
→ Data Management → Data Model Rules** (`SOC ProofpointTAP Modeling Rule`).

---

## Step 5 — *(Optional)* Enable CIE identity enrichment

By default the rule resolves identity inline (email-first) and runs `REAL_TIME`. To instead
resolve identity from `socfw_identity_map` (SID/SAM/UPN → canonical email across vendors):

1. Confirm the CIE chain is live: Cloud Identity Engine → `pan_dss_raw` → `SOC IdentityResolve`
   → `socfw_identity_map` (with `SOC IdentityResolve` enabled).
2. Edit the rule's XQL and **delete the `/*` and `*/` lines** wrapping the `CIE ENRICHMENT`
   block.
3. Set the rule to **Scheduled**: crontab `*/10 * * * *`, search window `25 hours`, schedule
   `10 minutes`.

The overlay coalesces `socfw_identity_map` values **over** the inline identity — the
alert-field mappings don't change, so nothing downstream is affected. Until the chain is live
the join no-ops and the rule keeps running flat.

---

## What Is Not Required

The following items from older versions of this pack are **no longer needed** and should
not be configured:

| Old Requirement | Status | Reason |
|---|---|---|
| Two separate integration instances (Clicks / Messages) | Removed | Single instance with `Events to fetch: All` replaces both |
| Classifier (`Proofpoint TAP Classifier`) | Removed | Field mapping handled natively in correlation rule via `alert_fields` |
| Mapper (incoming) | Removed | No incident field mapping required; `socfw*` fields populated directly |
| Custom incident fields (`proofpointtap*`) | Removed | Replaced by `socfw*` fields read by Foundation playbooks |
