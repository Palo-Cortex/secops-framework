# SOC Abnormal Security — Post-Installation Steps

> **Warning — Duplicate Alerts**
> If any pre-existing or auto-generated Abnormal Security correlation rules are still
> enabled when the SOC Framework rule is enabled, every Abnormal detection will generate
> two alerts. Complete Step 2 (disable other rules) before Step 3 (enable the SOC rule).

This pack deploys the SOC Framework correlation rule for Abnormal Security email threats.
The data is collector-fed — the rule reads `abnormal_security_email_protection_raw` — so no
integration instance or mapper is required. The steps below must be completed after
installation before alerts will flow correctly.

---

## Step 1 — Configure the Abnormal Security Data Source

1. Navigate to **Settings → Configurations → Data Collection → Data Sources & Integrations**
2. Add / enable the **Abnormal Security** data source (HTTP Log Collection)
3. Confirm events land in `abnormal_security_email_protection_raw`:

```xql
dataset = abnormal_security_email_protection_raw
| filter attackType != null
| fields _time, attackType, attackVector, recipientAddress, senderDomain
| limit 10
```

> No classifier or mapper is needed — field normalization is handled by the correlation
> rule via `alert_fields`, not a mapper.

---

## Step 2 — Disable Any Other Abnormal Correlation Rules

Any system-generated or previously installed Abnormal correlation rule will conflict with
the SOC Framework rule and produce duplicate alerts.

1. Navigate to **Detection & Threat Intel → Correlations**
2. Filter the **Name** column for `Abnormal`
3. Disable any non-SOC rules that are currently enabled — the SOC Framework rule replaces them

---

## Step 3 — Enable the SOC Framework Correlation Rule

XSIAM imports pack correlation rules **disabled** by default, regardless of pack settings.

1. Navigate to **Detection & Threat Intel → Correlations**
2. Filter the **Name** column for `SOC Abnormal`
3. Locate **`SOC Abnormal Security - Threat Detected All Alerts`**
4. Right-click → **Enable**

> **What this rule does:** fires on any Abnormal detection where `attackType` is present
> (blank verdicts are filtered out), naming alerts
> `[Email] {recipient} - Initial Access: {attackType} Email Detected`. It is `SCHEDULED`
> (`*/10 * * * *`, 20-minute search window) because the dataset is collector-fed. MITRE is
> derived per-alert from `attackVector` (Link → **T1566.002**, Attachment → **T1566.001**,
> otherwise **T1566**) under Initial Access (**TA0001**) — there is no static rule-level
> ATT&CK mapping. Suppression is per `abxMessageId` with a 24-hour window. Identity resolves
> **email-first** — the recipient is normalized to a canonical, unquoted email that matches
> endpoint sources' `user_name` for cross-source case grouping.

---

## Step 4 — Verify SOCProductCategoryMap_V3

Confirm the Abnormal data source routes to the **Email** product category. Run in a
playground war room:

```
!core-api-post uri="/lists/v2/get_indicator_by_value"
body={"list_name": "SOCProductCategoryMap_V3", "value": "ds_abnormal_security_email_protection"}
```

Confirm `product_map` routes Abnormal to `"Email"`. If the entry is missing, add it so
issues land under the Email product category and NIST IR lifecycle.

---

## Step 5 — *(Optional)* Enable CIE identity enrichment

By default the rule resolves identity inline (email-first). To instead resolve identity from
`socfw_identity_map` (SID/SAM/UPN → canonical email across vendors):

1. Confirm the CIE chain is live: Cloud Identity Engine → `pan_dss_raw` → `SOC IdentityResolve`
   → `socfw_identity_map` (with `SOC IdentityResolve` enabled).
2. Edit the rule's XQL and **delete the `/*` and `*/` lines** wrapping the CIE overlay block.

The overlay coalesces `socfw_identity_map` values **over** the inline identity — the
alert-field mappings don't change, so nothing downstream is affected. Until the chain is live
the join no-ops and the rule keeps running flat.

---

## What Is Not Required

| Item | Status | Reason |
|---|---|---|
| Integration instance | Not required | Collector-fed; rule reads `abnormal_security_email_protection_raw` directly |
| Classifier / Mapper | Not required | Field normalization handled in the correlation rule via `alert_fields` |
| Custom incident fields | Not required | `socfw*` fields populated directly and read by Foundation playbooks |
