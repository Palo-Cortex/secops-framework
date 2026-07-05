# SOC Wiz Cloud — Post-Installation Steps

Complete these after installing the pack: enable the rule, verify, and (optionally) enable CIE
identity enrichment. Prerequisites are in the pack **README**.

---

## Step 1 — Enable the correlation rule

XSIAM imports pack correlation rules **disabled** by default, regardless of pack settings.

1. **Detection & Threat Intel → Correlations**
2. Filter the **Name** column for `SOC Wiz`
3. Find **`SOC Wiz Finding`** → right-click → **Enable**

> If a native or previously hand-built Wiz correlation rule is still enabled, disable it so
> findings don't double-alert — the consolidated SOC Framework rule replaces it.

---

## Step 2 — Verify

Confirm findings reshape correctly (cloud surface populated, values clean):

```xql
dataset = wiz_generic_alert_raw
| filter _alert_data != null
| alter resource_type = coalesce(json_extract_scalar(entitysnapshot, "$.nativeType"), json_extract_scalar(entitysnapshot, "$.type")),
        resource_name = json_extract_scalar(entitysnapshot, "$.name")
| fields resource_type, resource_name
| limit 10
```

- `resource_name` reads as a clean value (no surrounding quotes).
- New issues land under **Cases**, routed to the **Cloud** product category and NIST IR
  lifecycle.
- Compute-resource findings carry `agent_hostname` (the VM hostname) so they group with EDR
  detections on the same host; user-type findings resolve an email-first `username`.

---

## Step 3 — *(Optional)* Enable CIE identity enrichment

By default the rule resolves identity inline and runs `REAL_TIME`. To resolve cloud identity
entities (accounts, identities, service accounts) to their real directory user via
`socfw_identity_map` (matched on display name):

1. Confirm the CIE chain is live: Cloud Identity Engine → `pan_dss_raw` → `SOC IdentityResolve`
   → `socfw_identity_map` (with `SOC IdentityResolve` enabled).
2. Edit the rule's XQL and **delete the `/*` and `*/` lines** wrapping the `CIE ENRICHMENT`
   block.
3. Set the rule to **Scheduled**: crontab `*/10 * * * *`, search window `25 hours`, schedule
   `10 minutes`.

The overlay coalesces `socfw_identity_map` values **over** the inline identity — the
alert-field mappings don't change, so nothing downstream is affected. Non-identity findings
(misconfigurations, exposures) are unaffected; only user-type entities are resolved.

---

## What Is Not Required

| Item | Status | Reason |
|---|---|---|
| Separate per-finding-type correlation rules | Not used | One consolidated `SOC Wiz Finding` rule |
| Classifier / Mapper | Not used | Normalization is done in the correlation rule XQL via `alert_fields` |
| Crown-jewel registry join | Not shipped here | The governance-tag severity bump is a tenant-specific customization; add it separately with sanitized placeholders if required |
