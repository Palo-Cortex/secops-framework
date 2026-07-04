# SOC CrowdStrike Falcon SaaS — Post-Installation Steps

Complete these after installing the pack: two required (enable → verify) and one optional
(CIE enrichment). Prerequisites are in the pack **README** (*Before you install*).

---

## Step 1 — Enable the correlation rule

XSIAM imports pack correlation rules **disabled** by default, regardless of pack settings.

1. **Detection & Threat Intel → Correlations**
2. Filter the **Name** column for `SOC CrowdStrike`
3. Find **`SOC CrowdStrike Falcon - SaaS All Alerts`** → right-click → **Enable**

> The rule ships `is_enabled: true`; if your tenant already imported it enabled, skip this step.
> If a native CrowdStrike marketplace rule for SaaS is enabled, disable it so detections
> don't double-alert.

---

## Step 2 — Verify

Confirm SaaS detections are reshaping correctly:

```
dataset = crowdstrike_falcon_event_raw
| filter product = "saas-security"
| fields user_name, actor_effective_username, alert_name, originalalertsource, country, mitre_attack
| limit 10
```

- `user_name` / `actor_effective_username` read as **emails** for real users (machine/`$`
  accounts keep their name).
- `originalalertsource` identifies the product classification.
- New issues land under **Cases**, routed to the correct product category and NIST IR lifecycle.

---

## Step 3 — *(Optional)* Enable CIE identity enrichment

Resolve identity from `socfw_identity_map` (SID/SAM/UPN → canonical email across vendors)
instead of the event alone.

1. Confirm the CIE chain is live: Cloud Identity Engine → `pan_dss_raw` → `SOC IdentityResolve`
   → `socfw_identity_map` (with `SOC IdentityResolve` enabled).
2. Edit the rule's XQL and **delete the `/*` and `*/` lines** wrapping the `CIE ENRICHMENT`
   block.
3. Set the rule to **Scheduled**: crontab `*/10 * * * *`, search window `25 hours`, schedule
   `10 minutes`.

The overlay coalesces `socfw_identity_map` values **over** the flat identity — the alert-field
mappings don't change. Until the chain is live the join no-ops and the rule keeps running flat.
