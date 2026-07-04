# SOC CrowdStrike Falcon — Post-Installation Steps

Complete these after installing the pack: three required (enable → migrate → verify) and one
optional (CIE enrichment). Prerequisites are in the pack **README** (*Before you install*).

---

## Step 1 — Enable the correlation rule

XSIAM imports pack correlation rules **disabled** by default, regardless of pack settings.

1. **Detection & Threat Intel → Correlations**
2. Filter the **Name** column for `SOC CrowdStrike`
3. Find **`SOC CrowdStrike Falcon - Endpoint All Alerts`** → right-click → **Enable**

> The rule ships `is_enabled: true`; if your tenant already imported it enabled, skip this step.

---

## Step 2 — Disable legacy CrowdStrike rules *(migration only)*

If this tenant previously ran the per-tactic SOC rules or the native CrowdStrike marketplace
rule, disable them so detections don't **double-alert**. The single consolidated rule replaces
all of them.

1. **Detection & Threat Intel → Correlations**, filter **Name** for `CrowdStrike`
2. Disable any of these still enabled:
   - `CrowdStrike Falcon - Endpoint Alerts - <tactic>` (the 12–15 per-tactic rules)
   - `CrowdStrike Falcon (Catch-All) - Endpoint Alerts`
   - `CrowdStrike Falcon - Endpoint Alerts (automatically generated)`

---

## Step 3 — Verify

Confirm EPP detections are reshaping correctly:

```
dataset = crowdstrike_falcon_event_raw
| filter product = "epp"
| fields user_name, actor_effective_username, alert_name, originalalertsource
| limit 10
```

- `user_name` / `actor_effective_username` read as **emails** for real users (machine/`$`
  accounts keep their name).
- `originalalertsource` = `CrowdStrike Falcon`.
- New issues land under **Cases**, routed to the **Endpoint** product category and NIST IR
  lifecycle.

---

## Step 4 — *(Optional)* Enable CIE identity enrichment

Resolve identity from `socfw_identity_map` (SID/SAM/UPN → canonical email across vendors)
instead of the event alone.

1. Confirm the CIE chain is live: Cloud Identity Engine → `pan_dss_raw` → `SOC IdentityResolve` → `socfw_identity_map` (with `SOC IdentityResolve` enabled).
2. Edit the rule's XQL and **delete the `/*` and `*/` lines** wrapping the `CIE ENRICHMENT`
   block.
3. Set the rule to **Scheduled**: crontab `*/10 * * * *`, search window `25 hours`, schedule
   `10 minutes`.

The overlay coalesces `socfw_identity_map` values **over** the flat identity — the alert-field
mappings don't change, so nothing downstream is affected. Until the chain is live the join
no-ops and the rule keeps running flat.

---

## What is *not* required

| Old requirement | Status | Reason |
|---|---|---|
| 12–15 per-tactic correlation rules | Removed | One consolidated `Endpoint All Alerts` rule |
| Catch-all correlation rule | Removed | Covered by the consolidated rule |
| Classifier / Mapper (incoming or outgoing) | Not used | Normalization is done in the correlation rule XQL via `alert_fields` |
