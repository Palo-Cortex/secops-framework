# SOC CrowdStrike Falcon — Post-Installation Steps

Complete these after installing the pack: three required (enable → migrate → verify) and two
optional (CIE enrichment, scheduled mode). Prerequisites are in the pack **README** (*Before you install*).

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

## Step 5 — *(Optional)* Run the rule on a schedule instead of real time

The rule ships **Real Time**, so alerts are raised as detections are ingested. Run it on a
schedule only if a tenant needs it (for example, to add stages a real-time rule can't run).
For CIE enrichment, use Step 4 instead — it has its own schedule.

1. **Detection & Threat Intel → Correlations** → edit **`SOC CrowdStrike Falcon - Endpoint All Alerts`**
2. Set **Execution Mode** to **Scheduled**: crontab `*/10 * * * *`, schedule `10 minutes`,
   search window `20 minutes`.
3. Leave **suppression** on (`composite_id`, 1 hour). The window overlaps the schedule so
   detections that ingest late are still picked up; suppression stops the overlap from
   alerting the same detection twice.

Alerts now arrive on the schedule, up to 10 minutes after ingestion, instead of immediately.

> **If you edit the XQL while the rule is Real Time:** real-time rules accept only the
> `dataset`, `filter`, `alter`, `fields` and `config` stages. Some functions also stop a
> real-time rule from alerting **without raising an error**, even though the same XQL runs
> fine in XQL Search — `array_length`, `arraystring`, `arrayrange`, `to_string` and `trim`
> did on XSIAM 3.6. After any edit, send one test detection and confirm it alerts before
> relying on the rule.

---

## What is *not* required

| Old requirement | Status | Reason |
|---|---|---|
| 12–15 per-tactic correlation rules | Removed | One consolidated `Endpoint All Alerts` rule |
| Catch-all correlation rule | Removed | Covered by the consolidated rule |
| Classifier / Mapper (incoming or outgoing) | Not used | Normalization is done in the correlation rule XQL via `alert_fields` |
