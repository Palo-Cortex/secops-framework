# SOC CrowdStrike Falcon - Post-Installation Steps

> **Warning — Duplicate Alerts**
> This pack (`socfw-crowdstrike-falcon`) installs alongside the previous pack
> (`soc-crowdstrike-falcon`) — it does not replace it. If any old CrowdStrike correlation
> rules are still enabled when the new consolidated rule is enabled, every CrowdStrike
> detection will generate two alerts. Complete Step 2 (disable old rules) before Step 3
> (enable new rule).

This pack deploys the SOC Framework correlation rule and modeling rule for CrowdStrike
Falcon endpoint alerts. Complete the steps below after installation.

---

## Step 1 — Verify the CrowdStrike Falcon Integration Instance

The CrowdStrike Falcon integration must be configured and running before alerts will
flow into `crowdstrike_falcon_event_raw`. If not already done:

1. Navigate to **Settings → Configurations → Data Collection → Automation & Feed Integrations**
2. Find the `CrowdstrikeFalcon_Detections_Incidents` instance and open its configuration
3. Confirm the following are filled in:
   - **Server URL**
   - **Client ID**
   - **Secret**
4. Leave **Classifier** and **Mapper (incoming)** empty — field normalization is handled
   by the correlation rule and modeling rule, not a mapper
5. Click **Test** to verify connectivity, then **Save & Exit**
6. Confirm the instance is **enabled**

> **Troubleshooting:** The modeling rule requires `crowdstrike_falcon_event_raw` to exist
> before it can register. If the pack fails to install, confirm the integration instance
> is active and has ingested at least one event.

---

## Step 2 — Disable Old Per-Tactic CrowdStrike Correlation Rules

Previous versions of this pack (1.0.14 and earlier) installed up to 15 per-tactic
correlation rules plus a catch-all. The SOC Framework consolidated rule replaces all of them.
The CrowdStrike marketplace pack may also install a system-generated rule.

1. Navigate to **Detection & Threat Intel → Correlations**
2. Filter the **Name** column for `CrowdStrike`
3. Disable all of the following if present:

   | Rule to Disable |
   |---|
   | `CrowdStrike Falcon - Endpoint Alerts - Initial Access` |
   | `CrowdStrike Falcon - Endpoint Alerts - Execution` |
   | `CrowdStrike Falcon - Endpoint Alerts - Persistence` |
   | `CrowdStrike Falcon - Endpoint Alerts - Privilege Escalation` |
   | `CrowdStrike Falcon - Endpoint Alerts - Defense Evasion` |
   | `CrowdStrike Falcon - Endpoint Alerts - Credential Access` |
   | `CrowdStrike Falcon - Endpoint Alerts - Discovery` |
   | `CrowdStrike Falcon - Endpoint Alerts - Lateral Movement` |
   | `CrowdStrike Falcon - Endpoint Alerts - Collection` |
   | `CrowdStrike Falcon - Endpoint Alerts - Command and Control` |
   | `CrowdStrike Falcon - Endpoint Alerts - Exfiltration` |
   | `CrowdStrike Falcon - Endpoint Alerts - Impact` |
   | `CrowdStrike Falcon - Endpoint Alerts - Reconnaissance` |
   | `CrowdStrike Falcon - Endpoint Alerts - Resource Development` |
   | `CrowdStrike Falcon (Catch-All) - Endpoint Alerts` |
   | `CrowdStrike Falcon - Endpoint Alerts (automatically generated)` |

4. Right-click each → **Disable**

---

## Step 3 — Enable the SOC Framework Correlation Rule

The SOC Framework rule ships disabled for side-by-side validation before cutover.

1. Navigate to **Detection & Threat Intel → Correlations**
2. Filter the **Name** column for `SOC CrowdStrike`
3. Locate **SOC CrowdStrike Falcon - Endpoint Alerts**
4. Right-click → **Enable**

> **What this rule does:** fires on all CrowdStrike EPP detections (`filter product = "epp"`),
> computes a rich `[Endpoint] {user} - {tactic}: {technique}` alert name, and uses
> `user_defined_category: tactic` to dynamically set the alert category from the MITRE
> tactic field — replacing the 15 per-tactic rules with a single unified rule.
> Suppression is per `composite_id` with a 1-hour window.

---

## Step 4 — Verify the Modeling Rule

1. Navigate to **Settings → Configurations → Data Management → Data Model Rules**
2. Confirm **SOC CrowdStrike Falcon Modeling Rule** is listed and active
3. Validate with an XQL probe:

```xql
datamodel dataset in("crowdstrike_falcon_event_raw")
| fields xdm.event.id, xdm.source.host.hostname, xdm.source.user.username,
         xdm.event.original_event_type, xdm.source.host.device_id
| limit 5
```

If rows return with populated fields, the modeling rule is working correctly.

---

## What Is Not Required

| Old Requirement | Status | Reason |
|---|---|---|
| 15 per-tactic correlation rules | Removed | Replaced by single `SOC CrowdStrike Falcon - Endpoint Alerts` rule using `user_defined_category: tactic` |
| Catch-all correlation rule | Removed | Covered by single unified rule with no tactic filter |
| Classifier / Mapper (incoming) | Removed | Field normalization handled in correlation rule XQL via `alert_fields`; mapper deprecated in XSIAM |
| Outgoing mapper | Removed | Not required for alert-driven workflows |
