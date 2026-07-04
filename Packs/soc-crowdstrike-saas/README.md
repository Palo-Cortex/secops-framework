# SOC CrowdStrike Falcon — SaaS Security

Reshapes CrowdStrike Falcon **SaaS Security** detections into email-first SOC Framework issues, routed to the **SaaS** product category and the **NIST IR** lifecycle; shown under **Cloud IR** in the PoV Companion.

> **Telemetry note:** current CrowdStrike SaaS alerts carry identity + geo + MITRE context but no SaaS-app/session artifacts. Containment therefore acts at the user/IP level (disable user, block IP) via the Universal Command; SaaS-app-specific actions light up automatically once the telemetry carries session/app fields.

Part of the CrowdStrike three-pack set — one pack per product, all sharing the
`crowdstrike_falcon_event_raw` dataset:

| Pack | Product | Category (DC display) | Product category | Lifecycle |
|---|---|---|---|---|
| `soc-crowdstrike-falcon` | Endpoint (EPP) | Endpoint | Endpoint | NIST IR |
| `soc-crowdstrike-idp` | Identity Protection | Identity | Identity | NIST IR |
| `soc-crowdstrike-saas` | SaaS Security | Cloud IR | SaaS | NIST IR |

---

## What's included

| Component | Description |
|---|---|
| **Correlation Rule** — `SOC CrowdStrike Falcon - SaaS All Alerts` | Fires on every CrowdStrike SaaS Security detection (`product = "saas-security"`). Normalizes identity, geo, and MITRE fields; resolves identity email-first; maps to SOC Framework issue fields. Real-time; suppression per `composite_id` / 2 hours. |

---

## How it works

The rule is a single pipeline over `crowdstrike_falcon_event_raw`:

1. **Filter** to SaaS Security detections (`| filter product = "saas-security"`).
2. **Extract** the relevant fields from the raw event.
3. **Resolve identity — an email-first coalesce.** `user_name` and `actor_effective_username` resolve to
   the canonical identity via `coalesce(email, UPN, NetBIOS, raw)` — email (derived from the UPN) first, then UPN, then NetBIOS (`domain\\user`), then the raw name.
   Machine/service accounts (ending in `$`) keep their name; the raw value is preserved as
   `original_user_name`. This lets a CrowdStrike alert line up with Proofpoint, Entra, and
   XSIAM's native identity layer on a single person.
4. **Map** to SOC Framework issue fields (`alert_fields`).
5. **Route.** `originalalertsource = "CrowdStrike Falcon SaaS Security"` classifies the alert to the **SaaS** product category (via `SOCProductCategoryMap_V3`), and `DOMAIN_SECURITY` sends it through the **NIST IR** lifecycle.

### Two identity modes

| Mode | When | Identity source |
|---|---|---|
| **Flat** (default) | Ships this way — real-time, no dependencies | The event's own UPN / `user_name` |
| **CIE-enriched** (optional) | Uncomment the `/* */` overlay + set the rule Scheduled | `socfw_identity_map` (email join), coalesced over the flat values |

The CIE overlay is inert by default — the rule runs flat with **no** dependency on the identity
map. Enabling it requires the Cloud Identity Engine chain (see **Before you install**).


---

## Before you install

Confirm the CrowdStrike Falcon integration is ingesting SaaS Security detections — the dataset must
exist or the pack won't register:

```
dataset = crowdstrike_falcon_event_raw | filter product = "saas-security" | limit 5
```

*(Optional, for CIE enrichment)* the identity chain must be live end-to-end:
**Cloud Identity Engine → `pan_dss_raw` → `SOC IdentityResolve` → `socfw_identity_map`**.

`SOC IdentityResolve` is the **scheduled** correlation rule in the **SOC Framework Optimization** pack (`soc-optimization-unified`) that builds `socfw_identity_map` from `pan_dss_raw` (runs daily at 02:00). It **ships disabled — you must enable it** for CIE enrichment. The rule here runs flat without any of this.

## After you install

See `POST_CONFIG_README.md`: enable the rule, verify, and (optionally) turn on CIE enrichment.

---

## Requirements

- SOC Framework core (`soc-framework-nist-ir`, `soc-optimization-unified`).
- CrowdStrike Falcon integration ingesting SaaS Security detections to `crowdstrike_falcon_event_raw`.
- *(Optional, for CIE enrichment)* Cloud Identity Engine → `pan_dss_raw` → `SOC IdentityResolve`
  → `socfw_identity_map`.
