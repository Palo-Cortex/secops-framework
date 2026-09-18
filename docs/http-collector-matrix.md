# HTTP Collector Matrix — deathstar

Generated 17 Sep 2026 from the repo's correlation rules, the tenant's
`correlations/get`, and the `.env-deathstar-*` collector files present locally.

**Needed** means a collector has to exist before that rule can be exercised by a
replay. Rules with no collector cannot be tested at all — their branch of the
lifecycle has never run on this tenant.

| Rule | Dataset | Repo mode | On tenant | Collector env | Needed |
|---|---|---|---|---|---|
| SOC Abnormal Security - Threat Detected All Alerts | `abnormal_security_email_protection_raw` | SCHEDULED | ✅ REAL_TIME | `.env-deathstar-abnormal` | have it |
| SOC CrowdStrike Falcon - Endpoint All Alerts | `crowdstrike_falcon_event_raw` | SCHEDULED | ✅ REAL_TIME | `.env-deathstar-crowdstrike` | have it |
| SOC CrowdStrike Falcon - IDP All Alerts | `crowdstrike_falcon_event_raw` | SCHEDULED | ✅ REAL_TIME | `.env-deathstar-crowdstrike` | have it |
| SOC Microsoft Graph Defender EndPoint | `msft_graph_security_alerts_raw` | SCHEDULED | ✅ REAL_TIME | `.env-deathstar-defender` | have it |
| SOC Proofpoint TAP - Threat Detected All Alerts | `proofpoint_tap_v2_generic_alert_raw` | SCHEDULED | ⚠️ REAL_TIME, **disabled** | `.env-deathstar-proofpoint` | enable the rule |
| SOC CrowdStrike Falcon - SaaS All Alerts | `crowdstrike_falcon_event_raw` | SCHEDULED | ❌ absent | `.env-deathstar-crowdstrike` | **rule needed**, collector shared |
| SOC MDO365 - Email Threat Detected | `msft_graph_security_alerts_raw` | SCHEDULED | ❌ absent | shares Defender collector | **rule needed** |
| SOC Purview DLP - Policy Alert | `msft_graph_security_alerts_raw` | SCHEDULED | ❌ absent | shares Defender collector | **rule needed** |
| SOC Identity - Entra ID Suspicious Sign-In | `msft_azure_ad_raw` | SCHEDULED | ❌ absent | — | **collector + rule** |
| SOC CheckPoint NDR - Behavioral Alerts | `checkpointndr_generic_alert_raw` | SCHEDULED | ❌ absent | — | **collector + rule** ⭐ |
| SOC SentinelOne Threat | `sentinelone_v2_generic_alert_raw` | SCHEDULED | ❌ absent | — | **collector + rule** |
| SOC Trend Micro Vision One V3 | `trend_micro_vision_one_v3_generic_alert_raw` | SCHEDULED | ❌ absent | — | **collector + rule** |
| SOC Nozomi Guardian - Security Alerts | `nozomi_networks_generic_alert_raw` | SCHEDULED | ❌ absent | — | **collector + rule** |
| SOC Wiz Finding | `wiz_generic_alert_raw` | SCHEDULED | ❌ absent | — | **collector + rule** |
| SOC SpyCloud - Infostealer Credential Exposure | `spycloudenterpriseprotectionfeed_raw` | SCHEDULED | ❌ absent | — | **collector + rule** |
| SOC Zscaler ZPA - Lateral Movement | `zscaler_zpa_raw` | REAL_TIME | ❌ absent | — | **collector + rule** |
| SOC IdentityResolve | `pan_dss_raw` | SCHEDULED (`0 2 * * *`) | ❌ absent | `.env-brumxdr-pandss` only | **collector**; keep scheduled |

⭐ Check Point is the priority: it is the reference case for the
`evidence_unavailable` blocker class and the required-set gate, and there is
currently no way to reproduce it on deathstar.

## Collectors that exist on brumxdr but not deathstar

`.env-brumxdr-ms-graph`, `.env-brumxdr-o365`, `.env-brumxdr-okta`,
`.env-brumxdr-pandss`, `.env-brumxdr-trendmicrovisionone`,
`.env-brumxdr-zscalerzpa`, `.env-brumxdr-testset`,
`.env-brumxdr-socfw-identity-map`. deathstar has only abnormal, crowdstrike,
defender, koi and proofpoint.

## The finding this matrix exposes

The tenant runs **5** SOC correlation rules. The repo ships **17**. The five on
the tenant are all `REAL_TIME`, all renamed with a ` Prod` suffix, and therefore
are **tenant-local copies, not pack content**.

So the pack ships `SCHEDULED */10` with a 20-minute search window, while every
rule actually in use is real-time. A customer installing the pack today gets the
scheduled behaviour nobody is testing against. Nine of the shipped rules also
carry a comment reading *"it ships REAL_TIME"* directly above
`execution_mode: SCHEDULED`.

Fixing the repo to match what is run matters more than flipping anything on the
tenant — the tenant is already correct.
