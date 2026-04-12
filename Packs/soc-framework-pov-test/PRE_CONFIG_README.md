# Pre-Configuration — SOC Framework PoV Test Pack

Complete these steps **before** installing this pack.
You need one HTTP Collector per data source.

---

## Create HTTP Collectors in XSIAM

In XSIAM navigate to **Settings → Data Sources → Add Data Source → HTTP Collector**.

Create two collectors — one per source. Use these exact product/vendor values
so events land in the correct datasets and the existing correlation rules fire.

### Collector 1 — CrowdStrike Falcon

| Field | Value |
|---|---|
| Name | `socfw_pov_crowdstrike` |
| Vendor | `CrowdStrike` |
| Product | `Falcon` |
| Dataset | `crowdstrike_falcon_event_raw` (auto-created) |

After saving: copy the **Endpoint URL** and **API Key** — you'll paste them into
the `socfw_pov_crowdstrike_sender` integration instance after install.

### Collector 2 — Proofpoint TAP

| Field | Value |
|---|---|
| Name | `socfw_pov_tap` |
| Vendor | `Proofpoint` |
| Product | `TAP` |
| Dataset | `proofpoint_tap_v2_generic_alert_raw` (auto-created) |

After saving: copy the **Endpoint URL** and **API Key** for the
`socfw_pov_tap_sender` integration instance.

---

## Verify existing correlation rules are enabled

The scenario data only produces cases if the correlation rules are active.
Confirm in **Detection Rules → Correlation**:

- `SOC CrowdStrike Falcon - Endpoint Alerts` → Enabled
- `SOC Proofpoint TAP - Threat Detected` → Enabled

If these rules are not installed, install `SocFrameworkCrowdstrikeFalcon`
and `SocFrameworkProofPointTap` packs first.

---

## Install the pack

Install `soc-framework-pov-test` from the Marketplace or via SDK upload.

After install, go to **Settings → Integrations** and configure:

**`socfw_pov_crowdstrike_sender`**
- HTTP Collector URL → paste CrowdStrike collector URL
- API Key → paste CrowdStrike collector API key
- Source Name → `crowdstrike` (pre-filled)

**`socfw_pov_tap_sender`**
- HTTP Collector URL → paste TAP collector URL
- API Key → paste TAP collector API key
- Source Name → `proofpoint` (pre-filled)

Click **Test** on each instance — should return `ok`.

See `POST_CONFIG_README.md` for running the scenario.
