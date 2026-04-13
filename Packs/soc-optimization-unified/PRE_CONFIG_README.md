# Pre-Configuration — SOC Framework PoV Test Pack

Complete these steps **before** installing this pack.

---

## Step 1 — Verify SOC Framework is installed

Confirm the following are installed and correlation rules are enabled:

- `soc-optimization-unified` — Foundation layer, lists, dashboards
- `soc-framework-nist-ir` — NIST IR lifecycle playbooks
- `SocFrameworkCrowdstrikeFalcon` — CrowdStrike correlation rule
- `SocFrameworkProofPointTap` — Proofpoint TAP correlation rule

In **Detection Rules → Correlation** confirm both rules show **Enabled**.

---

## Step 2 — Create HTTP Collectors

In XSIAM: **Settings → Data Sources → Add Data Source → HTTP Collector**

Create one collector per data source. Use these exact values — vendor and product
determine which dataset events are written to.

### Collector 1 — CrowdStrike Falcon

| Field | Value |
|---|---|
| Name | `socfw_pov_crowdstrike` |
| Vendor | `CrowdStrike` |
| Product | `Falcon_Event` |
| Dataset | `crowdstrike_falcon_event_raw` (auto-created on first event) |

### Collector 2 — Proofpoint TAP

| Field | Value |
|---|---|
| Name | `socfw_pov_tap` |
| Vendor | `Proofpoint` |
| Product | `TAP` |
| Dataset | `proofpoint_tap_v2_generic_alert_raw` (auto-created on first event) |

After saving each collector: copy the **Endpoint URL** and **API Key**.
You will paste these into the integration instances after pack install.

---

## Step 3 — Install the pack

Upload `soc-framework-pov-test` via SDK:

```bash
bash tools/upload_package.sh Packs/soc-framework-pov-test
```

---

## Step 4 — Configure integration instances

Go to **Settings → Integrations → SOCFWPoVSender**.

Two instances are created automatically. Configure each:

**`socfw_pov_crowdstrike_sender`**
- HTTP Collector URL → paste CrowdStrike collector URL
- API Key → paste CrowdStrike collector API key
- Source Name → `crowdstrike` (pre-filled — do not change)
- Click **Test** → must return `ok`

**`socfw_pov_tap_sender`**
- HTTP Collector URL → paste TAP collector URL
- API Key → paste TAP collector API key
- Source Name → `proofpoint` (pre-filled — do not change)
- Click **Test** → must return `ok`

See `POST_CONFIG_README.md` to run the scenario.
