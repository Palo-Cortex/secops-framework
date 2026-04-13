# SOC Framework PoV — DC Quick Start

> End-to-end setup in under 30 minutes. Follow in order.

---

## Phase 1 — Install SOC Framework

- [ ] Install `soc-optimization-unified` pack (Foundation, Universal Command, Lists, Dashboards)
- [ ] Install `soc-framework-nist-ir` pack (NIST IR lifecycle playbooks)
- [ ] Install vendor pack(s) for customer data sources:
  - `SocFrameworkCrowdstrikeFalcon` — if customer has CrowdStrike
  - `SocFrameworkProofPointTap` — if customer has Proofpoint TAP
- [ ] Run `!SOCFWPackManager action=apply` to configure lists, lookups, and integration instances
- [ ] Verify correlation rules are enabled: **Detection Rules → Correlation**
- [ ] Verify shadow mode is ON: `SOCFrameworkActions_V3` list — all actions have `shadow_mode: true`

---

## Phase 2 — Install PoV Test Pack

- [ ] In XSIAM: **Settings → Data Sources → Add Data Source → HTTP Collector**
  - Create **CrowdStrike** collector: Vendor = `CrowdStrike`, Product = `Falcon_Event`
  - Create **Proofpoint TAP** collector: Vendor = `Proofpoint`, Product = `TAP`
  - Copy the **URL** and **API Key** for each — you need them in the next step
- [ ] Install `soc-framework-pov-test` pack via SDK upload
- [ ] **Settings → Integrations → SOCFWPoVSender** — configure both instances:
  - `socfw_pov_crowdstrike_sender` → paste CrowdStrike collector URL + API Key
  - `socfw_pov_tap_sender` → paste TAP collector URL + API Key
  - Click **Test** on each — must return `ok`
- [ ] **Automation → Jobs → POV Teardown Reminder V1** → set schedule to last day of PoV

---

## Phase 3 — Run the Attack Scenario

- [ ] Open the playground or any case war room
- [ ] Run CrowdStrike (138 endpoint detection events):
  ```
  !SOCFWPoVSend list_name="SOCFWPoVData_CrowdStrike_TurlaCarbon_V1"
    instance_name="socfw_pov_crowdstrike_sender"
    source_name="crowdstrike"
    global_min="2025-12-02T13:00:00Z"
    global_max="2025-12-04T12:01:07Z"
  ```
- [ ] Run Proofpoint TAP (2 email threat events):
  ```
  !SOCFWPoVSend list_name="SOCFWPoVData_TAP_TurlaCarbon_V1"
    instance_name="socfw_pov_tap_sender"
    source_name="proofpoint"
    global_min="2025-12-02T13:00:00Z"
    global_max="2025-12-04T12:01:07Z"
  ```
- [ ] Watch **Cases & Issues → Cases** — cases appear within seconds
- [ ] Confirm cross-source grouping: one case showing both email delivery + endpoint detections
- [ ] Confirm SOC Framework ran: case war room shows Foundation → Analysis → AI narrative

---

## Phase 4 — Show the Value Dashboard

- [ ] Navigate to **Dashboards → XSIAM SOC Value Metrics**
- [ ] Walk the customer through the 4 Value Drivers:
  - **VD1** — MTTD, MTTC, MTTR (detection and response speed)
  - **VD2** — Shadow mode actions (what automation would have done)
  - **VD3** — Analyst time saved, automation percentage
  - **VD4** — Attack surface risk reduction, recovery validation
- [ ] Show the AI narrative in the case — cross-vendor correlation across TAP + CrowdStrike
- [ ] Show the NIST IR lifecycle running in shadow mode — containment, eradication, recovery logged but not executed
- [ ] Explain the 1-flip production path: `shadow_mode = false` per action in `SOCFrameworkActions_V3`

---

## Phase 5 — Teardown (Before PS Handoff)

- [ ] Run `!SOCFWPackManager action=apply` on the production tenant (Skynet) with PS
- [ ] On the PoV tenant, uninstall `soc-framework-pov-test` from Marketplace
- [ ] Delete both HTTP Collectors: **Settings → Data Sources → socfw_pov_crowdstrike / socfw_pov_tap → Delete**
- [ ] Set `shadow_mode = false` per action in `SOCFrameworkActions_V3` to enable live execution
- [ ] Help PS onboard the customer's real data sources ASAP:
  - CrowdStrike Falcon integration (native Marketplace pack)
  - Proofpoint TAP integration (native Marketplace pack)
  - Any additional sources per customer environment
- [ ] Verify correlation rules fire on real data before leaving the customer
- [ ] Close the POV Teardown Reminder case

---

## Replay anytime

To re-run the scenario (suppression IDs rotate automatically on each run):

```
!SOCFWPoVSend list_name="SOCFWPoVData_CrowdStrike_TurlaCarbon_V1"
  instance_name="socfw_pov_crowdstrike_sender"
  source_name="crowdstrike"
  global_min="2025-12-02T13:00:00Z"
  global_max="2025-12-04T12:01:07Z"
```

```
!SOCFWPoVSend list_name="SOCFWPoVData_TAP_TurlaCarbon_V1"
  instance_name="socfw_pov_tap_sender"
  source_name="proofpoint"
  global_min="2025-12-02T13:00:00Z"
  global_max="2025-12-04T12:01:07Z"
```
