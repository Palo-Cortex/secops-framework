# SOC Framework PoV — DC Quick Start

> End-to-end setup in under 30 minutes. Follow in order — the sequence matters.

---

## Phase 1 — Install SOC Framework (no dataset dependencies)

- [ ] Install `soc-optimization-unified` pack (Foundation, Universal Command, Lists, Dashboards)
- [ ] Install `soc-framework-nist-ir` pack (NIST IR lifecycle playbooks)
- [ ] Verify shadow mode is ON: `SOCFrameworkActions_V3` list — all actions have `shadow_mode: true`

---

## Phase 2 — Install PoV Test Pack + Create HTTP Collectors

- [ ] In XSIAM: **Settings → Data Sources → Add Data Source → HTTP Collector**
  - Create **CrowdStrike** collector: Vendor = `CrowdStrike`, Product = `Falcon_Event`
  - Create **Proofpoint TAP** collector: Vendor = `proofpoint`, Product = `tap`
  - Copy the **URL** and **API Key** for each
- [ ] Install `soc-framework-pov-test` pack via SDK upload or `xsoar_config.json`
- [ ] **Settings → Integrations → SOCFWPoVSender** — two instances are pre-installed:
  - `socfw_pov_crowdstrike_sender` → paste CrowdStrike collector URL + API Key, set Vendor = `CrowdStrike`, Product = `Falcon_Event`
  - `socfw_pov_tap_sender` → paste Proofpoint collector URL + API Key, set Vendor = `proofpoint`, Product = `tap`
- [ ] **Test** both instances — clicking Test sends a schema seed event that creates the dataset. Both should return "ok".
- [ ] Wait 60 seconds for the datasets to populate

---

## Phase 3 — Install Vendor Correlation Rule Packs

> The datasets now exist (created by the Test button). Correlation rules can bind to them.

- [ ] Install vendor pack(s) for customer data sources:
  - `soc-crowdstrike-falcon` — CrowdStrike Falcon correlation rules
  - `soc-proofpoint-tap` — Proofpoint TAP correlation rules
- [ ] Verify correlation rules are enabled: **Detection Rules → Correlation**

---

## Phase 4 — Run the Attack Scenario

- [ ] Open the playground or any case war room
- [ ] Run CrowdStrike (138 endpoint detection events):
  ```
  !SOCFWPoVSend list_name=SOCFWPoVData_CrowdStrike_TurlaCarbon_V1 source_name=crowdstrike global_min=2025-12-02T13:00:00Z global_max=2025-12-04T12:01:07Z
  ```
- [ ] Run Proofpoint TAP (2 email threat events):
  ```
  !SOCFWPoVSend list_name=SOCFWPoVData_TAP_TurlaCarbon_V1 source_name=proofpoint global_min=2025-12-02T13:00:00Z global_max=2025-12-04T12:01:07Z
  ```
- [ ] Watch **Cases & Issues → Cases** — cases appear within seconds
- [ ] Confirm cross-source grouping: one case showing both email delivery + endpoint detections
- [ ] Confirm SOC Framework ran: case war room shows Foundation → Analysis → AI narrative

---

## Phase 5 — Show the Value Dashboard

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

## Phase 6 — Teardown (Before PS Handoff)

- [ ] On the PoV tenant, uninstall `soc-framework-pov-test` from Marketplace
- [ ] Delete both HTTP Collectors: **Settings → Data Sources → [collector] → Delete**
- [ ] Set `shadow_mode = false` per action in `SOCFrameworkActions_V3` to enable live execution
- [ ] Help PS onboard the customer's real data sources:
  - CrowdStrike Falcon integration (native Marketplace pack)
  - Proofpoint TAP integration (native Marketplace pack)
  - Any additional sources per customer environment
- [ ] Verify correlation rules fire on real data before leaving the customer
- [ ] Close the POV Teardown Reminder case

---

## Replay Anytime

To re-run the scenario (suppression IDs rotate automatically on each run):

```
!SOCFWPoVSend list_name=SOCFWPoVData_CrowdStrike_TurlaCarbon_V1 source_name=crowdstrike global_min=2025-12-02T13:00:00Z global_max=2025-12-04T12:01:07Z
```

```
!SOCFWPoVSend list_name=SOCFWPoVData_TAP_TurlaCarbon_V1 source_name=proofpoint global_min=2025-12-02T13:00:00Z global_max=2025-12-04T12:01:07Z
```
