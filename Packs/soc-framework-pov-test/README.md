# SOC Framework PoV Test Pack

Enables repeatable, safe attack scenario replay for SOC Framework PoV demonstrations.
Sends scenario event data into XSIAM via HTTP Collector so correlation rules fire
exactly as they would on real vendor data.

**Install on PoV and dev tenants only. Uninstall before PS handoff.**

---

## How it works

```
XSIAM List (scenario data)
  ↓ SOCFWPoVSender integration
  ↓ timestamp rebase → suppress ID rotation → HTTP POST
HTTP Collector endpoint
  ↓
vendor dataset (crowdstrike_falcon_event_raw, proofpoint_tap_v2_generic_alert_raw, ...)
  ↓
Correlation rule fires → XSIAM alert → Case → SOC Framework runs
```

---

## DC workflow

**1. Install pack and configure integration instances**

See `PRE_CONFIG_README.md` for HTTP Collector setup.
After install, edit each integration instance and paste the URL and API key.

**2. Run the scenario from any case war room or playground**

```
# Send CrowdStrike EDR events
!socfw-pov-send-data list_name=SOCFWPoVData_CrowdStrike_TurlaCarbon_V1
  global_min=2025-12-02T13:00:00Z global_max=2025-12-04T12:01:07Z
  using=socfw_pov_crowdstrike_sender

# Send Proofpoint TAP email events
!socfw-pov-send-data list_name=SOCFWPoVData_TAP_TurlaCarbon_V1
  global_min=2025-12-02T13:00:00Z global_max=2025-12-04T12:01:07Z
  using=socfw_pov_tap_sender
```

Watch Cases & Issues → Cases. Cases form within seconds (real-time rules).

**3. Set the teardown reminder**

Go to Automation → Jobs → POV Teardown Reminder V1 → set schedule to last day of PoV.

---

## Scenarios

| Scenario | Lists | global_min | global_max |
|---|---|---|---|
| Turla Carbon (CS + TAP) | `SOCFWPoVData_CrowdStrike_TurlaCarbon_V1` + `SOCFWPoVData_TAP_TurlaCarbon_V1` | `2025-12-02T13:00:00Z` | `2025-12-04T12:01:07Z` |

---

## Adding a new scenario source (e.g. XDR agent)

1. Build the TSV from the lab execution
2. Add it as a new List in the pack following the same naming convention
3. Add a third integration instance in `xsoar_config.json` pointing to the correct HTTP Collector
4. Run `!socfw-pov-send-data` with the new list name and instance — same global_min/max

No code changes needed.
