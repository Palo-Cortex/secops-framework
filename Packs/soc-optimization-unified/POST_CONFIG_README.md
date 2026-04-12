# Post-Configuration — SOC Framework PoV Test Pack

---

## Running the Turla Carbon scenario

Open the playground or any case war room and run both commands.
The shared `global_min` / `global_max` keeps both sources on the same time axis
so the email delivery always appears ~2 hours before the endpoint detections.

### Send CrowdStrike Falcon events (138 endpoint detections)

```
!SOCFWPoVSend list_name="SOCFWPoVData_CrowdStrike_TurlaCarbon_V1"
  instance_name="socfw_pov_crowdstrike_sender"
  source_name="crowdstrike"
  global_min="2025-12-02T13:00:00Z"
  global_max="2025-12-04T12:01:07Z"
```

### Send Proofpoint TAP events (2 email threat events)

```
!SOCFWPoVSend list_name="SOCFWPoVData_TAP_TurlaCarbon_V1"
  instance_name="socfw_pov_tap_sender"
  source_name="proofpoint"
  global_min="2025-12-02T13:00:00Z"
  global_max="2025-12-04T12:01:07Z"
```

Navigate to **Cases & Issues → Cases**. Cases appear within seconds for real-time rules.

---

## What you should see

- **Email alert**: `[Email] Gunter@SKT.LOCAL - Initial Access: Threat Email Delivered`
- **Endpoint alerts**: `[Endpoint] Gunter@SKT.LOCAL - Command and Control: ...` (138 events grouped)
- **Cross-source case**: XSIAM groups both into one case via shared `Gunter@SKT.LOCAL` username
- **AI narrative**: spans both sources — email delivery → Carbon dropper execution → C2
- **SOC Framework**: Foundation → Analysis → Containment → Eradication → Recovery (all shadow mode)

---

## Replaying the scenario

Suppression IDs rotate automatically on every run. Just re-run the same commands.
No cleanup needed between replays.

To compress into a shorter window for a live demo:

```
!SOCFWPoVSend list_name="SOCFWPoVData_CrowdStrike_TurlaCarbon_V1"
  instance_name="socfw_pov_crowdstrike_sender"
  source_name="crowdstrike"
  compress_window="30m"
  global_min="2025-12-02T13:00:00Z"
  global_max="2025-12-04T12:01:07Z"
```

---

## Set the teardown reminder

Go to **Automation → Jobs → POV Teardown Reminder V1**.
Set the schedule to fire on the last day of the PoV.
The JOB creates a High severity case titled:
`ACTION REQUIRED: Uninstall SOC Framework PoV Test Pack`

---

## Teardown (before PS handoff)

Complete in order:

```
☐ 1. Uninstall soc-framework-pov-test from Marketplace
☐ 2. Delete socfw_pov_crowdstrike HTTP Collector
      Settings → Data Sources → socfw_pov_crowdstrike → Delete
☐ 3. Delete socfw_pov_tap HTTP Collector
☐ 4. Set shadow_mode = false per action in SOCFrameworkActions_V3
☐ 5. Help PS onboard real customer data sources (CrowdStrike, TAP integrations)
☐ 6. Verify correlation rules fire on real data before leaving
☐ 7. Close the teardown reminder case
```

---

## Adding future scenario sources (XDR agent, MS Defender, etc.)

1. Build the TSV from lab execution
2. Add as a new List: `SOCFWPoVData_<Vendor>_<Scenario>_V1`
3. Create a new HTTP Collector in XSIAM targeting the correct dataset
4. Add a new `SOCFWPoVSender` integration instance
5. Run `!SOCFWPoVSend` with the new list name and instance name

No code changes needed for new vendors.
