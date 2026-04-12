# Post-Configuration — SOC Framework PoV Test Pack

---

## Running the Turla Carbon scenario

Open any case war room or the playground and run both commands.
Run order does not matter — global_min/global_max synchronises the time axis.

```
!socfw-pov-send-data list_name=SOCFWPoVData_CrowdStrike_TurlaCarbon_V1
  global_min=2025-12-02T13:00:00Z global_max=2025-12-04T12:01:07Z
  using=socfw_pov_crowdstrike_sender

!socfw-pov-send-data list_name=SOCFWPoVData_TAP_TurlaCarbon_V1
  global_min=2025-12-02T13:00:00Z global_max=2025-12-04T12:01:07Z
  using=socfw_pov_tap_sender
```

Navigate to **Cases & Issues → Cases**. Cases should appear within seconds
for real-time correlation rules. Up to 10 minutes for scheduled rules.

### What you should see

- Proofpoint TAP alert: `[Email] Gunter@SKT.LOCAL - Initial Access: Threat Email Delivered`
- CrowdStrike alerts: `[Endpoint] Gunter@SKT.LOCAL - Command and Control: ...` (138 events → grouped)
- XSIAM groups both sources into one case via shared `Gunter@SKT.LOCAL` username
- SOC Framework runs in shadow mode — AI narrative spans both sources

---

## Replaying the scenario

Each run rotates suppression IDs automatically so correlation rules fire again
regardless of how recently the previous run was. Just re-run the same commands.

To compress into a shorter window (e.g. for a 30-minute live demo):
```
!socfw-pov-send-data list_name=SOCFWPoVData_CrowdStrike_TurlaCarbon_V1
  global_min=2025-12-02T13:00:00Z global_max=2025-12-04T12:01:07Z
  compress_window=30m using=socfw_pov_crowdstrike_sender
```

---

## Set the teardown reminder

Go to **Automation → Jobs → POV Teardown Reminder V1**.
Set the schedule to fire on the last day of the PoV. The JOB creates a
High severity case titled `ACTION REQUIRED: Uninstall SOC Framework PoV Test Pack`
with the full uninstall checklist.

---

## Teardown (before PS handoff)

Complete in order:

```
☐ 1. Delete socfw_pov_crowdstrike HTTP Collector
      Settings → Data Sources → socfw_pov_crowdstrike → Delete
☐ 2. Delete socfw_pov_tap HTTP Collector
☐ 3. Uninstall soc-framework-pov-test from Marketplace
☐ 4. Set shadow_mode = false per action in SOCFrameworkActions_V3 to go live
☐ 5. Close the teardown reminder case
```

The integration instances and list data are removed automatically when the pack
is uninstalled.

---

## Adding future scenarios (XDR agent, MS Defender, etc.)

When you have a new TSV:
1. Add it as a new List following the `SOCFWPoVData_<Vendor>_<Scenario>_V1` naming convention
2. Create a new HTTP Collector in XSIAM for the target dataset
3. Add a new `SOCFWPoVSender` integration instance pointing to that collector
4. Run `!socfw-pov-send-data` with the new list name and instance

No code changes to `SOCFWPoVSender.py` required for new vendors as long as
normalization is not needed. For new normalization logic (new suppression fields,
new UPN reconstruction patterns), add a branch in `normalize_events()`.
