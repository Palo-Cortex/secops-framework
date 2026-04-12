# SOC Framework PoV Test Pack

Enables repeatable, safe attack scenario replay for SOC Framework PoV demonstrations.
Injects scenario event data into XSIAM via HTTP Collector so correlation rules fire
exactly as they would on real vendor data — with timestamps current and suppression
IDs rotated on every run.

**Install on PoV and dev tenants only. Uninstall before PS handoff.**

See `DC_QUICKSTART.md` for the full end-to-end setup checklist.

---

## Architecture

```
SOCFWPoVSend (Script)
  → reads XSIAM list (scenario data)
  → rebases timestamps to now (2h window compression)
  → rotates suppression IDs (safe to replay multiple times)
  → normalizes source-specific fields (UPN reconstruction, recipient list, etc.)
  → calls SOCFWPoVSender (Integration) in batches

SOCFWPoVSender (Integration)
  → stores HTTP Collector URL + API key securely per instance
  → posts NDJSON to HTTP Collector endpoint

HTTP Collector → vendor dataset → correlation rule fires
  → XSIAM alert → Case → SOC Framework NIST IR lifecycle (shadow mode)
```

---

## Scenarios included

| Scenario | Sources | Events | MITRE Tactics |
|---|---|---|---|
| Turla Carbon | CrowdStrike Falcon + Proofpoint TAP | 138 EDR + 2 email | TA0001, TA0002, TA0011 |

---

## Run commands

```
!SOCFWPoVSend list_name="SOCFWPoVData_CrowdStrike_TurlaCarbon_V1"
  instance_name="socfw_pov_crowdstrike_sender"
  source_name="crowdstrike"
  global_min="2025-12-02T13:00:00Z"
  global_max="2025-12-04T12:01:07Z"

!SOCFWPoVSend list_name="SOCFWPoVData_TAP_TurlaCarbon_V1"
  instance_name="socfw_pov_tap_sender"
  source_name="proofpoint"
  global_min="2025-12-02T13:00:00Z"
  global_max="2025-12-04T12:01:07Z"
```

---

## Pack contents

| Content | Purpose |
|---|---|
| `SOCFWPoVSend` (Script) | List read, normalize, rebase, batch send |
| `SOCFWPoVSender` (Integration) | Credential storage + HTTP POST per source |
| `SOCFWPoVData_CrowdStrike_TurlaCarbon_V1` (List) | 138 CrowdStrike Falcon events |
| `SOCFWPoVData_TAP_TurlaCarbon_V1` (List) | 2 Proofpoint TAP email threat events |
| `JOB - POV Teardown Reminder V1` (Playbook) | Scheduled uninstall reminder case |
