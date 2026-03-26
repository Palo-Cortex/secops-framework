# SOC Trend Micro Vision One — Post-Installation Configuration

Complete these steps after uploading the pack to your XSIAM tenant.

---

## Step 1 — Configure the Layout Rule

Create a layout rule so Vision One alerts display the enriched analyst layout.

**Go to:** Settings → Configurations → Object Setup → Issues → Layout Rules

| Field | Value |
|---|---|
| Rule Name | `Trend Micro Vision One Alert Layout` |
| Filter Criteria | Alert Source — Tags: `DS:Trend Micro Vision One V3` |
| Layout to Display | `SOC Trend Micro Vision One IR` |

---

## Step 2 — Enable the Correlation Rule

**Go to:** Detection & Correlation → Correlation Rules

Enable `SOC Trend Micro Vision One V3`.

> **Important:** Disable any default correlation rules installed by the native Trend Micro Vision One marketplace integration. Running both simultaneously will produce duplicate alerts.

---

## Step 3 — Verify SOC Framework Routing

Vision One alerts are classified as **Endpoint** category by the SOC Framework's product classification. Confirm the following in `SOCProductCategoryMap_V3`:

- Dataset key: `trend_micro_vision_one_v3_generic_alert` → Category: `Endpoint`

If the key is missing, add it. The framework will fall through to a default category otherwise.

---

## Step 4 — Confirm Shadow Mode is Active

All Containment, Eradication, and Recovery actions for the Endpoint category run in Shadow Mode by default. Verify in `SOCFrameworkActions_V3` that endpoint actions have `shadow_mode: true`.

In Shadow Mode, every action is logged to the warroom and written to `xsiam_socfw_ir_execution_raw` with `execution_mode: shadow` — but no vendor command is sent to Vision One. This lets you validate the full NIST IR lifecycle and measure MTTD/MTTC/MTTR during a PoV without touching production endpoints.

**To go live:** Set `shadow_mode: false` per action in `SOCFrameworkActions_V3`. This is the 1-flip production path.

---

## Step 5 — Validate End-to-End

1. Generate or replay a Vision One workbench alert
2. Confirm it appears in XSIAM with the correct layout
3. Confirm the SOC Framework playbook triggered (check war room)
4. Confirm MITRE tactic and technique are populated on the alert
5. Confirm `xsiam_socfw_ir_execution_raw` has a record for the alert with `execution_mode: shadow`

---

## Value Driver Alignment

| What This Enables | Value Driver |
|---|---|
| Automated triage with MITRE routing — analyst sees verdict without manual investigation | VD3 — Operational Efficiency |
| Full lifecycle timestamps in Shadow Mode — MTTD/MTTC/MTTR demonstrable during PoV | VD1 — Reduce Risk |
| Single correlation rule replaces per-tactic rule sprawl | VD2 — Simplify Operations |
| 1-flip production path — zero changes to playbooks or rules to go live | VD2 — Simplify Operations |

---

For questions or support, contact your Palo Alto Networks Field Team or the SOC Framework maintainers at [github.com/Palo-Cortex/secops-framework](https://github.com/Palo-Cortex/secops-framework).
