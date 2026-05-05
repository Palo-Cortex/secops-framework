# SOC Framework — Foundation Pack

Foundation layer for the Palo Alto Networks XSIAM SOC Framework. Provides the
shared infrastructure every Framework deployment depends on: Universal Command,
Auto-Triage, the Modular Playbooks "Upon Trigger Foundation" chain, and the
Value Metrics dashboards.

This pack is the base. Vendor lifecycle packs (SOC CrowdStrike Falcon, SOC Microsoft
Defender, SOC Trend Micro, SOC Proofpoint TAP, etc.) install on top of it.

---

## Components

- **Auto-Triage** — `JOB_-_Auto_Triage_V3` runs on schedule and auto-closes
  cases with case risk score ≤ 40. Hours saved feed the Value Metrics dashboard.
- **Modular Playbooks (Upon Trigger Foundation)** — `Foundation_-_Upon_Trigger_V3`
  and the Foundation enrichment / normalization chain. Runs on every alert,
  classifies the source, and routes into the NIST IR lifecycle.
- **Value Metrics** — three dashboards driven by the
  `xsiam_socfw_ir_execution_raw` dataset. See
  *Reading the metrics* below.

---

## Content

Marketplace → search **"SOC"** for the full set of installable Framework packs
(Foundation, NIST IR Lifecycle, Pack Manager, vendor packs).

---

## What's required

- An XSIAM tenant
- **Case Risk Scores** *and / or* **Starred Issues** enabled — Auto-Triage uses one
  of these to gate case auto-closure
- A Standard XSIAM API Key
    - Security Level: **Standard**
    - Role: **Instance Administrator**
- A credential entry on the tenant
    - API Key
    - API ID
    - Name: **`Standard XSIAM API Key`**

---

## How to install and set up

1. **Install the SOC Framework Pack Manager** from the Marketplace.
2. **Configure the SOC Framework Pack Manager integration instance:**
    - API Key
    - API ID
    - API URL
3. **Apply the Foundation pack** from the Playground:
   ```
   !SOCFWPackManager action=apply pack_id=soc-optimization-unified
   ```
4. **Run the health check** from the Playground:
   ```
   !SOCFWHealthCheck
   ```
   Correlation rule activation must be checked manually — the health check
   inventories presence, not behavior.
5. **Switch to the SOC Framework correlation rules** for your enabled sources
   (SOC CrowdStrike Falcon, SOC Microsoft Defender, SOC Trend Micro, etc.). Disable any vendor
   defaults that overlap with the Framework's rules.
6. **Enable the Auto-Triage job** (`JOB_-_Auto_Triage_V3`).
    - Default behavior closes cases with case risk score ≤ 40.
    - Starring remains a supported alternative if your tenant uses Starred
      Issues instead of risk scoring.
7. **Create an Automation Trigger** for `EP_IR_NIST (800-61)_V3` on all alerts
   of severity **Medium or higher**.
8. **Configure the NIST IR Layout Rule:**
    - Severity: **Medium or higher**
    - Issue Domain: **Security**

---

## How to run

### Default

Once setup is complete, no further action is required:

- Auto-Triage runs on schedule
- NIST IR runs on every Medium+ alert
- Value Metrics dashboards populate (MTTD, MTTI, MTTC, MTTE, MTTR)

### Show an attack

Optional — for live-fire demonstrations:

- **MITRE Turla Carbon Attack Lab**
    - Configure XDR agent policies for **logging only**
    - Install the XDR agent in a BYOS environment
    - Run the Turla Carbon scenario; the Value Metrics dashboards light up
      end-to-end through the lifecycle

---

## Reading the metrics

Three dashboards, each scoped to a different view of the same execution data.

### XSIAM SOC Value Driver Metrics V3

Top-level operational KPIs.

- Total Cases
- Total Starred Manual Cases
- Critical & High Alerts
- Security Tools Integration
- Cases Auto Resolved
- Total Manual Cases
- Total Alerts by Source
- Critical Alerts by Source
- Average Alert Ingestion Lag
- Top 20 Slowest Data Sources
- MTTD (sec) — Mean Time To Detect
- MTTI (min) — Mean Time To Investigate
- MTTC (min) — Mean Time To Contain
- MTTE (min) — Mean Time To Eradicate
- MTTR (min) — Mean Time To Recovery

### XSIAM SOC Value Metrics — Full Run

Production-mode automation impact. Filtered to `execution_mode = "production"`.

- Time Saved by Category
- Time Saved by XSIAM per Task
- XSIAM Vendor Usage
- Tools Used by XSIAM by Hour
- Total SOC Hours Worked by XSIAM
- Analysts Required without XSIAM (Events Per Hour 8–13)
- Analysts Required with XSIAM (EPH 8–13)
- Total Alerts by Data Source
- Total Alerts by Source — Total Alerts
- Total Cases
- Cases Auto Resolved
- Total Manual Cases
- Total Starred Manual Cases

### XSIAM SOC Value Metrics — Shadow Mode

Same widget set as Full Run, filtered to `execution_mode = "shadow"`. Use this
to show what the lifecycle *would* do in production while running safely in
shadow.
