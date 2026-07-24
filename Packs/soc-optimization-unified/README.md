# SOC Framework — Foundation Pack

Foundation layer for the Palo Alto Networks XSIAM SOC Framework. Provides the
shared infrastructure every Framework deployment depends on: Universal Command,
Shadow Mode, the Upon Trigger Foundation chain, Auto-Triage, the execution
dataset, and the Value Metrics dashboards.

This pack is the base. Vendor lifecycle packs (SOC CrowdStrike Falcon, SOC Microsoft
Defender, SOC Trend Micro, SOC Proofpoint TAP, etc.) install on top of it.

---

## Components

### Universal Command

`SOCCommandWrapper` is the single interface every action goes through. Action
playbooks never call a vendor integration directly — they call the wrapper,
which resolves the action, applies Shadow Mode, executes or simulates, and
writes one execution record per action.

This is what makes the Framework vendor-agnostic: swapping CrowdStrike for
SentinelOne changes a registration in `SOCFrameworkActions_V3`, not a playbook.

### Shadow Mode

Per-action `shadow_mode` flag in `SOCFrameworkActions_V3`, read by
`SOCCommandWrapper`. When set, the action prints its intent to the war room and
writes its execution record, but does not call the vendor.

Containment, eradication, and recovery become visible without touching
production. Flipping a single flag per action moves it to live execution — the
same content runs in a PoV and in production.

### Foundation chain

Runs on every alert regardless of lifecycle, before any lifecycle logic.

| Playbook | Role |
|---|---|
| `Foundation_-_Upon_Trigger_V3` | Entry into the chain. Must never stop. |
| `Foundation_-_Product_Classification_V3` | Resolves the product category via `SOCProductCategoryMap_V3` |
| `Foundation_-_Normalize_Artifacts_V3` | Maps vendor fields into `SOCFramework.Artifacts.*` |
| `Foundation_-_Enrichment_V3` | Indicator and asset enrichment |
| `Foundation_-_Dedup_V3` | Duplicate suppression, canonical-case selection |
| `Foundation_-_Data_Integrity_V3` | Contract validation |
| `Foundation_-_Environment_Detection` | Shadow vs production mode resolution |
| `Foundation_-_Error_Handling` | Shared failure path |
| `Foundation_-_Case_Sync`, `Foundation_-_Escalation`, `Foundation_-_Assessment`, `Foundation_-_Performance_Capture` | Case state, escalation, scoring support |

Only Foundation reads `issue.*` fields. Downstream lifecycle playbooks consume
`SOCFramework.*` keys.

### Auto-Triage

`JOB_-_Auto_Triage_V3` runs on schedule and auto-closes low-signal cases —
by default those with case risk score ≤ 40, scoped by domain and age window.
Configuration lives in `SOCOptimizationConfig_V3`. Hours saved feed the Value
Metrics dashboards.

### Execution dataset

`SOCFWDatasetWriter` posts execution records to an XSIAM HTTP Collector,
producing `xsiam_socfw_ir_execution_raw`. Every writer — Universal Command,
Dedup, Auto-Triage, and the NIST IR analysis anchor — addresses the
`socfw_ir_execution_writer` instance by name.

Writes are non-blocking. A missing or unconfigured instance is recorded and
the run continues; no playbook stops because a metrics write failed.

### Configuration lists

Runtime-tunable by PS and customers without editing content.

| List | Controls |
|---|---|
| `SOCFrameworkActions_V3` | Action registry, vendor bindings, per-action `shadow_mode` |
| `SOCExecutionList_V3` | Which branch each Workflow playbook runs |
| `SOCProductCategoryMap_V3` | Source → product category routing |
| `SOCActionTimeMap_V3` | Analyst-minutes per action, the time-saved source |
| `SOCActionClassMap_V3` | Action classification |
| `SOCOptimizationConfig_V3` | Auto-Triage, Dedup, and Shadow Mode settings |
| `SOCFWFeatureFlags` | Feature gating |

### Identity resolution

`SOC IdentityResolve` correlation rule plus the CIE identity overlay pattern
used by vendor packs to join alerts to canonical identities.

### Value Metrics

Three dashboards driven by `xsiam_socfw_ir_execution_raw`. See
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
6. **Create the execution-metrics HTTP Collector:**
    - Settings → Data Sources → Add Data Source → **Custom - HTTP Collector**
    - Vendor: `XSIAM`
    - Product: `socfw_ir_execution`
    - This creates the `xsiam_socfw_ir_execution_raw` dataset that the Value
      Metrics dashboards read from.
    - Open the collector's **Connection Details** and copy the API URL and API key.
7. **Configure the SOC Framework Dataset Writer integration instance:**
    - Applying the pack creates an instance named `socfw_ir_execution_writer`
      with placeholder values. Edit that instance rather than creating a new
      one — playbooks and scripts address it by name via `using`, so the name
      must match exactly.
    - HTTP Collector URL: replace `REPLACE-ME-collector-url`
    - API Key: replace `REPLACE-ME-collector-api-key`
    - Vendor Name and Product Name default to `XSIAM` and `socfw_ir_execution`,
      matching the collector created above.
    - Click **Test** — it posts a single probe event, so a passing test confirms
      the URL, the key, and the write path end to end.
8. **Enable the Auto-Triage job** (`JOB_-_Auto_Triage_V3`).
    - Default behavior closes cases with case risk score ≤ 40.
    - Starring remains a supported alternative if your tenant uses Starred
      Issues instead of risk scoring.
9. **Create an Automation Trigger** for `EP_IR_NIST (800-61)_V3` on all alerts
   of severity **Medium or higher**.
10. **Configure the NIST IR Layout Rule:**
    - Severity: **Medium or higher**
    - Issue Domain: **Security**

Post-install configuration detail, including collector setup and troubleshooting,
lives in [POST_CONFIG_README.md](POST_CONFIG_README.md).

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
