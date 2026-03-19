# SOC Framework for Cortex XSIAM

The SOC Framework turns XSIAM into a structured, repeatable incident response machine. Every alert that matters gets normalized, enriched, analyzed, and — when you're ready — contained and remediated through a standardized NIST IR lifecycle. You control the pace. Shadow Mode lets the framework show you exactly what it *would* do without touching a single endpoint, making it safe to run in any environment from day one.

---

## Five Things Worth Understanding First

### 1. Every alert runs through the same foundation

When a starred alert fires the entry point playbook, `Foundation - Upon Trigger V3` runs immediately — on every alert, every time. It normalizes artifacts, classifies the product category, deduplicates, and enriches before the analyst ever sees it. This is what eliminates the swivel-chair work.

### 2. The lifecycle follows NIST IR 800-61

After the Foundation, alerts enter a structured lifecycle:

```
Alert → Foundation → Analysis → Containment → Eradication → Recovery
```

Each stage has a clear contract — a defined set of context keys it reads and writes. Containment doesn't guess what Analysis found; it reads `Analysis.verdict` and `Analysis.compromise_decision`. Each stage is independent and replaceable without touching the others.

→ [Lifecycle Contracts](./docs/contracts.md)

### 3. Shadow Mode is the default — nothing executes until you say so

Every Containment, Eradication, and Recovery action is registered in `SOCFrameworkActions_V3` with `shadow_mode: true`. The Universal Command (`SOCCommandWrapper`) reads that flag before doing anything. In shadow mode it:

- Prints the action to the warroom so analysts can see exactly what would happen
- Writes the record to the `xsiam_socfw_ir_execution_raw` dataset for metrics
- Does **not** call the vendor command

To move a specific action to production, set `shadow_mode: false` for that action in `SOCFrameworkActions_V3`. The switch is per-action — you can run isolation in production while credential resets stay in shadow.

→ [Shadow Mode Detail](./docs/shadow_mode.md)

### 4. The Universal Command abstracts vendor differences

`SOCCommandWrapper` is a single script that handles every action across every vendor. When a playbook needs to isolate an endpoint, it calls `soc-isolate-endpoint`. The wrapper looks up which EDR is installed (CrowdStrike, Cortex, Defender, Trend Micro) and calls the right vendor command with the right arguments. Playbooks never contain vendor-specific logic.

→ [Universal Command Reference](./docs/universal_command.md)

### 5. Value metrics are built in from day one

Every action that runs through `SOCCommandWrapper` is written to the `xsiam_socfw_ir_execution_raw` dataset. The `JOB - Store Playbook Metrics in Dataset V3` job collects task-level data and joins it against the `value_tags` lookup table. The result powers the **XSIAM SOC Value Metrics** dashboard — hours saved, vendor usage, automation coverage by category — without any custom configuration.

→ [Value Metrics](./docs/value_metrics.md)

---

## Quick Setup

These steps complete the configuration after the pack is installed.

**1. Enable the Auto Triage job**

Auto Triage is disabled by default to protect existing tenants.

- Navigate to **Investigation & Response → Automation → Jobs**
- Find **JOB - Triage Alerts V3** and click **Enable**

This job automatically closes low-priority, non-starred alerts. Without it, your case queue will fill with noise.

→ [Auto Triage](./docs/auto_triage.md)

**2. Set your starring rule**

Starred alerts are what feed the NIST IR lifecycle. A reasonable default:

- Navigate to **Cases & Issues → Case Configuration → Starred Issues**
- Add rule: `Severity >= Medium` **AND** `Has MITRE Tactic`

**3. Add the automation trigger**

- Navigate to **Investigation & Response → Automation → Automation Rules**
- Add rule: Run playbook **EP_IR_NIST (800-61)_V3** when `starred = true`

This is the catch-all. You can layer more specific rules above it (e.g., trigger a phishing-specific EP on T1566) — the catch-all handles everything else.

**4. Verify the Value Metrics dashboard**

- Navigate to **Dashboards → XSIAM SOC Value Metrics V3**
- Select **7 days** for a realistic reporting window

The dashboard will be empty until alerts fire playbooks and tasks run. Give it a few hours after setup.

---

## Components

### Foundation Playbooks

These run on every alert. They are shared infrastructure — you do not modify them for individual use cases.

| Playbook | Purpose |
|---|---|
| `Foundation - Upon Trigger V3` | Entry point for all alert processing. Calls the entire Foundation chain. |
| `Foundation - Normalize Artifacts V3` | Extracts and standardizes entities: user, endpoint, IP, hash, domain, URL |
| `Foundation - Product Classification V3` | Identifies the alert source category (Endpoint, Email, Identity, Network, SaaS, Workload) and routes to the correct lifecycle playbook |
| `Foundation - Enrichment V3` | Runs enrichment pipelines tailored to the classified product category |
| `Foundation - Dedup V3` | Suppresses duplicate alerts within the configured dedup window |
| `Foundation - Assessment V3` | Evaluates alert risk and determines escalation need |
| `Foundation - Escalation V3` | Handles escalation logic for critical or unresolved alerts |
| `Foundation - Environment Detection V3` | Detects tenant environment context used by shadow mode logic |
| `Foundation - Data Integrity V3` | Validates context key completeness before lifecycle handoff |
| `Foundation - Error Handling V3` | Catches and logs playbook errors without breaking the pipeline |
| `Foundation - Performance Capture V3` | Records timing data for MTTD/MTTC metrics |

### Job Playbooks

| Playbook | Purpose |
|---|---|
| `JOB - Triage Alerts V3` | Runs on a schedule. Closes non-starred alerts that meet triage criteria. Keeps the case queue clean. |
| `JOB - Store Playbook Metrics in Dataset V3` | Runs on a schedule. Collects task-level execution data and writes to `xsiam_playbookmetrics_raw` for the Value Metrics dashboard. |

### Communications Playbooks

Fire-and-forget side effects. Never block the main lifecycle flow.

| Playbook | Purpose |
|---|---|
| `SOC Comms Email V3` | Sends email notifications at configured lifecycle stages |
| `SOC Comms IM V3` | Sends instant message notifications (Slack, Teams, etc.) |
| `SOC Comms Ticketing V3` | Creates or updates tickets in integrated ticketing systems |

### Scripts

| Script | Purpose |
|---|---|
| `SOCCommandWrapper` | Universal Command. Reads `SOCFrameworkActions_V3` to determine the vendor command and shadow mode state for every action. The only script that calls vendor APIs. |
| `setValueTags_V3` | Tags playbook tasks for the value metrics system. Maps tasks to categories (enrichment, containment, eradication, etc.) and vendor. |
| `SOCFWHealthCheck` | Validates that required integrations, playbooks, jobs, and lists are correctly installed. Run this to diagnose a broken deployment. |

### Configuration Lists

| List | Purpose |
|---|---|
| `SOCFrameworkActions_V3` | Maps every SOC action (`soc-isolate-endpoint`, `soc-delete-file`, etc.) to vendor-specific commands and sets `shadow_mode` per action. **This is where you flip Shadow Mode to production.** |
| `SOCExecutionList_V3` | Controls which lifecycle playbooks are active and sets their `execute_branch`. |
| `SOCProductCategoryMap_V3` | Maps alert sources to product categories (Endpoint, Email, Identity, Network, SaaS, Workload, PAM, Data). Drives the routing in Product Classification. |
| `SOCOptimizationConfig_V3` | Runtime configuration for jobs: triage window, metrics lookback, dedup window. |
| `SOCFWConfig` | Framework-level configuration: required integration brands, entry point prefixes, required datasets. Used by health checks. |

### Datasets

| Dataset | Written by | Used for |
|---|---|---|
| `xsiam_socfw_ir_execution_raw` | `SOCCommandWrapper` | Records every action execution (shadow and production). Primary dataset for execution metrics. |
| `xsiam_playbookmetrics_raw` | `JOB - Store Playbook Metrics in Dataset V3` | Task-level execution data for the Value Metrics dashboard. |

---

## How Shadow Mode Works End to End

```
Lifecycle playbook reaches a C/E/R action
  → calls SOCCommandWrapper with action = "soc-isolate-endpoint"
  → wrapper reads SOCFrameworkActions_V3
       entry: { "shadow_mode": true, "responses": { "CrowdstrikeFalcon": {...} } }
  → shadow_mode is true:
       warroom → "SHADOW MODE — cs-falcon-contain-host would have run"
       dataset → xsiam_socfw_ir_execution_raw (execution_mode: "shadow")
       vendor command → NOT called
  → shadow_mode is false (production):
       vendor command → called
       dataset → xsiam_socfw_ir_execution_raw (execution_mode: "production")
```

To move to production for a specific action, edit `SOCFrameworkActions_V3` and set `"shadow_mode": false` for that action. No playbook changes required.

---

## Lifecycle Stage Contracts

Each stage defines what context it expects to receive and what it promises to write before handing off to the next stage. These contracts are what make the Framework composable — a new use case can reuse existing stages as long as it honors the contracts.

| Stage | Key inputs | Key outputs |
|---|---|---|
| **Foundation** | Raw alert fields | `SOCFramework.Artifacts.*`, `SOCFramework.Product.category`, `SOCFramework.Mitre.*` |
| **Analysis** | Foundation artifacts | `Analysis.verdict`, `Analysis.confidence`, `Analysis.compromise_decision` |
| **Containment** | Analysis verdict | `Containment.action`, `Containment.status`, `Containment.isolate_hosts` |
| **Eradication** | Containment status | `Eradication.files_removed`, `Eradication.persistence_removed`, `Eradication.success` |
| **Recovery** | Eradication success | `Recovery.restore_required`, `Recovery.restore_method`, `Recovery.status` |

→ [Full Contract Reference](./docs/contracts.md)

---

## Troubleshooting

**Dashboard is empty**
Alerts must fire playbooks and tasks must run before metrics appear. Confirm the automation trigger is configured and at least one starred alert has processed. Check `xsiam_playbookmetrics_raw` exists in your XQL dataset list.

**Job shows as Error**
See the [Job Troubleshooting](./POST_CONFIG_README.md#errored-jobs) section. The most common cause is the playbook registering with a timing delay after pack install. Wait 30–60 minutes and try enabling the job again.

**Actions not executing after flipping shadow mode**
Verify the integration instance is installed and the brand name in `SOCFrameworkActions_V3` matches the exact brand name of the configured instance in Settings → Integrations.

**Run SOCFWHealthCheck** to get a structured diagnostic of your installation:
- Integration instances present and enabled
- Required playbooks installed
- Required jobs configured
- Required lists and datasets present
