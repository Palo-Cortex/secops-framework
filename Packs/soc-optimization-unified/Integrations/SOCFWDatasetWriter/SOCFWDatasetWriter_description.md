### Setup

1. Go to **Settings → Data Sources** and open (or create) the HTTP Collector for the SOC Framework execution dataset.
2. Copy the **API URL** from Connection Details into **HTTP Collector URL**.
3. Copy the **API Key** into **API Key**.
4. Leave **Vendor Name** and **Product Name** at their defaults unless you are routing this instance to a different dataset.

**Vendor** and **Product** determine the target dataset. The defaults `XSIAM` and `socfw_ir_execution` write to `xsiam_socfw_ir_execution_raw`, which is what the Value Metrics dashboards read.

### Usage

This integration is called by SOC Framework content, not directly by analysts.

- `SOCCommandWrapper` writes one execution record per Universal Command action.
- `Foundation - Dedup_V3` writes the dedup outcome.
- `SOC_Analysis_Evaluation_V3` writes the `analysis_complete` MTTI anchor.
- `JOB - Auto Triage V3` writes per-case triage outcomes.

Each caller addresses this instance by name, so a tenant can point separate lifecycles at separate collectors by configuring additional instances.

Writes are non-blocking. If this integration is missing or unconfigured, callers record the failure and continue — no playbook stops because a metrics write failed.
