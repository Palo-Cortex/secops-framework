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
    - HTTP Collector URL: replace `REPLACE-ME-collector-url` with the API URL
      copied above
    - API Key: replace `REPLACE-ME-collector-api-key` with the collector API key
      copied above
    - Click **Test** — it posts a single probe event, so a passing test confirms
      the URL, the key, and the write path end to end.
    - Vendor Name and Product Name default to `XSIAM` and `socfw_ir_execution`,
      which target the `xsiam_socfw_ir_execution_raw` dataset created in step 6.
      Change them only when pointing an instance at a different collector and
      dataset. Additional instances can be configured to write other lifecycles
      to their own datasets.
    - Full setup and command reference:
      [SOC Framework Dataset Writer](Integrations/SOCFWDatasetWriter/README.md)
8. **Enable the Auto-Triage job** (`JOB_-_Auto_Triage_V3`).
    - Default behavior closes cases with case risk score ≤ 40.
    - Starring remains a supported alternative if your tenant uses Starred
      Issues instead of risk scoring.
9. **Create an Automation Trigger** for `EP_IR_NIST (800-61)_V3` on all alerts
   of severity **Medium or higher**.
10. **Configure the NIST IR Layout Rule:**
    - Severity: **Medium or higher**
    - Issue Domain: **Security**

---

Running the framework and reading the Value Metrics dashboards are covered in
[README.md](README.md).
