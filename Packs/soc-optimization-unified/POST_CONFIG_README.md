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
6. **Create the HTTP Collectors.** Settings -> Data Sources -> Add Data Source ->
   **Custom - HTTP Collector**. Create one per row; Vendor is `XSIAM` for both.

    | Product | Dataset it creates | Read by |
    | --- | --- | --- |
    | `socfw_ir_execution` | `xsiam_socfw_ir_execution_raw` | Value Metrics dashboards |
    | `socfw_case_ledger` | `xsiam_socfw_case_ledger_raw` | Case-scoped analysis |

   Copy each collector's API URL and API key from its **Connection Details**.
7. **Configure the two Dataset Writer instances.** Applying the pack creates both
   with placeholder values. Edit them rather than creating new ones — scripts and
   playbooks address them by name, so the names must match exactly.

    | Instance | Product Name | Collector |
    | --- | --- | --- |
    | `socfw_ir_execution_writer` | `socfw_ir_execution` | execution metrics |
    | `socfw_case_ledger_writer` | `socfw_case_ledger` | case ledger |

    - Replace `REPLACE-ME-collector-url` and `REPLACE-ME-collector-api-key` with
      that collector's values.
    - Confirm Product Name matches the table. Vendor Name stays `XSIAM`.
      Together they select the target dataset.
    - Click **Test** — it posts a single probe event, so a pass confirms the URL,
      the key, and the write path end to end.
    - Command reference:
      [SOC Framework Dataset Writer](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-optimization-unified/Integrations/SOCFWDatasetWriter/README.md)
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
[README.md](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-optimization-unified/README.md).
