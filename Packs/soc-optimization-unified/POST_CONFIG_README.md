# Post-Installation Configuration

After the pack is installed, these manual steps are required to complete the configuration.

---

## Quick Start (5 minutes)

**1. Enable the Auto Triage job**
- Navigate to **Investigation & Response → Automation → Jobs**
- Find **JOB - Triage Alerts V3** → click **Enable**
- Refresh — status should show **Running** or **Completed**

**2. Configure the Starring Rule**
- Navigate to **Cases & Issues → Case Configuration → Starred Issues**
- Add rule: `Severity >= Medium` AND `Has MITRE Tactic`

**3. Configure the Automation Trigger**
- Navigate to **Investigation & Response → Automation → Automation Rules**
- Add rule: Run playbook **EP_IR_NIST (800-61)_V3** when `starred = true`

---

## What to Check Next

**Value Metrics Dashboard**
- Navigate to **Dashboards → XSIAM SOC Value Metrics V3**
- Select a **7-day** window for reporting
- The dashboard requires alerts to have fired playbooks with tasks. Give it a few hours after your first starred alert processes.

**Shadow Mode**
- All Containment, Eradication, and Recovery actions default to Shadow Mode
- Actions are logged to the warroom and written to `xsiam_socfw_ir_execution_raw` but vendor commands are not executed
- To move individual actions to production, set `"shadow_mode": false` in `SOCFrameworkActions_V3`

**Run a Health Check**
- Open any case and run the `SOCFWHealthCheck` script from the warroom
- It will report on integration instances, installed playbooks, jobs, and required lists

---

## Errored Jobs

If **JOB - Triage Alerts V3** or **JOB - Store Playbook Metrics in Dataset V3** show as **Error**:

**Step 1 — Verify the playbooks are installed**

In the Playbook Library (**Investigation & Response → Automation → Playbooks**), verify both playbooks exist:

```
JOB - Triage Alerts V3
JOB - Store Playbook Metrics in Dataset V3
```

If they are missing, the pack installation failed. Re-run the installer.

**Step 2 — Check for a registration timing gap**

A known XSIAM behavior: there is sometimes a delay between when a custom content pack installs and when its playbooks become available to jobs. If the job shows **"Missing/Deleted playbook"** but the playbook exists in the library:

1. Wait 30–60 minutes
2. Hard-refresh the page
3. If the playbook now appears, click **Run now** to verify it executes

**Step 3 — Clean stuck job runs**

If previous job runs are stuck in **Running** status, clean them before enabling:

1. In the top-right corner of the Jobs screen, click the hamburger menu → **Switch to Detailed View**
2. For each run showing **Running**:
   - Click the Run ID
   - Go to the **Work Plan** tab
   - Click **Choose a playbook**
   - Select **SOC Close Cases V3** or another simple close playbook to terminate the run
3. Once all stuck runs are cleared, click **Enable** on the job
