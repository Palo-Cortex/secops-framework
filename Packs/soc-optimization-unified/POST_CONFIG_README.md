# Install the SOC Framework

Install the framework pack on a tenant, connect its two datasets, pick the evaluation mode, and confirm with the health check. About 30 minutes. Nothing on the estate changes: every action that would change something ships in Shadow Mode, whichever lifecycle you install on top.

## Before you start

All of these must be true. If one is not, stop here; nothing below will work until it is.

- An XSIAM tenant where you can install Marketplace packs, create HTTP Collectors and edit integration instances.
- An API key for that tenant (Settings → Configurations → Integrations → API Keys) with the Instance Administrator role, which the Package Manager needs to install packs; its key ID; and the tenant's API URL.
- At least one data source already ingesting, ideally endpoint, email or identity, which are the ones to connect first.
- Nothing else. There is no pre-configuration step for this pack.

## 1. Install the Package Manager

1. Marketplace → search **SOC Framework Pack Manager** → Install.
2. Settings → Integrations → **SOC Framework Pack Manager** → add an instance.
3. Enter the API Key, API ID and API URL from *Before you start*. Save.

## 2. Apply the framework pack

From the Playground:

```
!SOCFWPackManager action=apply pack_id=soc-optimization-unified
```

This installs the pack and creates its lists, lookups, jobs and the two Dataset Writer instances with placeholder values. The next two steps replace the placeholders.

## 3. Create the two HTTP Collectors

Settings → Data Sources → Add Data Source → **Custom - HTTP Collector**. Create one per row. Vendor is `XSIAM` for both.

| Product | Dataset it creates | What reads it |
|---|---|---|
| `socfw_ir_execution` | `xsiam_socfw_ir_execution_raw` | Value Metrics dashboards, health dashboard |
| `socfw_case_ledger` | `xsiam_socfw_case_ledger_raw` | Case ledger |

Copy each collector's API URL and API key from its **Connection Details**. You need them in the next step.

## 4. Point the Dataset Writers at the collectors

Settings → Integrations → **SOC Framework Dataset Writer**. Both instances already exist. Edit them; do not create new ones, because scripts call them by these exact names.

| Instance | Product Name | Paste from |
|---|---|---|
| `socfw_ir_execution_writer` | `socfw_ir_execution` | the execution collector |
| `socfw_case_ledger_writer` | `socfw_case_ledger` | the case ledger collector |

1. Replace `REPLACE-ME-collector-url` and `REPLACE-ME-collector-api-key` with that collector's values.
2. Confirm Product Name matches the table and Vendor Name is `XSIAM`. Together they select the dataset.
3. Click **Test**. It posts one probe event, so a pass proves the URL, the key and the write path.

## 5. Set the evaluation mode

From the Playground, with the email of the person who will own the framework jobs on this tenant:

```
!SOCFWConfig command=mode mode=pov owner=<email> apply=yes
```

One command sets the switches an evaluation needs: the Auto Triage and Analyst Assignment jobs on, star-on-assessment and case assignment live for automation, and every emergency-response action in Shadow Mode. Run it without `apply=yes` first to see the plan.

| Setting | Before | After `mode=pov` |
|---|---|---|
| Job `Auto Triage V3` | off | on, owner set |
| Job `SOCFW Analyst Assignment` | off | on, owner set |
| `soc-star-case` for automation | shadow | live |
| `soc-assign-case` for automation | shadow | live |
| `soc-close-issue` for ai | shadow | live in the shipped list; under review, see [AI Close Decision](https://palo-cortex.github.io/secops-framework/soc-framework-nist-ir-ai/close-decision/) |
| Every `issue_emergency` action | shadow | shadow |
| All other changing actions | shadow | shadow |

## 6. Verify

From the Playground:

```
!SOCFWHealthCheck
```

**Expected:** overall status `OK` or `WARN`, never `FAIL`, with:

- **Configuration (SOCFWConfig)** readable, and **Mode** matching `pov`.
- **Instance: socfw_ir_execution_writer** and **Instance: socfw_case_ledger_writer** enabled.
- Every **List:** row present.
- **JOB: Auto Triage V3** and **JOB: SOCFW Analyst Assignment** on, with the owner you set.
- **Analyst assignment roster** as `WARN` with "no roster yet" is normal until the job's first run.

A `WARN` on **Customer values** names a vendor value the framework needs for an integration you have enabled; set it with `!SOCFWConfig command=set` as the check says. A `FAIL` on **Configuration** means step 2 did not complete; re-run it.

The health check inventories presence, not behaviour. Correlation rules are checked on the next page, when the data sources are connected.

## Next

- **Connect a data source** — install the vendor pack for each evaluation source and switch to its SOC Framework correlation rules.
- **Install a lifecycle** — the framework does nothing on its own. NIST IR AI (issue assessment and case analysis, installed by hand) is the lifecycle documented here.
- **Run a scenario** — replay a known attack and watch the lifecycle call framework actions in Shadow Mode.

---

Verified against **soc-optimization-unified 3.31.1** source and the current install README · Tenant run: **pending** · Internal mapping: Notion, Evaluate track
