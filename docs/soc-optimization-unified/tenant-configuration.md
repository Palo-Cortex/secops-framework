---
title: "Tenant Configuration"
---

# Tenant Configuration

One command, `!SOCFWConfig`, is how the framework is configured on a tenant after install: what is live or simulated for each actor, the customer values the vendor integrations need, which jobs run and who owns them, the emergency-response policies, the Auto Triage limits, and the deployment mode. Every change is a dry run until you add `apply=yes`, and every applied change is written to the tenant override list, so it survives pack upgrades and is recorded in the execution dataset.

## 1. What it does

`SOCFWConfig` reads the shipped lists (`SOCFrameworkActions_V3`, `SOCFrameworkPhasePolicy_V3`, `SOCOptimizationConfig_V3`, `SOCFWConfigModes`) and the tenant's own overrides in `SOCFWTenantConfig`, shows the result, and writes only to `SOCFWTenantConfig`. The shipped lists are never edited on the tenant, which is what makes an upgrade safe: the pack replaces its lists, the override stays, and the tenant's choices still win.

| Sub-command | What it does |
|---|---|
| `status` | Every action with its shadow value per actor, the list field that decided each one, the customer values and whether they are set, the jobs and their owners |
| `shadow` | Take one action on or off Shadow Mode for named actors, or return it to the shipped value |
| `set` | Set or remove one customer value for a vendor integration (a block-list id, a proxy category, the `using` instance) |
| `job` | Turn a framework job on or off |
| `owner` | Set the user who owns a job; a job cannot run without one |
| `emergency` | List, edit or add issue-level emergency response policies and their guards |
| `triage` | Show or set Auto Triage's score threshold and age window |
| `mode` | Apply a deployment mode; see [Deployment Modes](deployment-modes.md) |

## 2. Where the switch lives

| Where | Key | Shipped default | Evaluation | Production |
|---|---|---|---|---|
| Command | `command=` | `status` | as needed | as needed |
| Command | `apply=` | `no` (dry run) | `yes` only after reading the dry run | same |
| List `SOCFWTenantConfig` | `shadow.<action>.<actor>`, `value`, jobs, emergency, triage, mode | does not exist until the first `apply=yes` | created on the first write | the one list that carries this customer's choices; back it up before a tenant rebuild |
| Shipped lists | read only through this command | pack values | never edited on the tenant | never edited on the tenant |

> Edit the shipped lists on a tenant only if you want the change gone on the next upgrade. Everything a customer decides goes through `!SOCFWConfig` so it lands in the override.

## 3. Use it

The pattern is the same for every sub-command: read, dry-run, apply, read again.

1. `!SOCFWConfig command=status` to see the current state. Add `action=soc-isolate-endpoint,soc-revoke-tokens` to narrow the table.
2. Run the change without `apply=yes` and read the plan it prints. A refused change says why (an argument that belongs to another sub-command, a job with no owner, a value that is not allowed).
3. Add `apply=yes`.
4. `command=status` again to confirm.

Three examples:

```
!SOCFWConfig command=owner job="Auto Triage V3" owner=analyst@customer.example apply=yes
!SOCFWConfig command=set vendor=Zscaler arg=category-id value=12345 apply=yes
!SOCFWConfig command=triage score_threshold=30 window_hours=12 apply=yes
```

## 4. Verify

```
config timeframe = 7d
| dataset = xsiam_socfw_ir_execution_raw
| filter event_type = "config_change"
| fields _time, universal_command, action_actor, shadow_mode_state, job, action_status, action_taken
| sort desc _time
```

**Expected:** one row per applied change, with `action_taken` showing the before and after. `!SOCFWHealthCheck` reads the same override and grades **Configuration (SOCFWConfig)**, **Customer values**, the **JOB:** rows and **Auto Triage settings** from it.

## 5. What it feeds

| Surface | What you see |
|---|---|
| `!SOCFWHealthCheck` | Configuration, customer values, jobs, triage and emergency sections are all read through this command's status |
| Dataset `xsiam_socfw_ir_execution_raw` | `config_change` rows: a dated, attributable history of every switch flipped on the tenant |
| List `SOCFWTenantConfig` | The single place a customer's framework choices live |
| Universal command | Reads the override on every call, so a change here is live on the next action |

---

Verified against **soc-optimization-unified 3.31.1** source (`SOCFWConfig` arguments and row writer) · Tenant run: **pending** · Internal mapping: Notion, Capability Reference row *Tenant configuration CLI*
