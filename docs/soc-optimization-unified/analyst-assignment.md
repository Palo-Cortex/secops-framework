---
title: "Analyst Assignment"
---

# Analyst Assignment

Analyst assignment keeps a roster of who is on duty in the lookup `socfw_on_duty` and gives each unassigned open case an owner from that roster, least-loaded first, so a case that needs a person has one within minutes of being starred.

## 1. What it does

Two scripts run from the job **SOCFW Analyst Assignment** every five minutes:

| Step | Script | What it does |
|---|---|---|
| Sync the roster | `SOCFWOnDutySync` | Asks every configured schedule source who is on duty through the action `soc-sync-on-duty` (PagerDuty ships; others join the same action), and keeps `socfw_on_duty` in step: each source owns and replaces only its own rows. With no schedule source set up, the tenant's own users fill the roster by role or user group. `analysts=<emails>` sets a manual list for a tenant with no schedule system. |
| Assign cases | `SOCFWAnalystSelect` | Picks unassigned open cases in the configured domains and window (starred only, with the shipped setting), re-reads each one just before acting, and assigns it through the action `soc-assign-case` to the on-duty analyst holding the fewest open cases, never above the per-analyst cap, and only to analysts logged in when `online_only` is set. |

The lookup is created by the first sync and never wiped. A schedule source that errors, is not configured or answers with nobody changes nothing. A role or group setting that matches no tenant user removes the fallback rows, so the roster never silently keeps people a changed setting no longer names. The framework assigns a case once and never replaces an owner.

## 2. Where the switch lives

| Where | Key | Shipped default | Evaluation | Production |
|---|---|---|---|---|
| Job `SOCFW Analyst Assignment` | `!SOCFWConfig command=job`, `command=owner` | off, placeholder owner | on, with a real owner (`mode=pov` turns it on) | on |
| `SOCFrameworkActions_V3` → `soc-assign-case` | `shadow_mode_by_actor.automation` | shadow for every actor | live for `automation` in `mode=pov` | live for `automation` once the shadow rows show the right people |
| `SOCFWTenantConfig` → `assignment` | `roles`, `groups`, `cases`, `domains`, `window`, `max_per_analyst`, `online_only` (set with `!SOCFWConfig command=assignment`) | not set; the shipped values below apply | `groups` set to the analyst group | same, plus `cases=all` where every open case should have an owner |
| `SOCOptimizationConfig_V3` → `Analyst Assignment JOB` | `AssignmentRoles`, `AssignmentGroups`, `AssignmentCases`, `AssignmentDomains`, `AssignmentWindow`, `AssignmentMaxPerAnalyst`, `AssignmentOnlineOnly`, `AssignmentMethod` | `Instance Administrator,Account Admin` · (none) · `starred` · `security` · `24 hours` · `20` · `true` · `least_loaded` | read only; the tenant section above overrides it | read only |
| `SOCFWTenantConfig` → `PagerDuty v2` | `schedule_ids` (`!SOCFWConfig command=set`) | not set | set when the customer uses PagerDuty | same |

> The shipped role fallback is the two admin roles, because every tenant has them. Most customers set `groups` to their analyst group and `roles=none` before turning the job on, so the roster is the people who work cases.

## 3. Turn it on

1. See the settings in force and where each comes from:

    ```
    !SOCFWConfig command=assignment
    ```

2. Point the fallback at the analysts (a comma list; quote names with spaces), and read the dry run:

    ```
    !SOCFWConfig command=assignment groups="SOC Analysts" roles=none
    ```

3. Apply it. `default` returns a setting to the shipped value; `none` turns the role or group fallback off:

    ```
    !SOCFWConfig command=assignment groups="SOC Analysts" roles=none apply=yes
    ```

4. Set the job's owner and turn it on:

    ```
    !SOCFWConfig command=owner job="SOCFW Analyst Assignment" owner=<a tenant user> apply=yes
    !SOCFWConfig command=job job="SOCFW Analyst Assignment" value=on apply=yes
    ```

5. Leave `soc-assign-case` shadowed for a day and read the rows (step 4 below). When the people and cases are right, take it live for the job's actor:

    ```
    !SOCFWConfig command=shadow action=soc-assign-case actor=automation value=off apply=yes
    ```

## 4. Verify

```
config timeframe = 24h
| dataset = xsiam_socfw_ir_execution_raw
| filter event_type in ("on_duty_sync", "analyst_assignment")
| fields _time, event_type, action_actor, case_id, assignee, status, on_duty_count, on_duty_added, on_duty_removed, execution_mode
| sort desc _time
```

**Expected:** one `on_duty_sync` row per run naming what each source added and removed, and one `analyst_assignment` row per case decision with the assignee and `execution_mode` `shadow` (simulated) or `production` (assigned). `!SOCFWHealthCheck` shows **Analyst assignment roster** with the count per source, and warns when the roster comes only from the role fallback, naming `command=assignment` as the fix.

## 5. What it feeds

| Surface | What you see |
|---|---|
| Lookup `socfw_on_duty` | Who is on duty now, with the source that put them there and when |
| Dataset `xsiam_socfw_ir_execution_raw` | `on_duty_sync` rows (roster changes over time), `analyst_assignment` rows (every decision with each analyst's load at that moment), `config_change` rows for every setting applied |
| `!SOCFWHealthCheck` | The roster, its sources, and the job's state and owner |
| `!SOCFWConfig command=status` | The assignment settings with their source (shipped or tenant) |
| The case | An owner, set once; the War Room entry names the action and the actor |

---

Verified against **soc-optimization-unified 3.31.2** source (`SOCFWOnDutySync`, `SOCFWAnalystSelect`, `SOCFWConfig`, the job playbook and the lists) · Tenant run: **2026-11-03** · Internal mapping: Notion, Capability Reference row *Analyst assignment JOB + on-duty roster*
