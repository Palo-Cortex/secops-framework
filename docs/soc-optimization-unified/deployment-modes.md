---
title: "Deployment Modes"
---

# Deployment Modes

A mode is a named bundle of switches: which automated actions run for real, which stay in Shadow Mode, and which framework jobs are on. Applying one sets every switch in the bundle at once, so a tenant is always in a known state and moving between modes leaves nothing behind.

## 1. What it does

Four modes ship in the list `SOCFWConfigModes`. Each sets the shadow flag for the same eleven automated actions and the state of the same two jobs. A mode never changes analyst actions, the Auto Triage threshold or window, or the emergency-response protect and role settings; those are set separately.

| Mode | What runs for real | What stays in shadow |
|---|---|---|
| `pov` | Star case, analyst assignment; Auto Triage and Analyst Assignment jobs on. The shipped list also takes benign AI close live for actor `ai`; that value is under review and may move to shadow | Every other changing action, including all emergency response |
| `star_and_triage` | Star case; Auto Triage job on | AI close, assignment, every other changing action |
| `contain_identity_and_hosts` | Everything in `pov`, plus raise severity, close contained issues, and emergency clear sessions, revoke tokens, isolate endpoint | Email retract, domain and network blocks |
| `contain_all` | Every automated action in the list, including email retract and blocks | Nothing |

`mode=default` removes the mode's settings and turns Auto Triage off, back to what the pack installs.

## 2. Where the switch lives

| Where | Key | Shipped default | Evaluation | Production |
|---|---|---|---|---|
| Command | `!SOCFWConfig command=mode mode=<name> owner=<email> apply=yes` | no mode applied; the tenant reads as its raw defaults | `pov` | `star_and_triage` first, then `contain_identity_and_hosts`, then `contain_all` as the customer approves each step |
| Command | `owner=<email>` | none; a job with no owner stays off | the person running the evaluation | the customer's job owner |
| List `SOCFWConfigModes` | `modes.<name>.shadow.<action>.<actor>` and `modes.<name>.jobs` | the four modes above | leave as shipped | leave as shipped; add a mode only when the customer needs a fifth step |
| Tenant override `SOCFWTenantConfig` | written by the command | unset | written by `apply=yes` | written by `apply=yes`; survives pack upgrades |

## 3. Apply a mode

1. List the modes against the tenant's current state: `!SOCFWConfig command=mode`. Each mode shows which switches it would change.
2. Dry-run the one you want: `!SOCFWConfig command=mode mode=pov owner=<email>`. The output lists every switch and job that will change.
3. Apply it: add `apply=yes`.
4. Confirm: `!SOCFWConfig command=status` shows the actions with their new values, and `!SOCFWHealthCheck` reports **Mode** as matching.

To change modes later, apply the new one the same way. Every switch in the list is set again, so there is no residue from the previous mode.

## 4. Verify

```
config timeframe = 1h
| dataset = xsiam_socfw_ir_execution_raw
| filter event_type = "config_change"
| fields _time, universal_command, action_actor, shadow_mode_state, job, action_status, action_taken
| sort desc _time
```

**Expected:** one `config_change` row per switch the mode changed (`action_status` reads `mode pov`), plus one per job it turned on or off. `!SOCFWHealthCheck` then shows **Mode** as `matches pov` (or the mode you chose) and the two **JOB:** rows as on with the owner you gave.

## 5. What it feeds

| Surface | What you see |
|---|---|
| `!SOCFWConfig command=status` | Every action with its shadow value per actor and the mode name |
| `!SOCFWHealthCheck` | The **Mode** row, and whether the tenant drifted from it |
| Dataset `xsiam_socfw_ir_execution_raw` | `config_change` rows, so a change of mode is dated and attributable |
| Lifecycle dashboards | The shadow and live views split exactly along the lines the mode drew |

---

Verified against **soc-optimization-unified 3.31.1** source (`SOCFWConfigModes`, `SOCFWConfig`) · Tenant run: **pending** · Internal mapping: Notion, Capability Reference row *Deployment modes*
