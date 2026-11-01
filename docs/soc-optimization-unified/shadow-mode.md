---
title: "Shadow Mode"
---

# Shadow Mode

Any action that would change something (isolate, revoke, block, retract, close, star, assign) prints what it would do and writes the execution row, but does not call the vendor until the action is switched on. Whatever lifecycle calls the action, nothing on the estate changes.

## 1. What it does

Every framework action runs through the universal command (`SOCCommandWrapper`). Before calling the vendor, the wrapper reads the action's shadow flag. If the flag is on, it writes the same execution row it would write for a real run, with `execution_mode = shadow`, posts the intended action to the War Room, and stops. If the flag is off, it calls the vendor and writes `execution_mode = production`.

The flag can be set per action, or per action *and* actor, so an analyst can run an action live from a layout button while unattended automation and AI stay shadowed. If the flag cannot be read, a changing action is simulated.

## 2. Where the switch lives

| Where | Key | Shipped default | Evaluation | Production |
|---|---|---|---|---|
| List `SOCFrameworkActions_V3` | `<action>.shadow_mode` | `true` for every changing action (isolate, de-isolate, revoke, block, retract, close, star, assign, ticket, comms); `false` for enrichment and investigation actions | leave as shipped | per action, once approved |
| List `SOCFrameworkActions_V3` | `<action>.shadow_mode_by_actor.{analyst, ai, automation, issue_emergency}` | `true` for all actors on `soc-isolate-endpoint`, `soc-deisolate-endpoint`, `soc-assign-case`, `soc-close-issue-contained`, `soc-raise-case-severity`; `soc-star-case` is `false` for analyst only | leave as shipped | flip one actor at a time |
| Tenant override (`SOCFWTenantConfig`) | `shadow.<action>.<actor>`, written by `!SOCFWConfig` | unset | unset | set here, not in the list, so the value survives pack upgrades |

> The wrapper's own `shadow_mode` argument is ignored; the list and the tenant override are authoritative. A named deployment mode (`!SOCFWConfig command=mode`) sets a bundle of these flags in one step.

## 3. Turn an action on

1. Confirm the current state: `!SOCFWConfig command=status`. The table lists every action with its shadow value per actor.
2. Dry-run the change: `!SOCFWConfig command=shadow action=soc-isolate-endpoint actor=analyst value=off`. Nothing is written until `apply=yes` is added.
3. Apply it: `!SOCFWConfig command=shadow action=soc-isolate-endpoint actor=analyst value=off apply=yes`.
4. Re-run `command=status` and confirm the analyst column for that action now reads `off`.

To revert, repeat with `value=default`, which removes the tenant override and returns to the shipped list value.

## 4. Verify

Trigger the action (for example, the Contain button on an issue the analyst owns), then query the execution dataset:

```
config timeframe = 1h
| dataset = xsiam_socfw_ir_execution_raw
| filter event_type = "command"
| fields _time, execution_mode, action_target, shadow_mode_state
| sort desc _time
```

**Expected:** the newest row shows `execution_mode = production` for the action you switched on. Rows from automation or AI for the same action still show `shadow`.

The `!SOCFWConfig command=status` table is the quickest second check and needs no query.

## 5. What it feeds

| Surface | What you see |
|---|---|
| Dataset `xsiam_socfw_ir_execution_raw` | `execution_mode` on every `command` row, so any metric can be split shadow vs production |
| War Room | One entry per shadowed action stating what it would have done and against which target |
| Lifecycle dashboards (for NIST IR AI: `NIST IR - Value Metrics Shadow Mode (AI)` and `NIST IR - Value Metrics (AI)`) | Each lifecycle's dashboards read `execution_mode` from the same dataset to show would-have-done against did |

## Why it is per actor

One flag per action was the original design. In practice an analyst needs to act now from the layout while the same action, fired by a lifecycle's automation on every alert, must stay simulated until the customer has approved it. Splitting the flag by actor lets both be true at once and lets production cutover happen one actor at a time.

---

Verified against **soc-optimization-unified 3.31.1** source · Tenant run: **pending** · Internal mapping: Notion, Capability Reference row *Shadow Mode*
