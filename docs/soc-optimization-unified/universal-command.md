---
title: "Universal Command"
---

# Universal Command

One command runs every framework action. You name the action (`soc-isolate-endpoint`, `soc-revoke-tokens`, `soc-block-domain`); the command works out which vendor integration on this tenant does that, applies Shadow Mode, runs or simulates it, and writes one row to the execution dataset. Playbooks and layouts never call a vendor command directly.

## 1. What it does

The command is the script `SOCCommandWrapper`. For each call it:

1. Reads the action's row in the action registry list `SOCFrameworkActions_V3`: which vendors implement it (`responses`), what arguments each needs, and the action's shadow flags.
2. Picks the vendor. The action's class (endpoint, identity, email, indicator) comes from `SOCActionClassMap_V3`; the alert's product map row (`SOCProductCategoryMap_V3`) says which vendor answers that class for this data source. A platform action with only a `Builtin` response needs no vendor. An action marked `dispatch = all_applicable` runs on every vendor that implements it.
3. Resolves Shadow Mode for the action and the actor making the call.
4. Runs the vendor command, or simulates it, and posts the result to the War Room.
5. Writes one `command` row to `xsiam_socfw_ir_execution_raw` carrying the action, vendor, target, `execution_mode`, the analyst minutes from the time map, and the lifecycle that called it.

Because the vendor is resolved from lists, the same playbook or button works on a tenant with CrowdStrike for endpoints and Entra ID for identities as on one with Defender and Okta. Swapping a vendor is a list edit, never a playbook edit.

## 2. Where the switch lives

| Where | Key | Shipped default | Evaluation | Production |
|---|---|---|---|---|
| Script argument | `action` | `soc-isolate-endpoint` | the action you want | same |
| Script argument | `Action_Actor` (`analyst`, `ai`, `automation`, `issue_emergency`, `layout`) | `analyst` | set by the caller; a layout button is `analyst`, a job is `automation` | same |
| Script argument | `target` | empty (acts on the issue's artifact) | set only for actions that name a target, e.g. a domain for `soc-block-domain` | same |
| Script argument | `LifeCycle` | `NIST_IR`, else `SOCFramework.lifecycle` from context | the calling lifecycle's id | same |
| List `SOCFrameworkActions_V3` | `<action>.responses.<Vendor>.command` and its argument map | one row per action and vendor the framework knows | leave as shipped | add a row when a customer brings a vendor the pack lacks |
| List `SOCFrameworkActions_V3` | `<action>.dispatch` | absent (one vendor) except `all_applicable` on `soc-block-domain`, `soc-block-network-indicator`, `soc-sync-on-duty`, `soc-assign-case` | leave as shipped | leave as shipped |
| List `SOCProductCategoryMap_V3` | `ds_<source>.responses.<class>` | one row per data source the pack knows | confirm the row for each evaluation source | add rows for the customer's sources |

> The `shadow_mode` argument on the command is ignored. Shadow Mode is decided by the action registry and the tenant override; see [Shadow Mode](shadow-mode.md).

## 3. Call it

From a playbook task, a layout button or the Playground:

```
!SOCCommandWrapper action=soc-isolate-endpoint Action_Actor=analyst
```

For an action that takes a target:

```
!SOCCommandWrapper action=soc-block-domain target=bad.example.com Action_Actor=analyst
```

The result lands in context under `SOCFramework.ActionOutput` (`success`, `command_executed`, `exec_args`), so a playbook can branch on it.

## 4. Verify

```
config timeframe = 1h
| dataset = xsiam_socfw_ir_execution_raw
| filter event_type = "command"
| fields _time, action, vendor, action_target, execution_mode, lifecycle
| sort desc _time
```

**Expected:** one row per call, `vendor` naming the integration the command chose for this tenant, `execution_mode` matching the action's shadow flag for that actor. A call that could not resolve a vendor still writes a row and says so in the War Room; the health dashboard counts it under failed commands.

## 5. What it feeds

| Surface | What you see |
|---|---|
| Dataset `xsiam_socfw_ir_execution_raw` | Every action ever asked for, with who asked, which vendor answered, and whether it ran |
| Time map `SOCActionTimeMap_V3` | Analyst minutes credited to each row, which the value dashboards sum |
| Dashboard `SOCFW Framework Health - Command Errors` | Failed commands, failure reasons, minutes credited to failures |
| Lifecycle dashboards | Read the same rows to show would-have-done against did |

---

Verified against **soc-optimization-unified 3.31.1** source · Tenant run: **pending** · Internal mapping: Notion, Capability Reference row *Universal Command*
