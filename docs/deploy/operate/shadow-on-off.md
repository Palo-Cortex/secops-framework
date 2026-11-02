---
title: "Take an action live, or put it back in shadow"
---

# Take an action live, or put it back in shadow

One action, one or more actors, one command. In shadow the action prints what it would do and writes its row; live, it calls the vendor. `default` returns the shipped setting.

## Before you start

- Know which actor you are changing. `analyst` is a person clicking a button; `automation` is the lifecycle acting on its own; `ai` is the close decision; `issue_emergency` is emergency response.
- Run the command without `apply=yes` first and read the plan.

## Steps

1. Take `soc-isolate-endpoint` live for people, leave it shadowed for automation:

    ```
    !SOCFWConfig command=shadow action=soc-isolate-endpoint actor=analyst value=off apply=yes
    ```

2. Put it back in shadow for the same actor:

    ```
    !SOCFWConfig command=shadow action=soc-isolate-endpoint actor=analyst value=on apply=yes
    ```

3. Return to what the pack shipped:

    ```
    !SOCFWConfig command=shadow action=soc-isolate-endpoint actor=analyst value=default apply=yes
    ```

**Expected:** the command reports the change and `!SOCFWConfig command=status action=soc-isolate-endpoint` shows the actor as `live` or `shadow`. The next time the action runs for that actor, its execution row carries the matching `execution_mode`:

```
config timeframe = 24h
| dataset = xsiam_socfw_ir_execution_raw
| filter event_type = "command" and universal_command = "soc-isolate-endpoint"
| fields _time, action_actor, execution_mode, action_status, entity_value
| sort desc _time
```

## Why it works this way

`value=on` means simulate and `value=off` means run for real: the switch is the shadow, not the action. The override lives in the tenant configuration list, so it survives a pack upgrade; the shipped flag in the action registry is what `default` goes back to.

Related: [See what runs for real on this tenant](see-what-runs-live.md) · [Shadow Mode](../../soc-optimization-unified/shadow-mode.md)
