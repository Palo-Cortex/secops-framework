---
title: "Turn a job on or off, and set its owner"
---

# Turn a job on or off, and set its owner

The framework's jobs are **Auto Triage V3**, **SOC Case Analysis** and **SOCFW Analyst Assignment**. A job cannot run without an owner who is a user on this tenant.

## Steps

1. Set the owner, with the email of a user on this tenant:

    ```
    !SOCFWConfig command=owner job="Auto Triage V3" owner=<email> apply=yes
    ```

2. Turn the job on (it then runs on its schedule) or off:

    ```
    !SOCFWConfig command=job job="Auto Triage V3" value=on apply=yes
    ```

**Expected:** `!SOCFWConfig command=status` lists the job as on with that owner. `!SOCFWHealthCheck` grades a job that is on with an owner who is not a user as `FAIL`.

## Why it works this way

Ownership is a platform rule: a job with no owner silently does nothing. Setting it through the command records the change as a `config_change` row, so a job that stopped can be traced to who turned it off and when.

Related: [Run the health check](health-check.md) · [Deployment Modes](../../soc-optimization-unified/deployment-modes.md) (sets all three at once)
