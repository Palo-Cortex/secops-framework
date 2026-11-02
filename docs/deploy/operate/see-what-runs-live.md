---
title: "See what runs for real on this tenant"
---

# See what runs for real on this tenant

One command lists every action, per actor, as `live` or `shadow`, names the list field that decided it, and shows which customer values are set and which jobs are on.

## Steps

1. From the Playground:

    ```
    !SOCFWConfig command=status
    ```

2. To see one or a few actions only:

    ```
    !SOCFWConfig command=status action=soc-isolate-endpoint,soc-star-case
    ```

**Expected:** a table with one row per action and actor (`analyst`, `ai`, `automation`, `issue_emergency`), the state, and whether a tenant override or the shipped value decided it; then the customer values with `set` or `required`; then each job with on or off and its owner; then the mode the tenant matches (`custom` when it matches none).

## Why it works this way

Shadow is decided per action and per actor, so "is isolation on?" has four answers. The table is the only place all four are read from the same source the wrapper reads at run time.

Related: [Take an action live, or put it back in shadow](shadow-on-off.md) · [Deployment Modes](../../soc-optimization-unified/deployment-modes.md)
