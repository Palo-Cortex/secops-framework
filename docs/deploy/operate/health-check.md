---
title: "Run the health check"
---

# Run the health check

A read-only check of the tenant: the configuration as `!SOCFWConfig command=status` reports it, graded; each job on or off and whether its owner is a user; the required customer values; the named integration instances; and whether every list, rule, dashboard and pack the framework needs is present.

## Steps

1. From the Playground:

    ```
    !SOCFWHealthCheck
    ```

2. To keep a record over time, add `write_dataset=true`; each check writes a row to the `socfw_health_checks` lookup.

**Expected:** overall `OK` or `WARN`, never `FAIL`. A `WARN` on **Customer values** names a vendor value an enabled integration needs; set it with `!SOCFWConfig command=set`. A `FAIL` on a job means it is on with an owner who is not a user. The check inventories presence, not behaviour: it does not run anything, and it cannot see the automation rule or the layout rule, which are checked by hand.

Related: [Turn a job on or off, and set its owner](jobs-and-owners.md) · [A job ran but produced no verdict](../../support/no-verdict.md)
