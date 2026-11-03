---
title: "Set who is on duty for assignment"
---

# Set who is on duty for assignment

Analyst assignment hands unassigned open cases (starred ones, with the shipped setting) to whoever the `socfw_on_duty` roster says is on duty, least-loaded first. The roster is filled from a schedule source when one is configured, from the tenant's own roles or user groups as a fallback, or by hand.

## Steps

1. By hand, for a tenant with no schedule system:

    ```
    !SOCFWOnDutySync analysts=<email>,<email>
    ```

   These people replace the manual rows; no other source is called.

2. From the tenant's users, for a tenant with no schedule system: name the analyst group (or roles), then let the job sync on its schedule or run the sync by hand:

    ```
    !SOCFWConfig command=assignment groups="SOC Analysts" roles=none apply=yes
    !SOCFWOnDutySync
    ```

   A comma list sets several groups or roles; set the list again without a name to drop it; `none` turns that fallback off; `default` returns to the shipped value (the two admin roles for `roles`, nothing for `groups`). The shipped roles are the admin roles because every tenant has them; most customers replace them with their analyst group before turning the job on.

3. From a schedule source (PagerDuty): set its schedule ids with `!SOCFWConfig command=set vendor="PagerDuty v2" arg=schedule_ids value=<ids> apply=yes`. Once a schedule source answers, it owns the roster and the role and group rows are removed.

**Expected:** the command reports the rows written per source. `!SOCFWHealthCheck` shows the roster as `WARN` with "no roster yet" until the first run, and the next assignment run assigns cases to the people listed.

## Why it works this way

A schedule source that errors, is not configured or returns nobody changes nothing, so an outage in the schedule system never empties the roster. The role and group fallback is different: a setting that matches no tenant user removes the fallback rows and the health check says nobody is on duty, so a renamed group is visible rather than hidden behind the previous roster. The manual list is for tenants without a schedule system, and for evaluations.

Related: [Analyst Assignment](../../soc-optimization-unified/analyst-assignment.md)

Related: [Keep a case for a person](keep-a-case.md) · [Turn a job on or off, and set its owner](jobs-and-owners.md)
