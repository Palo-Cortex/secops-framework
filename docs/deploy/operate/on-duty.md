---
title: "Set who is on duty for assignment"
---

# Set who is on duty for assignment

Analyst assignment hands unassigned open cases (starred ones, with the shipped setting) to whoever the `socfw_on_duty` roster says is on duty, least-loaded first. The roster is filled from a schedule source when one is configured, from roles or groups as a fallback, or by hand.

## Steps

1. By hand, for a tenant with no schedule system:

    ```
    !SOCFWOnDutySync analysts=<email>,<email>
    ```

   These people replace the manual rows; no other source is called.

2. From the configured sources (PagerDuty, or the roles and groups set in `SOCOptimizationConfig_V3`): run it with no arguments, or let the **SOCFW Analyst Assignment** job do it on its schedule.

**Expected:** the command reports the rows written per source. `!SOCFWHealthCheck` shows the roster as `WARN` with "no roster yet" until the first run, and the next assignment run assigns cases to the people listed.

## Why it works this way

A source that errors, is not configured or returns nobody changes nothing, so an outage in the schedule system never empties the roster. The manual list is for tenants without one, and for evaluations.

Related: [Keep a case for a person](keep-a-case.md) · [Turn a job on or off, and set its owner](jobs-and-owners.md)
