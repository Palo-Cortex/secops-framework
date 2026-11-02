---
title: "Turn an emergency response policy on or off"
---

# Turn an emergency response policy on or off

Emergency response acts on a single issue, without waiting for the case, when a policy matches: what the issue is about, which source or rule it came from, and the assessment's verdict and confidence. The shipped policies are `identity_compromise`, `endpoint_execution` and `email_delivered`; each is on or off per tenant, and every action they run is still gated by shadow for the `issue_emergency` actor.

## Steps

1. List the policies and their state:

    ```
    !SOCFWConfig command=emergency
    ```

2. Turn one off, or back on:

    ```
    !SOCFWConfig command=emergency policy=email_delivered enabled=off apply=yes
    ```

3. Protect what must never be contained, for every policy:

    ```
    !SOCFWConfig command=emergency protect=host:dc-*,cidr:10.0.0.0/8 apply=yes
    ```

**Expected:** the listing shows the policy's `enabled` state and the protect list. A policy that matched but was blocked by protection escalates the case to the configured severity instead of acting.

## Why it works this way

Policies decide *whether* to act; shadow decides *whether the vendor is called*. Turning a policy off stops the decision; leaving it on with `issue_emergency` in shadow shows every decision in the War Room and the dataset without touching the estate.

Related: [Take an action live, or put it back in shadow](shadow-on-off.md) · [See what runs for real on this tenant](see-what-runs-live.md)
