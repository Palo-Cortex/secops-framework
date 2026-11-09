---
title: "The playbook queue is backing up"
---

# The playbook queue is backing up

Issues wait minutes to hours before `EP_IR_NIST - AI` starts on them, and the tenant's pending playbook count keeps rising. The cause is almost always more issues starting the playbook per hour than the tenant processes per hour; read the surfaces below in order before changing anything.

## Where to look, in order

**1. How many issues actually started the playbook, by hour.** Count only issues that carry a playbook run status. Issues created are not the same thing: the platform's automation floor and the rule's own conditions keep many of them out, so a count of all issues overstates the load.

```
dataset = issues
| filter timestamp_diff(current_time(), _insert_time, "HOUR") <= 24
| filter playbook_run_status != null
| bin _insert_time span = 1h
| comp count() as issues_with_playbook by _insert_time
| sort asc _insert_time
```

Times in XQL results are UTC. Hours above the tenant's throughput add to the queue; hours below drain it.

**2. Which issues are driving it.**

```
dataset = issues
| filter timestamp_diff(current_time(), _insert_time, "HOUR") <= 24
| filter playbook_run_status != null
| comp count() as issues by xdm.issue.name, xdm.issue.severity, playbook_run_status
| sort desc issues
| limit 25
```

A few names holding most of the count, all Low, points at the automation rule's detection-method branch.

**3. The automation rule.** Investigation & Response → Automation → **Automation Rules**. The framework cannot read or install this rule, so `!SOCFWHealthCheck` says nothing about it; compare its branches against [Install NIST IR AI, step 5](../evaluate/install-nist-ir-ai.md#5-create-the-automation-rule).

**4. What each run calls.** A run that waits on an integration instance that fails or times out holds its place in the queue longer. Enrichment through the universal command runs on every issue, so a failing identity or reputation integration slows every run that reaches it.

## Causes seen, and the fix

| What the queries show | Cause | Fix |
|---|---|---|
| A burst of Low identity analytics (new country, new operating system, suspicious country, repeated MFA requests) | A newly connected identity source fires new-baseline analytics for every user until profiles settle, and the detection-method branch admits each one | Remove the detection-method branch from the rule; keep the starred and Medium-and-above branches. Turn on the Case Analysis job so those issues are still judged in their case |
| Many issues created, few with a playbook run status | The issues are outside the platform's automation floor (for example Low issues from a correlation rule or a native ingest) | Not a queue cause. Tune the source if the issue volume itself is a problem |
| Starts per hour within throughput, queue still rising | Runs are slow, not many | Check the integration instances the enrichment step calls; disable staging or test instances that fail on every call |
| A surge of starts with almost no new issues that day | Playbooks re-ran on existing issues | Confirm every branch of the rule carries `observation time in last 24H`, which bounds a re-run to recent issues |

## Before you change the rule

- Changing the rule stops new starts; it does not clear runs already queued. Work out how long the backlog takes to drain at the new rate before deciding whether to clear it.
- Removing a branch moves those issues to case level, not out of view. Check that the starring policy stars any Low detection that still needs assessment one issue at a time.
