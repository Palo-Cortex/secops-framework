---
title: "Operate the framework"
---

# Operate the framework

What a person does on a running tenant, one task per page. The framework runs the rest on its own: every alert goes through the Foundation chain, the jobs run on their schedules, every action writes its row. Two commands cover almost everything here, both from the Playground: `!SOCFWConfig` changes a setting and survives pack upgrades; `!SOCFWHealthCheck` reads the tenant back.

Every `!SOCFWConfig` change is a dry run until you add `apply=yes`, so run it once without to see what would change.

## Cases

- [Where every case is handled](where-every-case-is-handled.md): person, AI or Auto Triage, by state and age, and the one state nobody handles until a setting changes.
- [Let Auto Triage close a case](let-auto-triage-close.md): unstar it.
- [Keep a case for a person](keep-a-case.md): star it, or assign it.
- [Act from the issue layout](issue-layout.md): the Contain button, the feedback buttons, Print War Room.

## Switches

- [See what runs for real on this tenant](see-what-runs-live.md)
- [Take an action live, or put it back in shadow](shadow-on-off.md)
- [Turn an emergency response policy on or off](emergency-policy.md)

## Jobs and tuning

- [Turn a job on or off, and set its owner](jobs-and-owners.md)
- [Change Auto Triage's threshold and window](tune-auto-triage.md)
- [Set who is on duty for assignment](on-duty.md)

## Checking

- [Run the health check](health-check.md)
