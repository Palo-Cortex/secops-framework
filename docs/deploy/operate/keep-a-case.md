---
title: "Keep a case for a person"
---

# Keep a case for a person

Star a case and automation leaves it alone: Auto Triage will not close it, the AI close decision will not close its issues, and if analyst assignment is on it is assigned to whoever is on duty.

## Steps

1. Open the case and star it. If the issue layout offers it, the same star is set when an assessment elevates the case.
2. To hand it to a specific person instead of the roster, assign it. An assigned issue is also never closed by the AI close decision.

**Expected:** on the next **SOCFW Analyst Assignment** run the case shows an owner from the on-duty roster (the job assigns unassigned open cases least-loaded first; with the shipped setting `AssignmentCases: starred` in `SOCOptimizationConfig_V3`, starred ones). Auto Triage runs report the case under `skipped` with the reason `starred guard`.

## Why it works this way

Starring and assigning are the two signals a person has decided. Both guards are in code, not in a list, so no tenant setting can make automation close a case a person has claimed. Severity is raise-only for the same reason: the framework never lowers a case or removes a star.

Related: [Let Auto Triage close a case](let-auto-triage-close.md) · [Set who is on duty for assignment](on-duty.md)
