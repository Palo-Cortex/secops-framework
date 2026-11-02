---
title: "Let Auto Triage close a case"
---

# Let Auto Triage close a case

A starred case is never closed by Auto Triage; unstar it and the next run closes it, provided the case is still `New`, nobody has set a manual score on it, its score is at or below the threshold, and it is older than the window.

## Steps

1. Open the case and remove the star.
2. Leave its status at `New` and do not set a manual score; either one marks it as a person's.
3. Wait for the next scheduled run of **Auto Triage V3**.

**Expected:** the case closes as `Resolved - Other` with the comment "SOC Framework Auto Triage: case exceeded age threshold, aggregated_score below threshold, no analyst activity detected. Auto-closed by JOB." If it is still open after the run, check it against the four conditions:

```
!SOCFWConfig command=triage
```

shows the threshold and the window in force. A case above the threshold, younger than the window, not `New`, or carrying a manual score is skipped and stays as it is.

## Why it works this way

The star is the backstop. The framework never removes one, and the close path checks the star itself rather than trusting the search filter, so a starred case cannot reach the close call. Unstarring is therefore the one deliberate act that hands a case back to automation.

Related: [Keep a case for a person](keep-a-case.md) · [Change Auto Triage's threshold and window](tune-auto-triage.md)
