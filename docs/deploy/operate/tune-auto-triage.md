---
title: "Change Auto Triage's threshold and window"
---

# Change Auto Triage's threshold and window

Auto Triage closes an unstarred `New` case with no manual score whose score is at or below the threshold and which is older than the window. Both numbers are tenant settings.

## Steps

1. Read the settings in force:

    ```
    !SOCFWConfig command=triage
    ```

2. Change one or both:

    ```
    !SOCFWConfig command=triage score_threshold=30 window_hours=12 apply=yes
    ```

3. Return either to the shipped value with `default`, or ignore the score entirely with `score_threshold=off` (every unstarred `New` case older than the window then closes).

**Expected:** the command shows the old and new values, and the next run's `skipped` list reflects them.

## Why it works this way

The threshold is applied in the job, not in the search, because the platform does not filter on the score server-side. A week of score distribution on the tenant is the right basis for the number; the shipped value is a starting point, not a recommendation.

Related: [Let Auto Triage close a case](let-auto-triage-close.md)
