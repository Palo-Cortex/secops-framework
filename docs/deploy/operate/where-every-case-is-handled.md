---
title: "Where every case is handled"
---

# Where every case is handled

Every issue and every case on a tenant is handled by one of three things: a person, the AI, or Auto Triage. Which one is decided by the star, the case's age and score, and a handful of settings. This page is the map, with the shipped values, and it names the one state that nobody handles until a setting is changed.

## By state

| State | Handled by | What happens | Decided by |
|---|---|---|---|
| Every issue, the moment it is created | **AI** | Issue assessment runs at trigger. Emergency response acts at once if a policy matches. A malicious verdict at high confidence that recommends escalation stars the case. The close decision may close the issue when the assessment recommends closure, its confidence meets the policy, it lists no blockers, and the issue is neither starred nor assigned. | `SOCFrameworkPhasePolicy_V3` (elevate, emergency), `SOCFWClosurePolicy` (`min_closure_confidence`, `require_no_blockers`), the `ai` actor's shadow flag on `soc-close-issue` (shipped `pov` mode takes it live; under review) |
| Case **starred**, by a person or by the assessment | **A person** | Analyst assignment gives it an owner from the on-duty roster, least-loaded first, within the assignment window. Neither Auto Triage nor the AI close decision will close it. | `cases: starred`, `window: 24 hours`, `max_per_analyst: 20` (`!SOCFWConfig command=assignment`); `soc-assign-case` for `automation` (live in `pov` mode) |
| Case **assigned** or with a **manual score** | **A person** | Same as starred: a person has claimed it. | Guards in `SOCAutoTriageScoreFilter` and `SOCFWCloseDecision`; not configurable |
| **Unstarred** case with **two or more issues** of **two or more shapes** (or twenty or more issues of one shape), `New` or `Under investigation`, changed in the last 6 hours, quiet for 5 minutes | **AI** | Case analysis produces one verdict per case, again only if the case changes, up to twice. Starred cases are left to analysts. Case containment builds the action plan from it; both record in shadow until their actors are taken live. | `CaseMinIssues: 2`, `CaseMinShapes: 2`, `CaseCampaignIssues: 20`, `CaseWindowHours: 6`, `CaseSettleMinutes: 5`, `CaseMaxAnalyses: 2`, `CaseCases: unstarred` — set with `!SOCFWConfig command=case` |
| Case **unstarred**, `New`, no manual score, score at or below the threshold, older than the window | **Auto Triage** | Closed as `Resolved - Other` with the Auto Triage comment, on the next run. | `TriageScoreThreshold: 40`, `TriageWindowHours: 6` (`!SOCFWConfig command=triage`) |
| Case **unstarred**, `New`, score **above** the threshold, older than the window, issues not closed by the AI | **Nobody** | It stays open with no owner. Nothing stars it, nothing assigns it, nothing closes it. | See below |

Two more states worth knowing: a single-issue case gets the issue assessment only, never case analysis, by design (`CaseMinIssues`); and a case anyone has moved to `Under investigation` is out of Auto Triage for good (it only looks at `New`), so touching a case is claiming it.

## The gap, and the two settings that close it

With shipped values a case that scores above 40, is never starred, and is not closed by the AI has no handler after six hours. Either of these closes the gap; pick by how the SOC wants to work:

- **Assign every open case, not only starred ones:** `!SOCFWConfig command=assignment cases=all apply=yes`. The roster then owns everything open in the window, with the per-analyst cap still applied. Widen the window (`window="7 days"`) if cases can wait longer than a day before anyone sees them.
- **Let Auto Triage close more:** raise `TriageScoreThreshold` (`!SOCFWConfig command=triage score_threshold=<n> apply=yes`), after a week of reading the score distribution on this tenant. `score_threshold=off` closes every unstarred `New` case older than the window regardless of score, which is only right where starring is the SOC's working habit.

Whichever you choose, the elevate rule is the backstop in the other direction: a high-confidence malicious assessment stars the case, so the cases most worth a person already reach one.

## A case, hour by hour, with shipped values

| When | What |
|---|---|
| T+0 | First issue: assessed, emergency response decided, starred if the assessment says so, closed if the close decision says so. |
| T+5 min after the last issue joined | Case analysis, if the case has two shapes (or is a twenty-issue campaign). |
| T+6 h | Auto Triage will close it on its next run if it is unstarred, `New`, unscored by a person, and at or below the threshold. |
| T+24 h | Out of the assignment window: an unassigned starred case older than this is no longer picked up. |
| T+72 h | Out of the case analysis window. |

## Check it on the tenant

```
config timeframe = 7d
| dataset = xsiam_socfw_ir_execution_raw
| filter event_type in ("ai_close_decision", "elevate_decision", "analyst_assignment", "auto_triage")
| comp count() as decisions by event_type, action_status
```

**Expected:** rows for all four event types. Auto Triage rows that stop appearing while `New` unstarred cases pile up mean the job is off or has no owner; assignment rows with everyone at the cap mean the roster is too small for the volume.

Related: [Let Auto Triage close a case](let-auto-triage-close.md) · [Keep a case for a person](keep-a-case.md) · [Set who is on duty for assignment](on-duty.md) · [Tune Auto Triage](tune-auto-triage.md)
