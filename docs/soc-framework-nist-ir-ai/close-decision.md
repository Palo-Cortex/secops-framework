---
title: "AI Close Decision"
---

# AI Close Decision

After the issue assessment, the lifecycle decides whether that assessment may close the issue without a person looking at it. Four guards in code can never be loosened; a short policy list tunes the bar above them; and the close itself goes through the universal command, so nothing closes until `soc-close-issue` is live for the AI actor. A decision row is written either way, including for every issue held back and why.

## 1. What it does

`SOCFWCloseDecision` runs last in `EP_IR_NIST - AI`, after the assessment has been promoted to `Assessment.*`. It reads the issue, the assessment and `SOCFWClosurePolicy`, decides, writes an `ai_close_decision` row, and if the decision is yes, calls `soc-close-issue` through `SOCCommandWrapper` as actor `ai`.

The decision, in the order it is made:

| Check | Holds the issue when | Where it lives |
|---|---|---|
| Starred | the issue is starred: a person scoped it in, a person closes it | code |
| Assigned | an analyst owns it (tested on owner, not status, because automation moves status) | code |
| True positive | the verdict is `malicious`, at any confidence | code |
| Not recommended | the assessment set `closure_recommended = false` | code |
| Something landed | exposure is `delivered` or `executed`, not `already_contained`, and the verdict is not benign: a remediation is owed and that is decided at case scope | code |
| Category excluded | the policy's `category_overrides.<category>.skip` is set | `SOCFWClosurePolicy` |
| Blockers outstanding | `closure_blockers` is non-empty and `require_no_blockers` is true | `SOCFWClosurePolicy` |
| Confidence bar | `closure_confidence` is below `min_closure_confidence` | `SOCFWClosurePolicy` |

A truncated model reply is also held, because `closure_blockers` is the last field in the schema and the first thing truncation removes; an empty blocker list on a cut reply means the model never got there.

Closure is held to a higher bar than the verdict on purpose: escalating is recoverable, closing is a silent miss.

## 2. Where the switch lives

| Where | Key | Shipped default | Evaluation | Production |
|---|---|---|---|---|
| List `SOCFrameworkActions_V3` (via tenant override) | `soc-close-issue` for actor `ai`: `!SOCFWConfig command=shadow action=soc-close-issue actor=ai value=off apply=yes` | shadow | shadow. The shipped `pov` mode sets it live; that default has not been reviewed against production closes and is under review. Until it is, keep closes shadowed in an evaluation: `!SOCFWConfig command=shadow action=soc-close-issue actor=ai value=on apply=yes` after applying the mode | live only after the shadow numbers have been read and agreed with the customer |
| List `SOCFWClosurePolicy` | `min_closure_confidence` | `low` | as shipped | raise to `medium` or `high` if closes are too eager; the code falls back to `high` if the list is unreadable |
| List `SOCFWClosurePolicy` | `require_no_blockers` | `true` | as shipped | as shipped |
| List `SOCFWClosurePolicy` | `category_overrides.<category>.{skip, min_closure_confidence, require_no_blockers}` | `{}` | as shipped | per category where one source closes differently from the rest |

> The four code guards (starred, assigned, true positive, something landed) are not in the list and cannot be turned off. A deployment mode sets the actor flag; it never changes the policy list.

## 3. Turn it on

1. Run in shadow first: with `soc-close-issue` shadowed for `ai`, every issue still gets a decision row. Read them for at least a week (query below) and look at what `would_close = true` would have closed.
2. Tune the policy if the would-close set includes anything you would not close by hand: raise `min_closure_confidence`, or add a category override.
3. Take it live for the AI actor: `!SOCFWConfig command=shadow action=soc-close-issue actor=ai value=off apply=yes`.
4. Confirm with `!SOCFWConfig command=status action=soc-close-issue`.

To stop closes, reverse step 3 with `value=on`. The decision rows keep flowing either way.

## 4. Verify

```
config timeframe = 7d
| dataset = xsiam_socfw_ir_execution_raw
| filter event_type = "ai_close_decision"
| comp count() as rows by would_close, did_close, decision_reason
| sort desc rows
```

**Expected:** every issue that reached the decision has one row. `would_close` is what the model recommended; `did_close` is whether the policy allowed it; `decision_reason` says which guard held it. While `soc-close-issue` is shadowed, a `did_close = true` row still closes nothing; the matching `command` row shows `execution_mode = shadow`. Once live, the matching `command` row shows `production` and the issue is closed with the assessment's `closure_reason`. No production tenant has yet run with closes live; the first one should be watched daily for the first two weeks.

## 5. What it feeds

| Surface | What you see |
|---|---|
| Dashboard widget `Cases AI Would Auto-Close (Shadow)` | The would-close count against the total, before anything is live |
| Dataset rows `ai_close_decision` | `would_close`, `did_close`, `decision_reason`, `verdict`, `closure_confidence`, `closure_reason`, `blocker_count`, `truncated`, `alert_category` |
| Dataset rows `command` for `soc-close-issue` | Shadow or production, per close |
| Issue War Room | The close, or the reason it was held, beneath the verdict entry |

---

Verified against **soc-framework-nist-ir-ai 1.6.0** source (`SOCFWCloseDecision`, `SOCFWClosurePolicy`) · Tenant run: **pending** · Internal mapping: Notion, Reference — Auto-close: measuring the shadow, enabling, and tuning
