---
title: "Act from the issue layout"
---

# Act from the issue layout

An issue that ran the AI entry point gets the SOC Framework layout: the assessment on the first tab, and buttons that act as you, the `analyst` actor.

## Contain

1. Open the issue and choose **Contain**. The War Room shows the actions this issue can actually run, computed at that moment from the action registry and the integrations enabled on this tenant.
2. Choose one. It runs through the universal command as the `analyst` actor: in shadow it prints what it would do and writes its row; live, it calls the vendor.
3. **Undo Containment** reverses an action that has a reverse.

**Expected:** a War Room entry per action with the vendor it used and whether it was simulated, and one `command` row in the execution dataset with `action_actor = analyst`.

To make a button act for real, take that action live for the `analyst` actor; see [Take an action live, or put it back in shadow](shadow-on-off.md). The shipped setting is shadow for every containment action and live for `soc-star-case`.

## Feedback

**Correct**, **Wrong** and **Missing context** record your judgement of the assessment as it stood, with an optional note, to the execution dataset. They change nothing on the issue; they are how the assessment is measured against people.

## Print War Room

**Print War Room** attaches a self-contained HTML copy of the issue's War Room to the issue, entries reproduced as written. Open it and print to PDF. It reads only, so no shadow setting applies.

Related: [See what runs for real on this tenant](see-what-runs-live.md) · [Issue Assessment](../../soc-framework-nist-ir-ai/issue-assessment.md)
