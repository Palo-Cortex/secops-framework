---
title: "The Evaluation, End to End"
---

# The Evaluation, End to End

An evaluation of XSIAM running the NIST IR AI lifecycle on the SOC Framework runs the same way every time: prepare, install, connect the data sources (endpoint, email and identity first), prove the outcomes on the customer's own tenant, hand over. The lifecycle is what does the work on each issue and case; the framework is what it runs on: the normalized contract, the universal command, Shadow Mode, the lists, the dataset. Five stages, each with the pages that do it and the evidence it leaves behind. Install is a morning's work; the rest is the window. Nothing on the estate changes during any of it.

## Where the framework fits

The framework, with the NIST IR AI lifecycle on it, is running today at two ends of the scale, and the objection to the framework is different at each.

**At scale**, in a global shipping operation where the AI lifecycle assesses production issue volumes, the question is whether a framework can be customised enough. The numbers there: around 6,800 security issues a day (about 204,000 over 30 days, with a peak hour above 1,500) across network, email and endpoint sources, with network sources alone making up 62% of the volume. The automation rule brings that to roughly 300 issues a day entering the lifecycle, a four-to-one cut made entirely at the trigger with no per-source allowlist to maintain; the issue assessment runs in about 25 seconds per issue, with Foundation's normalization and enrichment taking most of the 95-second end-to-end time; and a hundred consecutive assessments produced zero parse errors and nothing recommended for closure on an active intrusion. The answer is that customisation lives in lists, not playbooks: which vendor answers which action, what minutes each action is worth, which policies gate containment, which assets are protected. Hundreds of per-vendor, per-site decisions sit in a handful of lists the customer owns, and the playbooks never change.

**In small SOCs** that need almost no customisation, the question is whether a framework is more than they need. It is not, for four reasons that get stronger as the SOC gets smaller.

- *The cost is the same install, with fewer sources.* Nothing is added for a small SOC and nothing has to be removed: install, apply a deployment mode, connect the sources, read the dashboards. The lists are never opened. In one SOC being built from scratch, with a handful of sources, the framework and the lifecycle were installed in a single working session, and the first configuration decision the customer faced was whether to let Auto Triage close cases.
- *A small SOC has the least capacity to build and maintain its own automation.* The alternative to the framework is not "nothing"; it is a playbook per tool, written once and never maintained. The framework replaces that with content that is maintained upstream and upgraded in place.
- *Small SOCs change tools more often than large ones, and feel it more.* Because actions resolve to vendors through a list, swapping an email or endpoint product is a list edit; the lifecycle, the dashboards and the measures carry across. A SOC of three people cannot afford to rebuild on every renewal.
- *The measures matter most where the headcount argument is hardest.* A small SOC rarely has the data to show what its automation does or what its analysts' time is worth. The execution dataset and the value dashboards give it that from day one, in its own numbers, and Shadow Mode lets it adopt automation one action at a time without a change process it does not have.

The framework earns its place at the small end by making whatever the lifecycle does visible, measurable and portable from day one, rather than by being tuned.

Both are evaluated the same way, below. The difference is how much of stage 4 is tuning and how much is reading.

## What an evaluation proves

Each proof below answers one of the problems a SOC describes in its own words. Before day one, sort the customer's requirements under these problems; the success criteria are chosen from the proofs that answer them.

| The problem the customer describes | What the evaluation proves on their tenant | Lifecycle component | Framework evidence |
|---|---|---|---|
| Too many manual investigations | Every selected issue gets a verdict with evidence, in seconds, where the analyst reads first; and the exact set that could have closed unseen, with the reason the rest could not | Issue assessment; close decision | `ai_reasoning` and `ai_close_decision` rows; the would-close widget |
| Analyst fatigue | Low-signal cases close on a schedule without a person; what remains is what needs one | Auto Triage (framework job), elevate rules | Cases auto-triaged; `elevate_decision` rows; starred cases |
| Poor prioritization | Which cases a person should look at now, starred by the lifecycle on evidence rather than by severity alone | Elevate rules | `elevate_decision` rows; starred cases |
| Slow time to resolution | What containment would have run, on which vendor, how fast, with how much analyst time returned, without running it | Emergency response and the containment buttons, calling framework actions | Shadow Mode `command` rows; time to contain; the shadow dashboard |
| Disconnected data sources | Email, endpoint and identity issues arrive in one shape, enriched the same way, and one case verdict spans them | Case analysis job | `case_analysis` rows; the case verdict; the Identity & Device section filled per source |
| Repetitive workflows | Enrichment, normalization and the response path run the same way on every issue from every source, with no per-vendor playbook | The lifecycle itself | One row per action with vendor, actor and minutes |
| Lack of visibility and detection delays | Time to detect and time to investigate, per source, with their definitions printed beside them | The lifecycle's dashboards | Widgets reading the execution dataset |

Not yet provable on a tenant: time to eradicate and time to recover. Those phases run in directions-only mode in the NIST IR AI lifecycle, so they record plans, not timed actions. They belong in the plan for after go-live, never in evaluation success criteria.

## The five stages

## 1. Prepare (before day one)

Agreed with the customer, in writing, before anything is installed:

- **The data sources, in priority order**: endpoint, email and identity first, because they are where the lifecycle has the most to prove; then whatever else the customer's problems need. An evaluation never onboards the whole estate.
- **Minutes per action**: the customer's own estimate of analyst time for each action in `SOCActionTimeMap_V3`. Every hours-returned number on the dashboards is derived from these, which is what makes it the customer's number.
- **The problems, in their words**: the customer's requirements sorted under the problems in the table above.
- **Success criteria**: three to six proofs from the table above, each tied to one of their problems, with the customer's current baseline, a target, and the widget that will show it. Anything the tenant cannot display by the readout goes in the after-go-live plan instead.
- **The scenario**: replay or live emulation, which attack, and (for a replay) that it stamps current time so the automation rule admits it.
- **Who owns the framework jobs** on the tenant (an email), and who will star and give feedback on verdicts during the window.

## 2. Install (about 30 minutes)

1. [Install the SOC Framework](install.md): Package Manager, the pack, two collectors, two writers, `mode=pov`, health check. The framework alone does nothing on an issue.
2. [Install NIST IR AI](install-nist-ir-ai.md): the lifecycle. The pack, two prompts, two hand-uploaded playbooks (including the entry point, which is lifecycle content that calls the framework), bindings, the automation rule sized on the tenant, the case job.
3. *Hand-made tenant settings*: confirm the automation rule and layout rule by hand, since the framework cannot check them.

Evidence: `!SOCFWHealthCheck` with no `FAIL`; one issue run through the entry point with a verdict.

## 3. Connect (about an hour per source, then wait for live issues)

For each source, endpoint, email and identity first: install its pack, switch to its framework correlation rules, confirm its category in `SOCProductCategoryMap_V3`, and watch one live issue arrive with `SOCFramework.Artifacts.*` populated.

Evidence: each connected source producing `ai_reasoning` rows; the Identity & Device section of the layout filling for each.

## 4. Prove (the evaluation window, typically two to three weeks)

- Run the scenario and walk the customer through one case: the issue verdicts, the case verdict, the shadowed containment in the War Room with the vendor it would have used. Two ways to run it:
  - **Replay** (the default): send a recorded attack's events through HTTP collectors into the tenant. No endpoints, no agents, repeatable in minutes; the replay must stamp current time. The collectors are created by hand for the evaluation and removed at the end: a collector left behind is an open door into the same datasets the customer's SOC reads.
  - **Live emulation** (needs the adversary-emulation tooling and endpoints with the XDR agent installed): run the MITRE emulation plan so detections come from the platform's own engines. Rehearse it on lab endpoints first, and only then on the estate.
- Let live issues flow for the window. Analysts star what they would work and use the feedback buttons on verdicts.
- Read the dashboards weekly against the success criteria. The shadow dashboard is the evaluation's story: what would have been contained, how fast, with how many analyst minutes returned.
- Tune only what the customer asks for, through `!SOCFWConfig`, so every change is recorded and reversible.

Evidence: the success-criteria table filled in from the tenant's own widgets, with each widget's definition beside its number.

## 5. Hand over (the readout and after)

- The readout: the customer's outcomes in their words, the capabilities that produced them, the metrics from their dashboards, how the lifecycle did it and how the framework made it visible, and the one sentence that matters: everything in containment was visible, nothing executed, going live is one setting per action.
- The handover table from *From evaluation to production*: every switch, its evaluation value, its production value, the command, the check.
- The after-go-live plan: the metrics an evaluation could not prove, who measures them, and when.
- Teardown: delete the replay's HTTP collectors and uninstall the test pack before the tenant carries production data, so nothing outside the SOC can write into its datasets.

Evidence: the handover table, the agreed production mode sequence (`star_and_triage` → `contain_identity_and_hosts` → `contain_all`), and the saved success-criteria table as the go-live baseline.

## Rules that keep it honest

- Every number shown comes from this customer's tenant during the window; reference baselines from other environments are sanity ranges, never promises.
- Every time-to-X number is shown with its definition, start and end event named.
- A capability is described as it ships, never as it is planned.
- Customer names and numbers never leave that customer's own notes.

---

Verified against the drafted install and reference pages and the current lifecycle scope · Tenant run: **pending** · Internal mapping: Notion, Evaluate track (value-driver mapping, success-criteria library, role mapping)
