# Case-Scoped Analysis — `JOB - SOC Case Analysis`

**Pack:** `soc-framework-nist-ir` | **Platform:** Cortex XSIAM

---

## What this is

Detection & Analysis runs once per **case**, on a schedule, instead of once per issue.

`EP_IR_NIST (800-61) AI` ends at `Foundation - Upon Trigger`: the issue path normalizes, classifies, dedups and writes the SOC Framework contract, then exits. Nothing else runs per issue. The NIST phases run at case scope, out of band, from this JOB.

The two paths are independent by design. The JOB decides candidacy from case state alone and does not depend on the issue path marking anything, so a scheduled job and an automation trigger never have to agree about anything.

Both entry points install side by side. `EP_IR_NIST (800-61)_V3` keeps the inline lifecycle; swapping the automation trigger between them is the cutover, and swapping back is the rollback.

## Why case scope

A conclusion available from the whole case is often unavailable from any single issue in it. Four hundred issues each saying "delete this message" never add up to "block the sending domain".

Measured on a real correlated case: six issues across Email and Endpoint, two hosts, one identity, an eight-second window. One reasoner reading all six identified the emailed payload, the masquerading process spawned from it, the elevation from that user's context, and — because two shapes shared a `first_seen` to the second — inferred the lateral move was scripted rather than manual. No single issue supports that conclusion.

## Flow

```
  0  start
100  Read JOB config                 SOCOptimizationConfig_V3 → Case Analysis JOB
105  Aggregate — analysis watermark  xsiam_socfw_ir_execution_raw
110  Select candidate cases          SOCFWCaseSelect
115  Any candidates?                 no → Close Job
120  Aggregate — issue shapes        dataset = issues
130  Aggregate — entities            dataset = alerts
155  Aggregate — contract coverage   dataset = issues
160  Build case payloads             SOCFWBuildCasePayload
165  Attach shape contracts          SOCFWFetchShapeContracts
170  SOC Case Analysis Phase         separatecontext, loop.forEach over Payloads
177  Post Case Analysis to dataset   run-level row
180  Close Job
190  Done
```

`SOC Case Analysis Phase`, once per case:

```
  0  start
  5  Pin case for this iteration     SOCFWCaseIterationSetup
 10  AI Case Analysis                title placeholder in the pack copy
 20  Report case verdict             SOCFWCaseVerdictReport
 25  Post Case Verdict to dataset    case-level row
 30  Done
```

## The collapse

The reason case scope is affordable. Issues sharing name, source, severity, category and rule collapse to one **shape** carrying an occurrence count. Shape count is bounded by variety, not volume.

| Case | Issues | Shapes | Raw contracts | Collapsed payload |
| --- | --- | --- | --- | --- |
| 48131 | 76 | 6 | 643,188 B | 3,856 B |
| 48794 | 57 | 4 | 482,391 B | 2,923 B |

A campaign is more uniform than a mixed case, not less, so the payload does not grow with issue count. At the 1024-issue cap, raw contracts would be 8.26 MB; the collapsed payload stays in single-digit KB.

Three aggregates run **once across all candidate cases**, filtered by `incident_id in (...)`, and are partitioned per case in memory. Aggregate cost is therefore per run, not per case. A 3,000-id filter in a 21 KB query was measured at 15s, so the id list is not the constraint.

## Contracts

The aggregates describe what happened in XDM terms. The contract is the normalized surface everything downstream reads, and it carries what XDM does not — resolved identity including the SID, MITRE tactic ids rather than technique strings inside an alert name, enrichment provenance, and the vendor routing an action would dispatch on.

`SOCFWFetchShapeContracts` reads it with `getContext` — in-process, no XQL quota, ~0.9s per call — for one representative issue per shape.

**The representative is chosen by trying several issues from the shape, not the lowest id.** A shape groups issues by alert name, source, severity, category and rule, not by whether the entry point ran. `min(id)` frequently lands on a dedup-closed issue with no contract: a six-shape case resolved 16.7% coverage while five of six shapes had a contracted issue available. The shapes aggregate returns `candidate_ids` and the fetch tries up to five.

The whole `SOCFramework` subtree is taken, never named fields, which is what lets a schema change reach the prompt: add a row to the normalize map, re-emit, and the new artifact appears in the payload with no code change here.

### Intel

Reputation and threat intelligence travel with the contract under `Intel`. The contract records that an enrichment lane *fired*; Intel is what it *concluded*. Default roots are `DBotScore`, `File`, `IP`, `Domain`, `URL`, `WildFire`, `AttackPattern`, `Tactic`, configurable via `CaseIntelRoots` — a customer running Recorded Future or GTI adds its root rather than editing the script.

`Whois` (11,935 B) and `DBotFindSimilarIncidents` (7,527 B) are excluded. Together they are the bulk of a context and carry nothing the reasoner needs.

## Watermark

Derived from the execution dataset, not a List. **A pack-installed List is system-owned and a JOB cannot write to it** — `setList` returns *"Item is system and cannot be modified (100001)"* — so a List-based watermark silently never persists and every run re-analyses every case. That produced 118 duplicate verdict entries before it was caught.

Task 105 aggregates `event_type = "case_analysis"` rows by `case_id`. The dataset already records what was analysed, so it is the watermark.

Two independent re-analysis triggers:

- `alert_count` grew — new issues joined the case
- coverage was incomplete last run — issues that were still executing have since landed their contracts

The second is why the in-flight race needs no detection. `playbook_run_status` reads `null` both for an issue that never ran and one still running, and the two cannot be told apart at selection time.

Selection windows on **`modification_time`**, not `creation_time`. A case created twelve days ago and still receiving issues would otherwise drop out of scope while it is still active.

## Scope and health are different filters

**Domain is scope.** This JOB is the NIST IR lifecycle, so `DOMAIN_SECURITY` only. Posture cases have their own lifecycle and never run this entry point, so they carry no contract by design rather than by fault. On one tenant, 117 of 126 uncontracted cases were posture — filtering domain removes them at selection with no XQL spend.

Note the value is spelled `DOMAIN_SECURITY` on the case record and `SECURITY` on the issue. They are not interchangeable in a filter.

**Contract coverage is health.** Within the domain, a case with zero contracted issues means the entry point did not fire. That is a finding about trigger configuration, reported in `Case.Uncontracted`, not something to silently analyse from vendor fields.

## Failing closed

Three causes of a missing contract are separated:

| Cause | Kind | Handling |
| --- | --- | --- |
| Fetch error | transient | defer the whole case |
| Over `max_fetches_per_case` | transient | defer the whole case |
| Issue carries no contract | structural | counts against coverage, reported |

A case below `CaseMinContractCoveragePct` is not analysed. Deferred cases get no watermark, so selection returns them next run — reasoning over a case whose input silently shrank is worse than waiting.

## Configuration

`SOCOptimizationConfig_V3` → `Case Analysis JOB` → `fields`:

| Field | Default | Effect |
| --- | --- | --- |
| `CaseWindowHours` | 72 | Only consider cases modified within this window |
| `CaseBatchSize` | 100 | Cases per `get_incidents` page, capped at the 100-row ceiling |
| `CaseMaxBatches` | 20 | Pages per run. Cases per run is batch × batches |
| `CaseDomain` | DOMAIN_SECURITY | Lifecycle scope |
| `CaseMaxShapes` | 40 | Shapes carried per case, highest count first |
| `CaseMaxContractFetches` | 40 | `getContext` calls per case |
| `CaseMinContractCoveragePct` | 50 | Below this, the case is deferred rather than analysed |
| `CaseIntelRoots` | 8 roots | Context roots carrying reputation and threat intelligence |

Schedule frequency is the tuning knob, set in the Jobs UI. It is also the MTTC floor now that C/E/R is case-scoped, so it is a latency-versus-quota decision rather than a pure cost one. Ten minutes is a reasonable start; five for a demo; fifteen where XQL quota is tight.

**Set the interval well clear of run duration**, and leave `shouldTriggerNew` false. A one-minute interval against a fourteen-minute run produced overlapping executions that ran the whole playbook more than once.

## Where output goes

**Case context** — `SOCFramework.Analysis.AI` on the case is the single current summary. Field targets come from `SOCFrameworkPhaseContract_V3` `writes_by_phase.analysis`, so a schema change propagates by re-emitting the List. Every declared target is seeded with its typed `init` value, which preserves the absent / at-init / populated distinction Containment needs to tell "analysis never ran" from "analysis ran and found nothing".

The prompt produces 17 of the 22 declared targets. The other five are deterministic case facts filled from the case record, and Containment reads two of them — `case_score` and `case_host_count` — so a contract built from model output alone would hand it empties.

`DeleteContext` runs before `Set` every time. **`Set` appends on repeat**, which would turn `verdict` into an array on the second analysis and break every consumer.

Written to `Analysis.AI`, not bare `Analysis`. There is no deterministic case producer to compare against yet, so writing to `Analysis` would make the first AI output authoritative by default; promotion belongs to `SOCPromoteAIPhaseOutput`.

**Case War Room** — one tagged entry per case, written with `core-api-post` to `/xsoar/public/v1/entry/execute/sync` against `INCIDENT-<case_id>`. A JOB runs in its own investigation, so a verdict left there lands where no analyst looks. Entries cannot be deleted — the delete endpoints return 303 — so the current verdict is tagged `socfw-case-verdict` and earlier ones `socfw-superseded`.

**Execution dataset** — a `case_analysis` row per case with the verdict and reasoning fields, and one `case_analysis_run` row per run carrying `xql_queries`, `xql_cost_charged` and `xql_remaining_quota` so cadence can be tuned from measured spend.

## AI and regions without it

`aiTask` content fails validation on tenants without AI capability, and an AI Prompt cannot ship in a pack at all — it is referenced only by a tenant-local `aiTaskId`.

So the aiTask lives in the **sub-playbook**, not the JOB:

- The JOB and the pack copy of `SOC Case Analysis Phase` contain no `aiTask` and install everywhere.
- Where AI is available, the same playbook id is uploaded by hand through the UI with the aiTask bound. It detaches on save, and pack upgrades leave it alone.

Order matters: create the prompt first, then upload the sub-playbook, because the aiTask can only reference a prompt id that already exists.

Keeping the aiTask in the four-task sub-playbook rather than the fourteen-task JOB means the orchestration stays pack-managed and upgradeable, and only the small artifact is hand-held.

## Scalar bindings

**Every task argument in the sub-playbook is a scalar read from `CaseIter.*`.**

XSIAM runs a task once per element when an argument resolves to an array, and the sub-playbook input accumulates across forEach iterations. Binding straight to `inputs.Case` fired every task once per case seen so far — a triangular series that produced 118 verdict entries for 16 cases, with later cases rendering under earlier headers.

A `Stringify` transformer does **not** fix this. The transformer applies per element.

`SOCFWCaseIterationSetup` pins the current case to scalar keys and clears `Analysis.AI`, so nothing downstream has an array to iterate. Anything a task needs that could accumulate is read from context inside the script instead of passed as an argument.

## Known limitations

- **The entities aggregate still reads `dataset = alerts`.** Shapes and coverage moved to `dataset = issues` with `xdm.issue.*` naming; entity columns have no issue-dataset equivalent that resolved cleanly. `xdm.issue.normalized_fields` carries `xdm.source.host.hostname`, `xdm.source.agent.identifier`, `xdm.source.ipv4` and `xdm.email.sender` and is the migration target once the JSON accessor syntax is settled.
- **Over-budget defers permanently.** Deferral is right for a transient failure, but a high-variety case that always exceeds `CaseMaxContractFetches` is never analysed. A permanent condition should degrade and declare its coverage rather than defer.
- **No deterministic counterpart.** Case analysis has no non-AI producer, which sits against the rule that the framework must never have a capability existing only with AI.
- **Multi-issue validation is thin.** One six-issue two-category case has been analysed end to end. The 76-issue and 57-issue cases have been collapsed and measured but not reasoned over.
- **Re-analysis is bounded by schedule interval, not issue count.** A JOB run batches whatever arrived since the last one, so a large arrival inside one interval is a single analysis. A case receiving issues in every interval for days is the remaining unbounded path.
