# Case analysis → ordered containment plan

**Status:** design, not built · **Written:** 2026-09-14 · **Tenant:** deathstar
**Supersedes the contract-content half of:** work order "Case Analysis JOB tightening"

## Why this exists

The case analysis contract was built to answer *how bad is this case*. The
question it actually has to answer is **is this a real threat, and what do we do
about it, in what order**. Those need different shapes, and the existing one
cannot be stretched into the second.

Issue-level assessment already exists and already runs. The case layer must stop
re-deriving what the issue contracts carry and spend its reasoning on the two
things only case scope can produce: a verdict over the whole intrusion, and a
containment plan across it.

## The shape problem

A case spanning Initial Access → Persistence → Credential Access → Lateral
Movement → C2 has a containment surface at nearly every step. The current
contract collapses all of it into `primary_entity_id`, one `mitre_technique`,
one `compromise_level`, one `spread_level`.

Singular fields cannot express a plural kill chain. A verdict with one primary
entity tells an analyst which host looked worst; it does not tell them that the
account has to be disabled before the host is isolated or the adversary simply
relocates.

`mitre_tactic` at case scope should therefore stop being one tactic and become
the SET of tactics represented across the case. That set is the containment
surface map.

## Division of labour

| Layer | Owns | Does NOT own |
|---|---|---|
| Issue assessment (exists) | Per-issue technique, entity, normalized contract, intel verdicts | Anything requiring the set |
| Case analysis (this) | Is it a real threat; which surfaces need containment; what must be collected for eradication | Rank, action selection, execution |
| Framework ranker (new) | Order, action resolution, dependency | Judgement about the evidence |
| Containment JOB (exists) | Executing the plan, in Shadow by default | Deciding the plan |

The prompt already states *"You do NOT select or execute vendor actions — a
separate Containment stage owns that decision."* That line stays true and stays
in. The model identifies surfaces; the framework ranks them and resolves
actions. This is the guardrail keeping the model out of action selection.

## What the model emits

One new output field, `containment_surfaces`, an array of:

| Field | Values | Why |
|---|---|---|
| `category` | endpoint, identity, network, email, saas, workload, data | Routes to the existing per-category Containment workflow |
| `entity_type` / `entity_id` / `entity_name` | — | The containment target |
| `tactic_id` | MITRE TAxxxx | Drives reason_class |
| `posture` | live, dormant, historical | A persistence mechanism already removed is not a surface |
| `harm` | exfiltration, destruction, none | Promotes a surface above everything else |
| `confidence` | high, medium, low | Rank tie-break |
| `evidence` | one line | Which shapes support it |

The model MUST NOT emit `rank` or `action`.

`posture` does the most work here. Without it the plan fills with steps against
things that are no longer there, and an analyst stops trusting the order.

## The ranker — framework, not model

Ordering is the part where being wrong is most expensive, so it must be
auditable and repeatable rather than regenerated each run. Same facts in, same
order out. A customer tunes disruption tolerance by editing a List, not a
prompt — that is the difference between a PoV conversation and a prompt
engineering session.

`reason_class` is derived, not asked for:

- `harm` != none → **active_harm**
- `tactic_id` in TA0001 / TA0003 / TA0006, or `category` = identity → **re_entry**
- `tactic_id` in TA0008 / TA0011 → **propagation**
- otherwise → **cleanup**

Sort on weights from `SOCFrameworkPhasePolicy_V3`, then category disruption
tier, then confidence. Defaults:

| reason_class | weight | principle |
|---|---|---|
| active_harm | 0 | Exfil or destruction in progress outruns the cost of tipping them off |
| re_entry | 100 | Isolating a host while the account is live just relocates the adversary |
| propagation | 200 | Cut spread before cleaning individual hosts |
| cleanup | 300 | Isolation is most visible, most disruptive, most easily undone by anything above left uncontained |

`posture` = historical drops the surface. `posture` = dormant demotes it one
class.

Action resolves from (`category`, `reason_class`) through
`SOCFrameworkActions_V3`, which already registers every action
`shadow_mode: true`. The whole plan therefore defaults to Shadow with no new
flag — the 1-flip production path is unchanged.

## Where the plan lives — the ledger

A ranked plan is a list, and the case context cannot hold a real array.
Measured on deathstar 2026-09-14: `setParentIncidentContext` stringifies every
value regardless of literal form, so an array lands as a JSON string and is not
addressable.

So the plan goes to `xsiam_socfw_ir_execution_raw`, one row per step:

`event_type: containment_step` — `case_id`, `rank`, `category`, `action`,
`entity_type`, `entity_id`, `entity_name`, `tactic_id`, `reason_class`,
`depends_on_rank`, `evidence_shapes`, `shadow_mode`, `plan_run_id`.

The Containment JOB selects from it by XQL the same way case selection reads its
watermark — a proven pattern, not a new one. Plan-versus-executed comparison
falls out for free and is a Value Driver metric.

The case context keeps scalars only:

- `containment_step_count`
- `containment_first_action`
- `containment_first_category`
- `tactics_observed` (comma-joined string)
- `containment_plan_ready` (second commit barrier, alongside `analysed_at`)

Headline on the case, detail in the ledger.

## Eradication

Emits prerequisites, never a plan. Some eradication evidence does not exist
until containment has run — you do not know every persistence mechanism until
you have collected from an isolated host. A model asked for an eradication plan
at analysis time will invent one.

`event_type: eradication_prereq` — `case_id`, `collect_what`, `from_entity`,
`blocked_until_rank`.

## What happens to the current 27 targets

| Target | Fate | Reason |
|---|---|---|
| `verdict`, `confidence`, `compromise_level`, `spread_level`, `case_category` | Keep | Answers "is this a real threat" |
| `story`, `closure_*`, `action_confidence` | Keep | Verdict reasoning and the closure veto |
| `case_score`, `case_host_count`, `case_issue_count`, `case_user_count`, `global_hash_prevalence_count` | Keep | Deterministic, read by Containment |
| `analysed_*` coverage trio | Keep | Makes the max_analyses cap honest on a growing case |
| `mitre_tactic` | Reshape | Becomes `tactics_observed`, a set, not one tactic |
| `primary_entity_id/name/type/user` | Demote | Artifacts of the singular shape; superseded by `containment_surfaces` |
| `mitre_technique`, `mitre_technique_id` | Demote | Already on the issue contracts; re-deriving them at case scope produces a worse copy |
| `persistence_type` | Fold in | Becomes a surface with `posture` |

Demoted fields should be removed from the prompt's output list before they are
removed from the contract, so a schema change never outruns what the model is
told to produce.

## Measured constraints this design inherits

All verified on deathstar 2026-09-14, all documented in
`SOCFWCaseVerdictReport`:

1. `setParentIncidentContext` APPENDS on repeat and silently ignores
   `append=false`. Two writes leave `["first","second"]`.
2. Individual leaves accumulate the same way, so the SUBTREE must be cleared.
3. `DeleteContext` runs inside a case investigation even though `Set` returns a
   nil pointer panic there. That asymmetry is why the clear went missing.
4. Every leaf lands as a STRING. Declared number / boolean / array types
   describe what the model produced, not what the case context holds. Readers
   comparing `case_score` numerically must coerce.
5. A JSON blob at the root is stored as a string, so dotted reads resolve to
   null. Leaf-by-leaf is the only addressable form.

## Build order

1. **`containment_surfaces` in the prompt.** Output field plus the surface
   rules. Prompt is re-uploaded by hand — an AI Prompt cannot ship in a pack.
2. **`SOCFrameworkPhasePolicy_V3`.** The weights and category disruption tiers.
   Authored before the ranker so the ranker has nothing hard-coded, same
   contract-first discipline as the phase contract.
3. **`SOCFWContainmentPlan`.** Derives `reason_class`, ranks, resolves actions
   through `SOCFrameworkActions_V3`, emits `containment_step` and
   `eradication_prereq` rows, writes the case scalars and the
   `containment_plan_ready` barrier.
4. **Containment JOB selects from the ledger** by rank instead of from the
   singular contract.
5. **War room rendering** — the ordered plan with `reason_class` shown, so the
   output explains its own order rather than emitting a bare list.

## Why this is the PoV artifact

In Shadow Mode the plan prints *"would disable account X to close re-entry, then
would block egress to Y, then would isolate host Z"* with nothing executed. That
is a materially stronger artifact than a verdict: it demonstrates containment
AND the sequencing judgement behind it, without the customer accepting a single
action. It is also the natural place to show Value Driver metrics, since
plan-versus-executed and time-to-first-containment both come off the ledger.

## Still open

- Whether `depends_on_rank` is derived from reason_class ordering alone or
  whether the model flags explicit dependencies. Start with derived; explicit
  dependency is a second pass.
- Whether a campaign-scale case caps the plan length, and on what.
- Whether demoted fields are removed in one schema change or deprecated first.
