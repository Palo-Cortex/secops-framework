# socfw-mapper

Tenant-driven tooling for the two contracts the SOC Framework resolves
against at runtime: the **product category map** (`SOCProductCategoryMap_V3`)
and the **normalization map** (`SOCFrameworkNormalizeMap_NIST_IR`).

Tools either connect to an XSIAM tenant via the API and read live `issue.*`
data, or work offline from a capture. None writes to a tenant. `--env`
selects which tenant, so the same tools run against dev, PoV, or production
by pointing at a different credentials file.

Deterministic. No LLM. Every classification carries the evidence that
produced it.

| tool | contract | answers |
|---|---|---|
| `check_routing.py` | category | which sources fall through unrouted? |
| `build_category_map.py` | category | build the map from live data |
| `regression_check.py` | category | did a map change move an existing source? |
| `socfw_contract.py` | normalization | where is the contract defective, and what would extend it? |
| `contract_coverage.py` | normalization | can each source fill what the contract promises? |
| `normalize_regression.py` | normalization | did a NormalizeMap change break a source? |
| `execution_baseline.py` | behaviour | did what the framework actually does change? |

---

## Captures

**Captures live outside the repo** — `~/captures/` by convention.
Never commit one.

`build_category_map.py --capture` is phase 1: connect, sanitise at the
boundary, write, stop. Nothing is analysed. A capture holds field **names and
counts only — no values**:

```json
{ "_schema": "socfw-mapper capture v1 — sanitised: field names and counts only, no values",
  "tenant": "https://...", "issues_scanned": 3000,
  "sources": [ { "ds_tag": "...", "product": "...", "issues": 42,
                 "fields": { "somecliname": 41 } } ] }
```

Everything downstream runs offline from these — `--from-capture`,
`socfw_contract`, `contract_coverage`, `normalize_regression`. One capture
per tenant; pass several to consolidate, and a source thinly sampled on one
tenant still classifies well if another saw it properly.

A capture records **presence, not type**. A field that arrives as a string on
one alert and an array on another looks identical in a capture, so nothing
here can emit a normalize row's `shape` — that needs values and is not built.

---

## check_routing.py — audit

Answers: **which of this tenant's data sources are actually routed?**

`Foundation - Product Classification` takes the `DS:` tag off an issue,
normalises it to a `ds_*` key, and looks it up in `SOCProductCategoryMap_V3`.
An exact miss means no category, which means no normalization — silently.
This tool performs the same lookup and reports what falls through.

```bash
python3 tools/socfw-mapper/check_routing.py --env .env-prod1 --pages 20
```

Output is two lists: routed sources, and unrouted ones with the nearest
shipped key. A near-miss (`ds_checkpointndr` vs shipped `ds_check_point_ndr`)
means the source is mapped but under a different spelling than the tenant
emits — a real production routing gap, not a tooling artifact.

Run this first. It tells you the size of the problem before you generate
anything.

---

## build_category_map.py — generate

Builds the category map schema from live tenant data, for the emitter to
turn into the shipped List.

```bash
python3 tools/socfw-mapper/build_category_map.py \
    --env .env-prod1 --detections-only \
    --out schemas/soc-optimization-unified/SOCProductCategoryMap_V3.yaml

python3 tools/generate_soc_framework_content.py emit \
    --mapping schemas/soc-optimization-unified/SOCProductCategoryMap_V3.yaml \
    --pack-root Packs/soc-optimization-unified
```

### How it classifies

Groups issues by `(DS: tag, product)`, builds a field signature from the
runtime `issue.*` context, and scores it against a corpus learned from the
vendor packs' `alert_fields`. The canonical core — fields every category
shares — is suppressed, since it carries no category signal and otherwise
swamps the discriminative tail.

Multi-product sources are scored **differentially**: a vendor's minority
products carry the parent's vocabulary (CrowdStrike identity alerts still
ship `agentid`/`initiatorpid`), so the absolute signature ranks them by the
parent's category. Subtracting the shared vendor core fixes this — measured
on brumxdr, Falcon Identity Protection moves from Endpoint 5.64 / Identity
2.2 (wrong) to Identity 2.2 / Endpoint 1.6 (right).

### Precedence

Highest wins:

1. **Hand edits** — any `type` / `response` / `responses` value you set
2. **Shipped contract** — seeded from `SOCProductCategoryMap_V3_data.json`
3. **House defaults** — mined majority responder per category
4. `TODO-REVIEW`

`category` and `confidence` always refresh from current evidence.
`product_map` is **additive only** — a derived value never replaces an
existing one, because misrouting a product sends its whole lifecycle to the
wrong playbooks. Conflicts are reported, not applied.

Merge is the default whenever `--out` exists. `--overwrite` is the explicit
destructive path.

### Confidence

| verdict | meaning |
|---|---|
| `high` / `medium` | emitted |
| `low` | emitted, worth a look |
| `weak` | real signal below floor — review, not emitted |
| `none` | no category evidence at all — not an IR data source |

`none` reliably catches health, audit, and posture telemetry. `weak` mostly
catches thin-corpus categories (see limitations).

### Key flags

| flag | purpose |
|---|---|
| `--env` | tenant credentials file |
| `--detections-only` | `sourceBrand:CORRELATION`; use on tenants where posture volume crowds out detections |
| `--query` | arbitrary issue filter, e.g. `name:CrowdStrike` |
| `--floor` | score threshold, default 10 |
| `--allowlist` | file of `ds_*` keys to promote; everything else stays tenant-local |
| `--no-differential` | disable differential scoring for multi-product sources |
| `--overwrite` | discard hand edits and rebuild |

---

## regression_check.py — category map safety

Answers: **did a category map change move a source that already worked?**

Replicates the runtime resolution — `DS:` tag → `ds_*` key → map lookup →
`_base_cat`, with `product_map[_product]` overriding and `responses[]`
selecting the responder — and compares HEAD against the working tree.

Any difference on an existing source is a behaviour change. Only new sources
should differ, absent to present.

---

## socfw_contract.py — normalization contract

Two subcommands, deliberately separate.

```bash
python3 tools/socfw-mapper/socfw_contract.py audit
python3 tools/socfw-mapper/socfw_contract.py audit --category network
python3 tools/socfw-mapper/socfw_contract.py extend --category network \
    --captures '~/captures/*.json' --emit
```

`audit` trues up what exists: it finds contract defects by set operations
over the NormalizeMap, the field registry, live population from captures, and
downstream playbook consumption. A target no playbook reads is dead weight; a
target every playbook reads and no source fills is a promise the contract
cannot keep.

`extend` proposes new mapping rows for a category, drawn from fields its
sources actually populate, using the complete category blocks as precedent.
`--emit` prints schema rows. **Read them before you paste them** — the tool
proposes, it does not decide, and `target` naming is a human call.

---

## contract_coverage.py — per-source gap analysis

Answers: **for every field the contract promises, can each source fill it?**

The inverse of `extend`. Not "what do sources emit, let us map it" but "the
contract says this target exists, so who populates it and who doesn't."

Per target, per source:

| verdict | meaning |
|---|---|
| `SATISFIED` | which `issue.*` field in the fallback chain this source populates |
| `CANDIDATE` | chain is empty here, but the source populates a field of the same concept |
| `ABSENT` | source carries nothing of that concept — a real gap |

`CANDIDATE` is the automatable part: a source-specific gap becomes a one-line
fallback alias without inventing a target. `--emit-aliases` prints them.
`ABSENT` is the one that needs a decision — either the vendor pack emits it,
or the contract stops promising it.

---

## normalize_regression.py — normalization safety

Answers: **did a NormalizeMap change break a source?**

`regression_check.py` for the normalization contract. For every target in a
category, resolve which `issue.*` field would populate it for each source
given a capture, then diff HEAD against the working tree.

| result | treatment |
|---|---|
| resolved before, not after | **regression** — exits non-zero |
| resolves from a different field | behaviour change, flagged not failed (fallback order legitimately changes) |
| newly resolves | improvement |

Run this on any NormalizeMap edit before `check_contribution.py`. The gate
proves the pack installs; this proves the change did not silently drop a
source.

---

## execution_baseline.py — behavioural baseline

Answers: **did what the framework actually does change?**

Everything above compares the *contract*. This compares behaviour, from
`xsiam_socfw_ir_execution_raw` — every phase execution, the entity it acted
on, the command it ran, and whether that succeeded.

```bash
python3 tools/socfw-mapper/execution_baseline.py snapshot \
    --env .env-dev --out ~/captures/baseline_before.json
# ... contract changes, deploy ...
python3 tools/socfw-mapper/execution_baseline.py snapshot \
    --env .env-dev --out ~/captures/baseline_after.json
python3 tools/socfw-mapper/execution_baseline.py compare \
    --before ... --after ...
```

A phase that produced entities and now produces none, or a command whose
success rate drops past `--tolerance`, is a regression no contract diff can
see. Exits non-zero on regression.

Snapshots are telemetry, not captures — same rule applies, they stay out of
the repo.

---

## Limitations

**The corpus is thin outside Endpoint and Email.** Training is 9 vendor packs:
Endpoint 3, Email 3, Identity 1, Network 1, Cloud 1. Endpoint and Email
classify at 24–48 with 6–11x margins and are correct on every source tested
across three tenants. Identity, Network, and Cloud score 1–5 and land in
`weak` — the tool abstains rather than guessing, but it cannot currently
classify them. More packs in those categories is the fix; tuning the floor
is not.

**Sampling is newest-first, so high-volume sources crowd out the rest.** On a
tenant with 50k posture alerts, 3,000 issues may surface only two detection
sources. `--detections-only` and `--query` are the workaround. Stratified
per-source sampling is the proper fix and is not built.

**`type` and the own-category responder are not inferred.** No path exists
from field data to "this is an NDR" or "the integration is called Trend Micro
Vision One V3". These stay human.

**`product_map` for a genuinely new multi-product vendor is human-authored.**
Differential scoring gets the ranking right but the scores are small, so it
lands in review. There is nothing to seed from on a vendor the shipped map
has never seen.

**Shape variance is invisible to the contract tools.** Captures carry
presence, not type, so a field that is a string on some alerts and an array
on others cannot be detected here. Nothing emits a `shape` value, and rows
that need both `f` and `f.[0]` forms stay human. Adding a per-field type
tally to the capture is the fix; it changes the capture schema.

**`ABSENT` and `CANDIDATE` are proposals, not verdicts.** `contract_coverage`
sees what a source populated in the sampled window. A source that emits a
field only on a rare alert type reads as `ABSENT` on a thin capture.
Consolidate several tenants before treating a gap as real.

**None of the contract tools run in CI.** They are pre-gate checks a human
runs and reads. `normalize_regression` and `execution_baseline` exit
non-zero and could be wired in; they are not.
