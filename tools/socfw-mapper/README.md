# socfw-mapper

Tenant-driven tooling for the SOC Framework product category map.

Both tools connect to an XSIAM tenant via the API and read live `issue.*`
data. Neither writes to a tenant. `--env` selects which tenant, so the same
tools run against dev, PoV, or production by pointing at a different
credentials file.

Deterministic. No LLM. Every classification carries the evidence that
produced it.

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
