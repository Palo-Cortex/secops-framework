# Alert Flow

How an alert enters the framework, what runs on it, and where it exits.

## The path, end to end

```
   Vendor data       Modeling rule        Correlation rule       Foundation              NIST IR phase playbooks
   (raw events)  →   (XDM mapping)    →   (alert generation) →   (normalize, route)  →   (Analysis → Containment → Eradication → Recovery)
                                                                                              ↓
                                                                                          Comms + dataset write + close
```

Every alert in the framework follows the same five stages, regardless of
which vendor produced it. The framework's job is to make stages 1–3
plug-replaceable (any vendor) while keeping stages 4–5 invariant (one
lifecycle, contractually defined).

## Stage 1 — Vendor data lands

Raw events arrive from a data source (an EDR, an email security gateway,
an identity provider, etc.) into a vendor-specific dataset like
`crowdstrike_falcon_event_raw` or `proofpoint_tap_v2_generic_alert_raw`.
Each pack owns its dataset.

## Stage 2 — Modeling rule maps to XDM

The pack's modeling rule (`.xif` file) reshapes the raw event into XDM
fields — `xdm.email.sender`, `xdm.endpoint.host.hostname`, etc. This is
where vendor-specific shapes get normalized so downstream content can
work uniformly. Each pack's modeling rule is documented on its schema
page.

## Stage 3 — Correlation rule fires the alert

A correlation rule watches the modeled data and fires an alert when its
condition matches. The rule is responsible for stamping standard
`alert_fields` on the alert — vendor, product, MITRE tactic/technique IDs,
host, user, file hashes, and the framework-specific `socfw*` fields that
Foundation reads.

## Stage 4 — Foundation normalizes and routes

The Foundation layer (in `soc-optimization-unified`) is the alert's
first stop inside the framework. Three things happen:

- **Categorization** — Foundation looks at `vendor + product` and resolves
  a category (endpoint, email, identity, network, saas, workload, pam,
  data) via `SOCProductCategoryMap_V3`.
- **Normalization** — pack-specific Normalize playbooks read the alert's
  raw fields and write them into the framework namespace
  (`SOCFramework.Artifacts.*`). What gets written for each category is
  defined by [`SOCFrameworkNormalizeMap_V3`](../soc-optimization-unified/SOCFrameworkNormalizeMap_V3.md).
- **Routing** — Foundation hands off to the entry-point playbook
  (`EP_IR_NIST (800-61)_V3`) which kicks off the lifecycle.

## Stage 5 — NIST IR lifecycle

The entry-point playbook walks the alert through four phases:

1. **Analysis** — hydrate artifacts, score MITRE, derive verdict
2. **Containment** — block, quarantine, restrict (Shadow Mode by default)
3. **Eradication** — reset, revoke, remediate
4. **Recovery** — re-enable, restore service

Each phase's contract — what it reads, what it writes — is defined by
[`SOCFrameworkPhaseContract_V3`](../soc-framework-nist-ir/SOCFrameworkPhaseContract_V3.md).
Comms, dataset writes for metrics, and case closure happen as the lifecycle
progresses.

## What stays the same across all vendors

The lifecycle. Phase contracts. The category-routing pattern. The Shadow
Mode default. The dataset write path. The metrics schema.

## What changes per vendor

Stages 1–3 (the data, the modeling rule, the correlation rule). Plus the
pack's category-specific normalize playbook. Everything else is inherited
from the Foundation and NIST IR packs.
