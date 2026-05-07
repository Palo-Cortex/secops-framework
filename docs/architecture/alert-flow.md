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
condition matches. The rule maps XQL output columns to the alert schema
via `alert_fields`, which is what Foundation later reads.

The framework's contract for that mapping: **native `issue.*` fields
first, `socfw*` only as a fallback for genuinely vendor-specific data.**
Native fields light up XSIAM's preconfigured incident enrichment,
grouping, asset extraction, MITRE coverage dashboards, and the analyst
Alert View — all without configuration. `socfw*` fields are dark to
the platform and should only carry data XSIAM doesn't model. The
decision tree, worked example, and the Endpoint normalizer pattern
are at the bottom of this page under
[Correlation rule field mapping](#correlation-rule-field-mapping).

The rule must also stamp MITRE fields (`mitretacticid`,
`mitretacticname`, `mitretechniqueid`, `mitretechniquename`) and
grouping fields regardless of vendor — these are how XSIAM's case
grouping correlates related alerts and how the native MITRE coverage
dashboard works.

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

---

## Correlation rule field mapping

A reference for anyone authoring or modifying a correlation rule.
Stage 3 above introduces the principle; this section is the operating
detail.

### The mapping order

When a correlation rule maps XQL output columns into `alert_fields`,
the mapping target order is non-negotiable:

1. **Native XSIAM alert field** if one semantically matches
   (`fw_email_sender`, `action_file_sha256`, `agent_hostname`,
   `causality_actor_*`, `mitretacticid`, `dns_query_name`, etc.)
2. **XDM field** the modeling rule can populate, which XSIAM
   auto-extracts to a native alert field
3. **`socfw*` custom field** only when neither of the above exists

`socfw*` is a documented fallback for genuinely vendor-specific data
with no native home. It is not the framework's default mapping pattern.

### Why this matters

Native fields are populated by XSIAM's preconfigured incident
enrichment. Mapping to them is what gives you native incident grouping,
automatic asset and artifact extraction, the analyst Alert View, MITRE
coverage dashboards, and full-text search across alerts — all without
configuration.

None of that works for `socfw*`. Custom fields are dark to the
platform. They live in playbook context and dataset writes and nowhere
else.

This is the lean build principle applied to alert normalization. Every
avoidable `socfw*` field is custom content the framework ships and
maintains forever, displacing what XSIAM already does natively. It is
also a direct **VD2 (Simplify Operations)** story: every native
mapping is one less thing the customer has to know about, configure,
or maintain.

### When `socfw*` is justified

A custom field earns its place only when the vendor delivers data the
platform doesn't model:

- A **lifecycle state** with no native equivalent (e.g., Proofpoint's
  `threatStatus` cycling through active / cleared / falsePositive)
- A **proprietary score** without a native home (`phishScore`,
  `spamScore`, `malwareScore`)
- A **vendor catalog or campaign identifier** that has meaning only
  inside that vendor (`threatId`, `campaignId`)
- A **proprietary taxonomy** the vendor invents (classification enums,
  threat-type strings)

If a proposed `socfw*` field doesn't fit one of those buckets, it is
doing work XSIAM already does — map to the native equivalent.

### Worked example — Proofpoint TAP

| TAP raw field | Mapping target | Why |
|---|---|---|
| `sender` | `fw_email_sender` (native) | Free incident enrichment |
| `recipient` | `fw_email_recipient` (native) | Native |
| `subject` | `fw_email_subject` (native) | Native |
| `senderIP` | `action_remote_ip` (native) | Native IP field |
| `messageID` | `email_message_id` (native if in tenant schema) | Verify first |
| `threatUrl` | native URL field if available, else `socfwemailthreaturl` | Check schema first |
| `threatId` | `socfwemailthreatid` (custom) | Vendor catalog, no native home |
| `threatStatus` | `socfwemailthreatstatus` (custom) | Vendor lifecycle state |
| `phishScore`, `spamScore`, `malwareScore` | `socfwemail*score` (custom) | Vendor scoring, no native |
| `campaignId` | `socfwemailcampaignid` (custom) | Vendor-specific grouping |
| `classification` | `socfwemailclassification` (custom) | Vendor taxonomy |

The split is roughly half-and-half. The native half lights up XSIAM's
incident enrichment for free. The `socfw*` half captures concepts the
platform doesn't model. Both halves are read by
`Foundation_-_Normalize_Email_V3` from `issue.*` — the namespace just
differs.

### The Endpoint normalizer model

`Foundation_-_Normalize_Endpoint_V3` is the canonical pattern. It
reads native `issue.*` fields directly:

```
issue.initiatorsha256[0]   → SOCFramework.Artifacts.Process.SHA256
issue.filesha256[0]        → SOCFramework.Artifacts.Target.SHA256
issue.agentid              → SOCFramework.Artifacts.Endpoint.AgentID
issue.hostname             → SOCFramework.Artifacts.Endpoint.Hostname
issue.mitretacticname      → SOCFramework.Artifacts.MITRE.Tactic
```

There is no `socfwendpointhostname`. There is no
`socfwendpointagentid`. XDR Agent populates these natively, and
third-party EDR packs (CrowdStrike, SentinelOne, Defender) carry the
same shape via their modeling rules.

Email is mid-migration — it currently mixes native (`fw_email_sender`)
and custom (`socfwemailthreatstatus`). Identity, Network, Cloud, and
Generic normalizers haven't started the structured `Artifacts.*`
migration yet. When they do, they follow the Endpoint pattern.
