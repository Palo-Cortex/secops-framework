# Darktrace (darktrace) — Vendor Schema

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

> **Source:** [`schemas/vendors/darktrace/darktrace-model-breaches.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/vendors/darktrace/darktrace-model-breaches.yaml)

## Identity

| Field | Value |
|---|---|
| vendor | `darktrace` |
| product | `Darktrace` |
| data_source | `darktrace_darktrace_raw` |
| category | `Network` |

## Raw Schema

Fields available in the raw ingest dataset.

| Field | Type | Array | Status | JSON Subfields |
|---|---|---|---|---|
| `pbid` | `float` |  | declared |  |
| `time` | `float` |  | declared |  |
| `creationTime` | `float` |  | declared |  |
| `score` | `float` |  | declared |  |
| `percentscore` | `float` |  | declared |  |
| `acknowledged` | `string` |  | declared |  |
| `commentCount` | `float` |  | declared |  |
| `breachUrl` | `string` |  | declared |  |
| `did` | `float` |  | declared |  |
| `device` | `string` |  | declared |  |
| `model` | `string` |  | declared |  |
| `triggeredComponents` | `string` | ✓ | declared |  |

## Modeling Rule — SOC Darktrace Modeling Rule

| Field | Value |
|---|---|
| modeling_rule_id | `SOC_Darktrace_ModelingRule` |
| modeling_rule_name | `SOC Darktrace Modeling Rule` |
| directory_name | `SOCDarktraceModelingRules` |
| fromversion | `6.10.0` |

### Field Mappings

What each XDM field is, where it sources from, what issue field it surfaces on, and why the mapping is shaped the way it is.

| XDM Path | Expression | Sources | Issue Field | Description |
|---|---|---|---|---|
| `xdm.event.id` | `to_string(pbid)` | `pbid` | `originalalertid` | Per-breach id. Not model.now.uuid, which identifies the model. |
| `xdm.alert.original_alert_id` | `to_string(pbid)` | `pbid` |  |  |
| `xdm.alert.name` | `json_extract_scalar(to_json_string(model), "$.now.name")` | `model` | `originalalertname` |  |
| `xdm.alert.description` | `json_extract_scalar(to_json_string(model), "$.now.description")` | `model` | `alert_description` |  |
| `xdm.alert.category` | `json_extract_scalar(to_json_string(model), "$.now.category")` | `model` |  |  |
| `xdm.alert.subcategory` | `json_extract_scalar(to_json_string(model), "$.now.behaviour")` | `model` |  |  |
| `xdm.alert.severity` | `to_string(percentscore)` | `percentscore` | `severity` | Raw 0-100. The correlation rule maps it to the XSIAM ladder. |
| `xdm.source.ipv4` | `json_extract_scalar(to_json_string(device), "$.ip")` | `device` | `action_local_ip` |  |
| `xdm.source.host.hostname` | `if(json_extract_scalar(to_json_string(device), "$.hostname") ~= "^SaaS::",   ...` | `device` | `agent_hostname` | A SaaS "device" puts "SaaS::Office365: <upn>" in hostname. That is an identity, not a host — nulled here rather than written into a hostname field, where it would break UEBA stitching. |
| `xdm.source.user.username` | `if(json_extract_scalar(to_json_string(device), "$.hostname") ~= "^SaaS::",   ...` | `device` | `actor_effective_username` | Null for host-shaped devices. Darktrace observes traffic, not logons, so a machine breach genuinely has no user and an invented one would be worse than an empty field. |
| `xdm.source.host.device_id` | `json_extract_scalar(to_json_string(device), "$.did")` | `device` |  |  |
| `xdm.source.host.os` | `json_extract_scalar(to_json_string(device), "$.os")` | `device` |  |  |
| `xdm.target.ipv4` | `json_extract_scalar(to_json_string(triggeredComponents), "$[0].ip")` | `triggeredComponents` | `action_remote_ip` | The peer address on the metric that fired. NOT the monitored entity's own address — keeping these apart is what stops victim and peer landing in one field. |
| `xdm.observer.product` | `"Darktrace"` |  |  |  |
| `xdm.observer.vendor` | `"Darktrace"` |  |  |  |

### Contributes (Artifacts.*)

Fields populated for downstream lifecycle Artifacts schemas:

- `Network.LocalIP`
- `Network.RemoteIP`
- `Endpoint.Hostname`

## Correlation Rules

### SOC Darktrace - Model Breach

| Field | Value |
|---|---|
| global_rule_id | `SOC Darktrace - Model Breach` |
| subtype | `passthrough` |
| fromversion | `6.10.0` |

Reshapes Darktrace model breaches (darktrace_darktrace_raw) into properly-formed XSIAM alerts for the SOC Framework Network category. Maps the monitored entity and the triggered metric's peer to the canonical network pivots, percentscore to the XSIAM severity ladder, and MITRE from the model definition. Grouping pivots: action_local_ip (entity), action_remote_ip (peer), agent_hostname (host-shaped entities only), causality_actor_causality_id (pbid). SCOPE: Critical and Suspicious SCOPE: Darktrace's own Critical band only, non-compliance (~4 breaches / 30 days on a reference tenant, measured as DISTINCT pbid — the collector re-polls, so row counts overstate by several thousand times). Suspicious is excluded: it is Darktrace's "worth a look", and including it put 82 breaches / 30 days on the queue, 67 of which were Antigena autonomous-response records or one chatty recon model. Everything below Critical stays queryable in darktrace_darktrace_raw and is better used as enrichment on a case another source opened. Identity axis is wired for SaaS entities only: a SaaS "device" is an account, and its UPN is recovered from the hostname string into actor_effective_username and user_principal. Measured IN SCOPE on a reference tenant that is 8 of 82 breaches over 30 days — across all breaches including Informational it is 70 of 400, but this rule does not fire on Informational and the in-scope number is the one that matters. Small, and still the only pivot this source shares with the email and identity categories. Host-shaped devices keep a null identity, which is correct: Darktrace observes traffic, not logons.

**Tags:** `SOCFramework`, `Passthrough`, `Network`, `NDR`, `Darktrace`

#### Schema Constants

| Field | Value |
|---|---|
| rule_id | `0` |
| alert_category | `User Defined` |
| alert_domain | `DOMAIN_SECURITY` |
| action | `ALERTS` |
| execution_mode | `SCHEDULED` |
| mapping_strategy | `CUSTOM` |
| user_defined_category | `dt_category` |
| user_defined_severity | `severity` |
| is_enabled | `✓` |
| drilldown_query_timeframe | `ALERT` |
| severity | `User Defined` |

#### Suppression

| Field | Value |
|---|---|
| enabled | `✓` |
| duration | `24 hours` |
| fields | `pbid` |

pbid is one id per model breach and is a real top-level column, so it is usable for suppression (suppression resolves against the dataset, not against the query's alters). Daily window absorbs re-polls of a breach that has not been acknowledged.

#### Alert Fields

Issue-field assignments emitted by the correlation rule. The Description column captures intent — when present, this is what downstream playbooks rely on the field meaning.

| Issue Field | Source | Bucket | Description |
|---|---|---|---|
| `vendor` | `vendor` | `computed` |  |
| `product` | `product` | `computed` |  |
| `originalalertid` | `originalalertid` | `computed` |  |
| `originalalertname` | `originalalertname` | `computed` |  |
| `originalalertsource` | `originalalertsource` | `computed` |  |
| `externallink` | `externallink` | `computed` |  |
| `alert_description` | `alert_description` | `computed` |  |
| `severity` | `severity` | `computed` |  |
| `mitretacticid` | `mitretacticid` | `computed` |  |
| `mitretacticname` | `mitretacticname` | `computed` |  |
| `mitretechniqueid` | `mitretechniqueid` | `computed` |  |
| `mitretechniquename` | `mitretechniquename` | `computed` |  |
| `action_local_ip` | `action_local_ip` | `network` |  |
| `action_remote_ip` | `action_remote_ip` | `network` |  |
| `agent_hostname` | `agent_hostname` | `endpoint` |  |
| `causality_actor_causality_id` | `causality_actor_causality_id` | `computed` |  |
| `actor_effective_username` | `actor_effective_username` | `identity` |  |
| `user_principal` | `user_principal` | `identity` |  |
| `localip` | `action_local_ip` | `legacy` |  |
| `remoteip` | `action_remote_ip` | `legacy` |  |
| `hostname` | `agent_hostname` | `legacy` |  |

#### Pre-Alter XQL

```xql
// Vendor / product (required for SOCProductCategoryMap routing)
| alter vendor_name = "Darktrace", product_name = "Darktrace"

// ========================================================================
// DETECTION SCOPE — measured on a reference tenant
//
// The collector RE-POLLS open breaches: 2,819 rows in 24h resolved to
// 11 distinct pbid (~256 rows per breach). Row counts are not detection
// counts, and reading them as such is what made an earlier draft of this
// filter Critical-only.
//
//   DISTINCT BREACHES        24h        30d
//     Informational            9        318
//     Suspicious               2         78
//     Critical                 0          4
//
// Scope is CRITICAL only, excluding compliance models (policy findings,
// not threats): ~4 breaches / 30d. That is deliberately rare. See the
// model-family breakdown below for why Suspicious was dropped.
//
// Suppression on pbid is load-bearing, not cosmetic. Without it the
// re-polling turns 11 breaches into 2,819 alerts a day.
//
// Critical never scores above 84 here while Suspicious is dominated by
// the 85+ band, so percentscore is NOT a severity proxy. Filter on
// category; use score only to rank within it. The severity ladder below
// does exactly that — an earlier version mapped percentscore straight
// onto the XSIAM scale and called 70 of 82 breaches critical.
// ========================================================================
| alter dt_scope_category   = json_extract_scalar(to_json_string(model), "$.now.category"),
        dt_scope_compliance = json_extract_scalar(to_json_string(model), "$.now.compliance"),
        dt_scope_model      = json_extract_scalar(to_json_string(model), "$.now.name")
| filter dt_scope_category = "Critical"
| filter dt_scope_compliance != "true"

// WHY CRITICAL ONLY, and not Critical + Suspicious.
//
// Including Suspicious put 82 breaches / 30 days on the queue. Broken
// out by model family that was:
//
//   Antigena::Network::*                              45
//   Device::Attack and Recon Tools                    22
//   SaaS::Access / Unusual Activity / Compromise       8
//   Compromise::* (DGA beaconing, Tor, DNS volume)     5
//   Device::Network Scan / Anomalous Github Download   2
//
// Antigena models are Darktrace's AUTONOMOUS RESPONSE firing: the
// traffic was already blocked. They record containment that happened,
// not a detection needing investigation. Device::Attack and Recon Tools
// is one model producing 22 breaches, which is scanner and admin-tooling
// behaviour rather than 22 incidents.
//
// Excluding those two left ~15, and they were still all Suspicious --
// Darktrace's "worth a look", not its "act on this". Building a case
// pipeline on another vendor's maybe is how a queue stops being read.
//
// So scope defers to Darktrace's own verdict and nothing else: the
// Critical band, ~4 breaches / 30 days on a reference tenant. Rare, and meaningful
// when it fires. Everything else stays in darktrace_darktrace_raw, fully
// queryable, and is better used as enrichment on a case another source
// opened than as a case of its own.
//
// Antigena is NOT excluded here. "Antigena Active Threat SMB Write
// Block" is in the Critical band and is a genuine compromise signal even
// though the traffic was stopped -- at 2 in 30 days it costs nothing and
// the fact that autonomous response fired is worth an analyst's time.
//
// A customer whose estate produces a different mix should widen this in
// their own config rather than the pack widening it for everyone.

// ---- Model definition (authored from `now`, the current definition) ----
| alter
    dt_model_name        = json_extract_scalar(to_json_string(model), "$.now.name"),
    dt_model_category    = json_extract_scalar(to_json_string(model), "$.now.category"),
    dt_model_behaviour   = json_extract_scalar(to_json_string(model), "$.now.behaviour"),
    dt_model_description = json_extract_scalar(to_json_string(model), "$.now.description"),
    dt_model_priority    = json_extract_scalar(to_json_string(model), "$.now.priority"),
    dt_mitre_tactic      = json_extract_scalar(to_json_string(model), "$.now.mitre.tactics[0]"),
    dt_mitre_technique   = json_extract_scalar(to_json_string(model), "$.now.mitre.techniques[0]")

// ---- Monitored entity ----
| alter
    dt_device_ip       = json_extract_scalar(to_json_string(device), "$.ip"),
    dt_device_hostname = json_extract_scalar(to_json_string(device), "$.hostname"),
    dt_device_did      = json_extract_scalar(to_json_string(device), "$.did"),
    dt_device_type     = json_extract_scalar(to_json_string(device), "$.typelabel"),
    dt_device_os       = json_extract_scalar(to_json_string(device), "$.os")

// A SaaS "device" is an account, not a host. Writing "SaaS::Office365:
// <upn>" into agent_hostname would put an identity in a hostname pivot and
// group unrelated SaaS breaches by a string that is not a machine.
| alter dt_is_saas = if(dt_device_hostname ~= "^SaaS::", "true", "false")
| alter dt_hostname = if(dt_is_saas = "true", null, dt_device_hostname)

// ...but the identity inside that string is the only cross-category
// bridge this source has, so it is recovered rather than discarded.
// Measured on a reference tenant over 30 days, by DISTINCT pbid:
//
//   host           180      ip-only        108
//   saas-identity   97      neither         15
//
// of the 97 SaaS entities, 70 carry a UPN-shaped principal resolving to
// 46 distinct identities. IN SCOPE, though — after the Critical +
// Suspicious filter below — it is 8 breaches of 82, because SaaS
// entities skew Informational. Verified by running this rule's emitted
// XQL against the tenant, not inferred from the population above.
// The other 27 SaaS entities carry a non-UPN label and
// correctly extract to null. Extraction is by regex on the whole string
// rather than by splitting on ":" — the provider segment varies, the
// separator may or may not be followed by a space, and a regex that
// finds no address returns null instead of inventing an identity from a
// label. Three states, not two.
| alter dt_saas_upn = if(dt_is_saas = "true",
        arrayindex(regextract(dt_device_hostname,
                   "([\w.%+\-']+@[\w.\-]+\.[A-Za-z]{2,})"), 0),
        null)

// ---- Peer from the triggered metric ----
| alter dt_peer_ip = json_extract_scalar(to_json_string(triggeredComponents), "$[0].ip")

// ---- Severity: Darktrace's OWN verdict first, score only to rank
// within it.
//
// The previous ladder mapped percentscore straight onto the XSIAM scale
// and was inverted in both directions. Measured over 30 days on a reference tenant:
//
//   emitted severity   Darktrace category   breaches
//   SEV_050_CRITICAL   Suspicious                 68   <-- 83% of output
//   SEV_040_HIGH       Suspicious                  6
//   SEV_030_MEDIUM     Suspicious                  4
//   SEV_050_CRITICAL   Critical                    2
//   SEV_040_HIGH       Critical                    1
//   SEV_030_MEDIUM     Critical                    1
//
// Darktrace calls 3 of 82 breaches Critical; the rule called 70 of them
// critical, and demoted two of the three real ones to Medium and High.
// The cause is that Darktrace's bands are not score-ordered: Suspicious
// is dominated by the 85+ band while Critical never exceeds 84 here. A
// high percentscore means "this model fired strongly", not "this is
// severe" -- a Suspicious model can breach at 100 and still be a
// Suspicious finding.
//
// The comment above the old ladder already said "percentscore is NOT a
// severity proxy. Filter on category; use score only to rank within it."
// This now does that.
| alter severity = if(
      dt_scope_category = "Critical"   and to_integer(percentscore) >= 70, "SEV_050_CRITICAL",
      dt_scope_category = "Critical",                                      "SEV_040_HIGH",
      dt_scope_category = "Suspicious" and to_integer(percentscore) >= 85, "SEV_030_MEDIUM",
      dt_scope_category = "Suspicious",                                    "SEV_020_LOW",
      "SEV_010_INFO")

| alter dt_category = coalesce(dt_model_category, "Network")

// ---- Analyst-facing title: [Network] <entity> - <category>: <model> ----
// dt_saas_upn sits second: for a SaaS breach the account name is what an
// analyst recognises, and without it the title fell through to a numeric
// Darktrace device id.
| alter dt_entity = coalesce(dt_hostname, dt_saas_upn, dt_device_ip,
                             to_string(dt_device_did), "Unknown")
| alter alert_name = concat("[Network] ", dt_entity, " - ",
                            dt_category, ": ", coalesce(dt_model_name, "Model Breach"))

| alter alert_description = concat(
      coalesce(dt_model_description, "Darktrace model breach"),
      " | Entity: ", dt_entity,
      " | Peer: ", coalesce(dt_peer_ip, "n/a"),
      " | Score: ", to_string(percentscore),
      " | Breach: ", to_string(pbid))

// ---- Canonical pivots ----
| alter
    vendor                       = vendor_name,
    product                      = product_name,
    originalalertid              = to_string(pbid),
    originalalertname            = dt_model_name,
    originalalertsource          = "Darktrace",
    externallink                 = breachUrl,
    action_local_ip              = dt_device_ip,
    action_remote_ip             = dt_peer_ip,
    agent_hostname               = dt_hostname,
    causality_actor_causality_id = to_string(pbid),
    mitretacticname              = dt_mitre_tactic,
    mitretechniqueid             = dt_mitre_technique,
    mitretacticid                = null,
    mitretechniquename           = dt_mitre_technique

// Identity axis carries the SaaS principal when the monitored entity IS
// an account, and stays null when it is a machine. A host-shaped device
// has no user on a Darktrace model breach — Darktrace observes traffic,
// not logons — so inventing one from the hostname would be worse than
// leaving it empty. Lowercased because grouping is exact-equality and
// casing is a silent pivot-killer.
| alter actor_effective_username = lowercase(dt_saas_upn),
        user_principal           = dt_saas_upn
```
