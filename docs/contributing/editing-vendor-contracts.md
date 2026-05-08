# Reading and Editing Vendor Contract YAMLs

A practical guide using `proofpoint-tap-threats.yaml` as the worked example.
The same patterns apply to every vendor contract under `schemas/vendors/`.

## What this file is

This is **not** a correlation rule. It's a contract. The file declares everything
needed to generate the actual XSIAM content (modeling rule + correlation rule
files), and `tools/generate_vendor_content.py` does the emit. **Always edit the
contract; never edit the generated rule files directly** — they'll be overwritten
on the next emit.

## Top-level structure

```yaml
# ─── Pack identity (lines 14-18) ─────────────────────────
vendor: proofpoint-tap         # kebab-case identifier
product: TAP                   # display name
data_source: proofpoint_tap_v2_generic_alert_raw   # XSIAM dataset name
category: Email                # SOC Framework category
pack: SocFrameworkProofPointTap                    # repo pack folder

# ─── What's in the dataset (lines 20-55) ──────────────────
raw_schema:
  # Fields the modeling/correlation rules can reference

# ─── Modeling rule (XDM mappings) (lines 57-156) ─────────
modeling_rule:
  # Read-only XDM views over the dataset

# ─── Correlation rules (lines 158-end) ────────────────────
correlation_rules:
  # List — one entry per correlation rule the contract emits
```

Five top-level keys. Edit any of them and re-emit.

---

## Section 1: `raw_schema`

Declares every dataset field you'll reference downstream. Each field has a type
and an array flag:

```yaml
raw_schema:
  recipient:      {type: string,   is_array: true}
  guid:           {type: string,   is_array: false}
  threatsinfomap: {type: string,   is_array: true,  json_subfields: [threatID, classification, threatType, ...]}
```

### Two subsections

The schema is split into two logical groups separated by a comment:

```yaml
raw_schema:

  # Fields declared in shipped _schema.json
  ccaddresses:    {type: string, is_array: true}
  guid:           {type: string, is_array: false}
  ...

  # Fields referenced in the correlation rule but missing from shipped _schema.json
  # (DRIFT — same pattern as CrowdStrike. The vendor integration writes these
  # to the dataset; the modeling rule's _schema.json is incomplete.)
  type:           {type: string, is_array: false, status: inferred_from_correlation}
  threatstatus:   {type: string, is_array: false, status: inferred_from_correlation}
  ...
```

The drift section exists because the modeling rule's deployed `_schema.json`
sometimes lags behind reality — the vendor integration writes more fields than
the schema declares. `status: inferred_from_correlation` flags these so the
generator emits a warning and you know to refresh the schema later.

### When to add a field

If your XQL or `alert_fields` references a dataset field that isn't here,
the emitter will fail validation. Add it before you reference it:

```yaml
useragent:      {type: string, is_array: false, status: inferred_from_correlation}
```

### `json_subfields`

For fields that carry JSON blobs, declare what's inside so the schema doc
generator and validators know:

```yaml
threatsinfomap: {type: string, is_array: true,
                 json_subfields: [threatID, classification, threatType, threatStatus, threatUrl, threatURL, threat]}
```

You still extract them with `json_extract_scalar` in XQL — declaring them
here doesn't auto-flatten anything. It's metadata only.

---

## Section 2: `modeling_rule`

Maps raw fields → XDM. This is what the XSIAM Analytics engine reads. Edit
this when adding analytics coverage or when XDM standards change.

```yaml
modeling_rule:
  fromversion: "6.10.0"
  modeling_rule_id: ProofpointTAP_modeling_rule
  modeling_rule_name: ProofpointTAP Modeling Rule
  directory_name: ProofpointTAPModelingRules

  fields:
    - xdm_path: xdm.email.cc
      expression: 'json_extract_array(ccaddresses, "$.")'
      sources: [ccaddresses]
      issue_field: emailcc

    - xdm_path: xdm.email.recipients
      expression: 'json_extract_array(recipient, "$.")'
      sources: [recipient]
      issue_field: emailrecipients
```

### Each `fields` entry has four parts

| Key | Purpose |
|---|---|
| `xdm_path` | The XDM field this populates (`xdm.email.recipients`, `xdm.source.ipv4`, etc.) |
| `expression` | The XQL expression the modeling rule writes |
| `sources` | Raw fields read by the expression (must all be in `raw_schema`) |
| `issue_field` | Optional — the alert field name when this XDM also feeds an alert (lets the same mapping serve XDM + alerts) |

### Adding XDM coverage

To populate `xdm.source.user.username` from `recipient`:

```yaml
- xdm_path: xdm.source.user.username
  expression: 'arrayindex(recipient, 0)'
  sources: [recipient]
```

The full list of XDM fields that drive analytics is in the SOC Framework skill
under "XDM ANALYTICS FIELDS — MODELING RULE CONTRACT."

### `contributes`

Below `fields:` is a `contributes:` list — the SOC Framework Artifacts schema
fields this modeling rule populates:

```yaml
contributes:
  - Email.Recipient
  - Email.Sender
  - Email.Subject
  - Email.MessageID
```

This is the contract the playbook layer reads from. Add a line here when you
add a new XDM mapping that maps to a Foundation-consumed Artifact field.

---

## Section 3: `correlation_rules`

A **list** — each entry generates one `CorrelationRules/<name>.yml`. The TAP
contract has one entry; CrowdStrike could have multiple (one per detection
class) under the same contract. Each entry has the same structure:

```yaml
correlation_rules:
  - subtype: passthrough               # passthrough | analytics
    fromversion: "6.10.0"
    global_rule_id: 'SOC Proofpoint TAP - Threat Detected'
    name: 'SOC Proofpoint TAP - Threat Detected'
    description: >-
      Multi-line description...
    tags: [SOCFramework, Detection, Email, ...]

    schema_constants:                  # Boilerplate the generator copies verbatim
      rule_id: 0
      alert_category: User Defined
      alert_domain: DOMAIN_SECURITY
      ...

    alert_name: '$alert_name'          # $-vars come from XQL output columns
    alert_description: '$alert_description'

    suppression:                       # Dedup behavior
      enabled: true
      duration: 24 hours
      fields: [GUID]

    pre_alter: |                       # ← WHERE THE LOGIC LIVES
      // The XQL alter chain that produces every column
      // referenced in alert_fields below.

    alert_fields:                      # ← WHERE FIELDS ARE WIRED TO ISSUES
      - {issue_field: vendor, source: vendor, bucket: computed}
      ...

    mitre_defs:                        # MITRE coverage declaration
      TA0001 - Initial Access: [T1566 - Phishing]

    investigation_query_link: ''       # Drilldown XQL (for analyst pivoting)

    contributes:                       # Email/Endpoint/etc. Artifact fields populated
      - Email.Threat.URL
      - Email.Threat.Type
      ...
```

The two parts you'll edit most often are `pre_alter` and `alert_fields`.
Everything else is set-once-and-forget.

### `pre_alter` — the XQL pipeline

Read it as a sequence of `| alter` stages. Each stage either filters, adds
a computed column, or normalizes a value. The contract's pipeline ends with
the **canonical core normalization** block, which every vendor pack must
emit:

```yaml
pre_alter: |
  // Vendor / product (required for SOCProductCategoryMap routing)
  | alter vendor_name = "Proofpoint", product_name = "TAP"

  // Gate filters — drop events the rule shouldn't fire on
  | filter type in ("messages delivered", "clicks permitted")

  // Field extraction — pull values out of JSON blobs, normalize types
  | alter
      threat_ids = arraystring(arraymap(json_extract_array(threatsInfoMap_str, "$."),
                              json_extract_scalar("@element", "$.threatID")), ", ")

  // Username normalization for cross-rule grouping
  | alter recipient_local = replex(to_string(recipient), "@.*$", "")

  // ============================================================
  // CANONICAL CORE NORMALIZATION
  // 29 columns every vendor pack must expose
  // ============================================================
  | alter
      vendor                              = vendor_name,
      product                             = product_name,
      ...
      action_file_sha256                  = proofpointsha256,
      action_local_ip                     = clickip,
      action_remote_ip                    = null
```

**The 29 canonical core columns are non-negotiable.** They feed the
SOC Framework's grouping pivots (12 of them are the canonical grouping
fields), the dashboards, and the Foundation enrichment layer. Don't
remove any; only change what they're populated *from*.

### `alert_fields` — wiring columns to issue fields

Each entry maps a `pre_alter` output column (or a raw dataset field) to a
named XSIAM alert field:

```yaml
alert_fields:
  # bucket: computed = source is a column produced in pre_alter
  - {issue_field: action_file_sha256, source: action_file_sha256, bucket: computed}

  # bucket: raw = source is a raw dataset field, used as-is
  - {issue_field: emailmessageid, source: messageid, bucket: raw}
```

| `bucket` value | What it means |
|---|---|
| `computed` | `source` is a column produced by the `pre_alter` chain |
| `raw` | `source` is a raw dataset field (must be in `raw_schema`) |

The two buckets exist so the generator can validate. `computed` entries are
checked against the `alter` chain; `raw` entries are checked against the
declared `raw_schema`. Mismatches fail the emit.

### Three sub-blocks inside `alert_fields`

The TAP contract organizes its `alert_fields` into commented sub-blocks:

```yaml
alert_fields:

  # === CANONICAL CORE — identical across every vendor pack ===
  # The 29 fields the framework guarantees are populated.
  - {issue_field: vendor, ...}
  - {issue_field: product, ...}
  ...

  # === VENDOR-SPECIFIC TAIL — preserved as shipped ===
  # XSIAM email-class issue fields and TAP-specific surfacing.
  - {issue_field: user_principal, source: user_principal, bucket: computed}
  - {issue_field: action_file_md5, source: proofpointmd5, bucket: computed}
  ...

  # === Legacy proofpointtap* fields — soc-phishing-investigation-1.0.5 ===
  # Remove when old phishing pack is decommissioned from all tenants.
  - {issue_field: proofpointtapcampaignid, source: campaignid, bucket: raw}
  ...
```

When adding a new field, decide which block:

- **Canonical core** — only if you're proposing a framework-wide schema change
  (rare — requires updating every vendor pack)
- **Vendor-specific tail** — most additions go here
- **Legacy** — never. New work shouldn't add legacy fields

---

## How my four edits land — worked example

The grouping-pivot edits I made earlier are a clean walkthrough of the
common edit shape. Here's what I changed and why:

### Edit 1: New alter line in `pre_alter` (before canonical core)

```yaml
| alter recipient_local = replex(to_string(recipient), "@.*$", "")
```

**Why:** Strips `@DOMAIN` from the recipient so we can populate
`actor_effective_username` with the bare SAM (matches CrowdStrike's format).
Inserted before canonical core because canonical core consumes it.

### Edit 2: Three reassignments inside canonical core

```yaml
actor_effective_username = recipient_local,   # was: recipient
action_local_ip          = clickip,           # was: null
action_remote_ip         = null               # was: senderip
```

**Why:**
- `actor_effective_username` now uses the stripped value → cross-rule pivot with CrowdStrike
- `action_local_ip` carries the click IP → endpoint pivot
- `action_remote_ip` was wrong (sender IP is the email server, not a meaningful network target) → cleared

The columns themselves don't change names; only what they're populated from.

### Edit 3: New alter block after canonical core

```yaml
| alter user_principal = recipient
```

**Why:** Adds a parallel UPN pivot. CrowdStrike's `user_principal` carries
`Gunter@SKT.LOCAL`; TAP's `recipient` is the same. Direct match, no
normalization needed. Placed *after* canonical core because `user_principal`
is vendor-specific, not core.

### Edit 4: New `alert_fields` entry

```yaml
- {issue_field: user_principal, source: user_principal, bucket: computed}
```

**Why:** Wires the new `user_principal` column from edit 3 into the
issue field. `bucket: computed` because `user_principal` is now a
column produced by `pre_alter` (not a raw dataset field).

Placed in the vendor-specific tail block, immediately after the section
header.

### What I did NOT change

- `raw_schema` — no new fields referenced; `recipient` and `clickip` were already declared
- `modeling_rule` — XDM unchanged
- `mitre_defs`, `suppression`, `investigation_query_link`, etc. — no semantic change to the rule's identity
- The 29 canonical core column names — still exactly 29

This is the right shape for a "tweak" — narrow `pre_alter` + `alert_fields`
edits, no schema changes, no contract-breaking moves.

---

## Update workflow

1. **Edit the contract YAML** in `schemas/vendors/<vendor>/<file>.yaml`
2. **Validate** — catches typos, missing fields, malformed entries:

   ```bash
   python3 tools/generate_vendor_content.py validate \
     --mapping schemas/vendors/proofpoint-tap/proofpoint-tap-threats.yaml
   ```

3. **Roundtrip to see the diff** before committing:

   ```bash
   python3 tools/generate_vendor_content.py roundtrip \
     --mapping schemas/vendors/proofpoint-tap/proofpoint-tap-threats.yaml \
     --pack-root Packs/SocFrameworkProofPointTap
   ```

   This emits to a temp dir and diffs against your shipped pack. Read the
   diff carefully — it shows you exactly what the rule file will become.

4. **Emit for real** when the diff is right:

   ```bash
   python3 tools/generate_vendor_content.py emit \
     --mapping schemas/vendors/proofpoint-tap/proofpoint-tap-threats.yaml \
     --pack-root Packs/SocFrameworkProofPointTap
   ```

5. **Verify the rule was regenerated:**

   ```bash
   grep -E "your-edit-marker" Packs/SocFrameworkProofPointTap/CorrelationRules/*.yml
   ```

6. **Push and test** via the daily flow:

   ```bash
   python3 tools/check_contribution.py
   ```

---

## Quick reference: where things go

| Want to... | Edit which section |
|---|---|
| Add a new dataset field reference | `raw_schema` (declare) AND wherever you reference it |
| Add an XDM mapping for analytics | `modeling_rule.fields` |
| Change what an alert field is populated from | `correlation_rules[].pre_alter` (the alter chain) |
| Add a new alert field | `correlation_rules[].alert_fields` (and `pre_alter` if computed) |
| Change rule firing conditions | `correlation_rules[].pre_alter` filter clauses |
| Change MITRE coverage | `correlation_rules[].mitre_defs` |
| Change dedup window | `correlation_rules[].suppression` |
| Add a new correlation rule for the same data source | New entry in `correlation_rules` list |

## What NOT to edit

- `schema_constants` — boilerplate, never change unless the framework changes
- `rule_id: 0` inside `schema_constants` — required, never change
- `fromversion` — change only as part of a coordinated framework version bump
- `directory_name` and `modeling_rule_id` — pack-bundle-installer references these; renaming breaks installs

## Things that will silently break

- Editing the generated `Packs/<pack>/CorrelationRules/<name>.yml` directly
  — the next emit overwrites it
- Adding a column reference in `alert_fields` without declaring it in
  `pre_alter` (computed) or `raw_schema` (raw) — emits with a broken
  reference
- Mismatched casing between `pre_alter` output column names and
  `alert_fields` `source:` values
- `yaml.dump` anywhere in your edit workflow — reorders keys, corrupts
  Upon Trigger semantics. Use `str_replace` on raw text, or hand-edit
  in a YAML-aware editor that preserves order
