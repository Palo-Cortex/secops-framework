# Adding Descriptions to Contract Schemas

The two contract schemas (`SOCFrameworkPhaseContract_V3.yaml` and
`SOCFrameworkNormalizeMap_V3.yaml`) drive the most important docs in the
site, but their entries currently have no `description:` fields. Adding them
is the highest-value docs work you can do.

The generator already supports `description:` on any record-list entry —
when present, a "description" column auto-appears in the rendered table.
No code change needed; just edit the YAML.

## Where to add descriptions

### `SOCFrameworkPhaseContract_V3.yaml` — `writes:` block (~42 entries)

Each entry currently looks like:

```yaml
writes:
  - phase: analysis
    target: Analysis.verdict
    type: string
    init: ""
```

Add a `description:` field explaining what the field is for and what it
holds:

```yaml
writes:
  - phase: analysis
    target: Analysis.verdict
    type: string
    init: ""
    description: >-
      Final analyst-verifiable verdict for the alert. One of:
      malicious / benign / suspicious / unknown. Containment, eradication,
      and recovery all gate on this value.
```

Same pattern for `writes_by_category:` (81 entries) — these are the
per-category outputs. Worth describing because the category-specific
fields (Endpoint vs Email vs Identity) are where the contract differs
between detection types.

### `SOCFrameworkPhaseContract_V3.yaml` — `reads_from_phases:` (~21 entries)

```yaml
reads_from_phases:
  - phase: containment
    from_phase: analysis
    source: Analysis.response_recommended
    description: Gate for whether to invoke any containment actions at all
```

These describe the cross-phase contract — what each phase needs from the
phase before it. Useful for anyone debugging why a phase didn't fire as
expected.

### `SOCFrameworkPhaseContract_V3.yaml` — `routing:` (12 entries)

```yaml
routing:
  - phase: analysis
    category: email
    sub_playbook: SOC_Email_Analysis_V3
    description: >-
      Email path through Analysis. Reads SOCFramework.Artifacts.Email.*,
      writes verdict + threat artifacts to Analysis.*.
```

12 entries covers all phase × category combinations. Quick to fill in.

### `SOCFrameworkNormalizeMap_V3.yaml` — `mappings:` (~101 entries)

The biggest block but also the most repetitive — many of these are
straightforward passthroughs that don't need explanation:

```yaml
- { category: endpoint, target: Endpoint.hostname, issue_field: agent_hostname, shape: flat }
```

Focus descriptions on the non-obvious ones — array-flattening, computed
fields, anything where the mapping isn't 1:1:

```yaml
- category: endpoint
  target: Artifacts.File
  issue_field: filesha256.[0]
  shape: structured
  description: >-
    XSOAR DT array index — the issue_field is array-typed; we take the
    first element only. Other hashes are surfaced via Artifacts.Files (plural).
```

## Order of value

Roughly in priority order:

1. **`writes:` and `writes_by_category:`** — these are the contract surface
   that downstream phases read. Highest value to document.
2. **`reads_from_phases:`** — cross-phase contract debugging.
3. **`routing:`** — short list, quick win.
4. **`mappings:`** — only the non-obvious ones. Skip the trivial passthroughs.
5. **`stamps:` and `mirrors:`** — tiny blocks (~6 each), do once.

## How to know it worked

After editing, run:

```bash
python tools/generate_schema_docs.py
git diff docs/
```

Each entry you added a description to gets a populated cell in the
"description" column of the relevant table. Empty cells stay empty — no
need to backfill all at once.
