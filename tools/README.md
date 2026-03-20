# SOC Framework Playbook Test Harness

Static execution engine and test runner for XSIAM SOC Framework playbooks.

## What it does

Parses playbook YAML, walks the task graph against a given input context, evaluates
conditions, simulates known script behavior, and asserts on output context keys and
execution paths — without needing a live XSIAM tenant.

## Directory layout

```
tools/
  test_playbooks.py        # CLI test runner — run this
  playbook_simulator.py    # Static execution engine (imported by runner)
  fixtures/
    email_unit.json        # Per-playbook unit tests for all Email playbooks
    email_e2e.json         # End-to-end scenarios: Turla Carbon, FP, broad campaign
    endpoint_unit.json     # Per-playbook unit tests for Endpoint playbooks
    identity_unit.json     # Per-playbook unit tests for Identity playbooks
```

## Quick start

```bash
# From repo root — run all email tests
python3 tools/test_playbooks.py --category email --suite all

# Run only e2e (includes Turla Carbon scenario chain)
python3 tools/test_playbooks.py --category email --suite e2e --verbose

# Run a single playbook
python3 tools/test_playbooks.py --playbook SOC_Email_Signal_Characterization_V3 --verbose

# Run everything
python3 tools/test_playbooks.py --category all --suite all

# Point at a different playbook directory
python3 tools/test_playbooks.py --pb-dir /path/to/Playbooks --category email
```

## CLI options

| Flag | Default | Description |
|---|---|---|
| `--category` | `all` | `email` / `endpoint` / `identity` / `all` |
| `--suite` | `all` | `unit` / `e2e` / `all` |
| `--playbook` | — | Run tests for a specific playbook name only |
| `--pb-dir` | `Packs/soc-framework-nist-ir/Playbooks` | Path to playbook YAML files |
| `--fixtures` | `tools/fixtures` | Path to fixtures directory |
| `--verbose` | off | Print warnings and output context for each test |

Exit code: `0` = all pass, `1` = failures present. CI-safe.

## Writing test fixtures

Fixtures are JSON arrays. Each test case:

```json
{
  "name": "Human-readable test name",
  "playbook": "SOC_Email_Signal_Characterization_V3",
  "category": "email",
  "suite": "unit",
  "tags": ["happy_path"],

  "context_inputs": {
    "SOCFramework.Artifacts.Email.ThreatType": "url",
    "alert.senderip": "198.51.100.45"
  },

  "uc_mocks": {
    "soc-get-email-events": {
      "UC.Email.Events.clicks_permitted": ["click1"]
    }
  },

  "sub_mocks": {
    "SOC_Email_Exposure_Evaluation_V3": {
      "Email.Exposure.level": "clicked"
    }
  },

  "assertions": [
    { "type": "context_key_equals",  "target": "Analysis.Email.signal_type", "expected": "url_phish" },
    { "type": "context_key_exists",  "target": "Analysis.Email.source_verdict" },
    { "type": "context_key_absent",  "target": "SomeKey.That.Should.Not.Exist" },
    { "type": "branch_taken",        "target": "2", "expected": "URL" },
    { "type": "task_executed",       "target": "3" },
    { "type": "task_not_executed",   "target": "7" }
  ]
}
```

### context_inputs

Flat key/value dict. These are injected into the simulator context before
playbook execution starts. Use the same key names you'd see in XSIAM context
(e.g. `inputs.ThreatType`, `SOCFramework.Artifacts.Email.ThreatType`,
`alert.username`).

### uc_mocks

Maps Universal Command action names (from `SOCFrameworkActions_V3`) to the
context keys they should write. The simulator calls SOCCommandWrapper, looks up
the action, finds the mock, and writes those keys into context.

```json
"uc_mocks": {
  "soc-isolate-endpoint": { "Containment.isolated_hosts": ["host1"] },
  "soc-reset-password":   { "Eradication.credentials_reset": true }
}
```

### sub_mocks

Maps sub-playbook names to context writes. Use this to stub out a dependent
playbook without recursing into it. If a sub-playbook is called but has no
mock, the simulator will try to recurse into it (and look it up from `--pb-dir`).

### assertion types

| Type | target | expected | Notes |
|---|---|---|---|
| `context_key_equals` | key path | value | Exact match after execution |
| `context_key_exists` | key path | — | Key is present (any value) |
| `context_key_absent` | key path | — | Key must not be set |
| `context_key_not_equals` | key path | value | Key exists but value differs |
| `branch_taken` | task id | label string | Which condition branch fired |
| `task_executed` | task id | — | Task appeared in execution trace |
| `task_not_executed` | task id | — | Task did NOT appear in trace |

## What the simulator can and cannot do

### Can simulate
- `SetAndHandleEmpty` / `SetField` → context key writes
- `AddDBotScoreToContext` → DBotScore context stub
- `GetIndicatorDBotScoreFromCache` → reads DBotScore stub
- All condition operators: `containsGeneral`, `isEqualString`, `isNotEmpty`,
  `isFalse`, `inList`, `greaterThan`, `isExists`
- Transformers: `join`, `count`, `uniq`, `substringFrom`, `MapRangeValues`,
  `if-then-else` (lte/gte)
- Sub-playbook recursion (or mock injection)
- Universal Command (SOCCommandWrapper) via uc_mocks

### Cannot simulate
- Live integration commands (actual API calls to CrowdStrike, Okta, etc.)
- XSIAM-native context variables populated by the platform at runtime
  (e.g. enriched asset data, case scoring)
- Scripts not in the mock library (warns and skips — does not fail)
- The dedup playbook or Foundation layer (test those separately)

## Adding a new category (e.g. Network)

1. Create `tools/fixtures/network_unit.json` with your test cases
2. Set `"category": "network"` in each test case
3. Run: `python3 tools/test_playbooks.py --category network`

The runner auto-discovers fixture files by scanning the fixtures directory —
no registration needed.

## Known limitations / backlog

- `if-then-else` transformer only supports `lte` and `gte` operators
- Complex filter expressions on `complex` value specs are simplified
  (existence-check only)
- No parallel branch tracking — queue-based traversal visits one branch at a time
- No timer or timeout simulation
- `inList` against `${lists.*}` requires the list value to be injected as a
  comma-separated string in context_inputs
