# Tool: test_playbooks.py + playbook_simulator.py

**Location:** `tools/test_playbooks.py` · `tools/playbook_simulator.py`
**Fixtures:** `tools/fixtures/`
**Added:** 2026-03-20

---

## Purpose

Static execution engine and test runner for SOC Framework NIST IR playbooks.
Parses playbook YAML, walks the task graph against injected context, evaluates
conditions, simulates known script behavior, and asserts on output context keys
and execution paths — without needing a live XSIAM tenant.

Sits in the pre-upload pipeline **after `fix_errors.py`** and **before upload**.

---

## Pipeline Position

```
pack_prep.py → fix_errors.py → test_playbooks.py → upload_package.sh
```

Recommended invocation before upload:

```bash
python3 tools/test_playbooks.py --category all --suite all
```

Exit code `0` = all pass. Exit code `1` = failures. CI-safe.

---

## Quick Start

```bash
# All tests across all categories
python3 tools/test_playbooks.py --category all --suite all

# Email only — unit + e2e
python3 tools/test_playbooks.py --category email --suite all --verbose

# Single playbook
python3 tools/test_playbooks.py --playbook SOC_Email_Verdict_Resolution_V3

# Non-default playbook directory
python3 tools/test_playbooks.py \
  --pb-dir Packs/soc-framework-nist-ir/Playbooks \
  --fixtures tools/fixtures \
  --category all --suite all
```

---

## Test Coverage (69 tests)

| Category | Suite | Count | Scenarios |
|---|---|---|---|
| Email | unit | 25 | Signal Char · Exposure · IOC Enrichment · Forensics · Verdict · Containment · Eradication · Recovery |
| Email | e2e | 16 | Turla Carbon chain · File Malware · False Positive · Broad Campaign / HVU |
| Endpoint | unit | 16 | Signal Char · Verdict · Compromise Evaluation · Containment · Eradication · Recovery · Spread |
| Identity | unit | 12 | Analysis (4 tactics) · Containment · Eradication (3 paths) · Recovery (3 paths) |

---

## Playbook Bugs Found During Test Build

These real bugs were surfaced by the harness and fixed in the playbook files:

### `SOC_Email_Verdict_Resolution_V3`

**Task 9 — DBot Confirms Malicious?**
Condition body had both checks in a single inner OR group:
```
(source_verdict == "malicious") OR (verdict == "benign")
```
Fires on ANY malicious source verdict regardless of current verdict — overwriting
every malicious path with suspicious/medium. Fixed: split into two AND groups so
it only fires when `source_verdict=malicious AND verdict=benign` (the intended
upgrade path from a benign classification).

**Task 14 — Recommend Action?**
All four action labels (`escalate_IR`, `search_and_purge`, `retract_message`,
`quarantine`) had their conditions as single OR groups. `escalate_IR` fired on
`verdict==malicious OR HVU==True` — meaning every malicious verdict escalated to
IR regardless of HVU status. Fixed: each label now uses separate AND groups so
conditions are properly combined:
- `escalate_IR`: `verdict=malicious AND HVU=true`
- `search_and_purge`: `verdict=malicious AND clicks>0`
- `retract_message`: `verdict=malicious AND delivered>0 AND clicks==0`
- `quarantine`: `verdict=malicious AND delivered==0`

### `SOC_Identity_Containment_V3`

**Tasks 157 and 159 — Disable Account? / Clear User Sessions?**
Both condition blocks have `conditions: null` (empty). Nexttasks are wired:
`Yes → soc-disable-user` / `Yes → soc-clear-sessions`, but the conditions that
would evaluate `inputs.UserContainment` and `inputs.ClearUserSessions` were never
authored. The tasks always route to `#default#` (No → Done), meaning the
Universal Commands are **never executed automatically**.

**Fix needed:** Add condition bodies:
- t157: `isEqualString inputs.UserContainment "true"`
- t159: `isEqualString inputs.ClearUserSessions "true"`

---

## Simulator Capabilities

**Scripts mocked:**
`SetAndHandleEmpty`, `SetField`, `SetMultipleValues` (with `parent` namespace),
`AddDBotScoreToContext`, `GetIndicatorDBotScoreFromCache`

**Condition operators:**
`isEqualString`, `isNotEqualString`, `isEqualNumber`, `isNotEmpty`, `isEmpty`,
`isExists`, `isTrue`, `isFalse`, `containsGeneral`, `containsString`, `contains`,
`in`, `notIn`, `match` (regex), `greaterThan`, `greaterThanOrEqual`, `lessThan`,
`lessThanOrEqual`

**Transformers:**
`join`, `count`, `uniq`, `substringFrom`, `toLowerCase`, `toUpperCase`,
`MapRangeValues`, `if-then-else` (lte/gte), `getField`

**Routing:**
- Outer condition list = AND (all groups must pass)
- Inner condition list = OR (any condition in group passes the group)
- YAML boolean labels (`true`/`false`) mapped to string nexttask keys
- Playbook input pre-population from input definitions
- Sub-playbook recursion or mock injection via `sub_mocks`
- Universal Command (SOCCommandWrapper) mock injection via `uc_mocks`
- Complex value spec with flat-key fallback for dotted accessor paths

**What it cannot simulate:**
- Live integration API calls
- XSIAM-native runtime context (case scoring, asset enrichment populated by platform)
- Scripts not in the mock library (warns and skips, does not fail)
- The dedup playbook or Foundation layer (test those separately)

---

## Writing Fixtures

Fixtures are JSON arrays in `tools/fixtures/`. Filename pattern: `{category}_{suite}.json`.
Auto-discovered by the runner — no registration required.

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
    "SOC Analysis Evaluation_V3": {
      "Analysis.verdict": "malicious"
    }
  },

  "assertions": [
    { "type": "context_key_equals",  "target": "Analysis.Email.signal_type", "expected": "url_phish" },
    { "type": "context_key_exists",  "target": "Analysis.Email.source_verdict" },
    { "type": "context_key_absent",  "target": "SomeKey.That.Should.Not.Exist" },
    { "type": "branch_taken",        "target": "2",  "expected": "URL" },
    { "type": "task_executed",       "target": "3" },
    { "type": "task_not_executed",   "target": "7" }
  ]
}
```

### Key input patterns

| What you want | How to inject |
|---|---|
| Playbook input `inputs.ThreatType` | `"inputs.ThreatType": "url"` |
| Context key with `${...}` reference | Use the resolved key directly: `"Analysis.Email.source_verdict": "malicious"` |
| Alert field `alert.senderip` | `"alert.senderip": "198.51.100.45"` |
| Nested alert dict (accessor pattern) | `"alert": {"proofpointtapcampaignid": "abc123"}` |
| Flat dotted accessor fallback | Both `"alert.field": "val"` and `"alert": {"field": "val"}` work |
| XSIAM list | `"lists.SOCFWHighValueUsers": "ceo@corp.com,cfo@corp.com"` |
| Eradication.attempted (bool gate) | `"Eradication.attempted": "true"` (string, not Python bool) |

---

## Backlog (BL-005)

- [ ] Fix `SOC_Identity_Containment_V3` tasks 157/159 empty condition bodies
- [ ] Add Network/DNS category fixtures once playbooks are built
- [ ] Add SaaS category fixtures
- [ ] E2E Identity scenario (Okta credential stuffing chain)
- [ ] E2E Endpoint scenario (CrowdStrike → lateral movement chain)
- [ ] Foundation / Dedup unit tests (separate fixture file)
- [ ] `--tag` filter flag (run only `happy_path` or `playbook_bug` tagged tests)
- [ ] JUnit XML output flag for CI pipeline integration
