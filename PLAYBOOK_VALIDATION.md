# XSIAM SOC Framework — Playbook Integrity Validator

Keeps your SOC Framework playbook repo from going stale between sprints
and before PoV handoffs.

---

## What It Checks

| Check | What breaks silently without it |
|---|---|
| **Integration References** | Playbook calls a brand (e.g. `Cortex XDR - IR`) that has no configured instance in `xsoar_config.json` → task silently skips or errors at runtime |
| **Orphaned Playbooks** | A sub-playbook is renamed/deleted but still referenced; or a new playbook is created but never wired in |
| **Missing Lists** | `GetList` / `SetList` tasks reference a list that was never seeded in config → automation falls back to empty or crashes |
| **Sub-Playbook Chains** | A playbook calls a sub-playbook by name that doesn't exist in the repo; also catches circular call loops |

---

## Setup

```bash
# 1 – install Python deps (once)
pip install pyyaml pre-commit

# 2 – install the git pre-commit hook
pre-commit install

# 3 – run manually at any time
python validate_playbooks.py
```

That's it. From now on every `git commit` that touches a `.yml` or
`xsoar_config.json` will run the checks automatically.

---

## CLI Reference

```
python validate_playbooks.py [OPTIONS]

Options:
  --root PATH      Repo root (default: current directory)
  --config PATH    Path to xsoar_config.json
                   (default: <root>/xsoar_config.json)
  --strict         Exit 1 on warnings as well as errors
  --json           Emit machine-readable JSON (for CI artifact upload)
  --verbose        Include INFO-level findings in console output
```

### Examples

```bash
# Standard run from repo root
python validate_playbooks.py

# Strict mode — useful for main branch gate
python validate_playbooks.py --strict

# Machine-readable output for dashboards / JIRA integrations
python validate_playbooks.py --json > report.json

# Point at a different config (e.g. production vs PoV config)
python validate_playbooks.py --config configs/pov_xsoar_config.json
```

---

## Output Legend

```
  ✓  CHECK_NAME — no issues
  ⚠  WARN  CHECK_NAME
        ● Playbook Name  →  detail message
  ✗  ERROR  CHECK_NAME
        ● Playbook Name  →  detail message
```

Exit codes: `0` = pass, `1` = errors found (or warnings in `--strict` mode).

---

## GitHub Actions

The workflow at `.github/workflows/playbook-validation.yml` runs on every
push/PR that changes a `.yml` or `xsoar_config.json`. It:

1. Runs the validator (human-readable output in the Actions log)
2. Emits a `playbook-validation-report.json` artifact (retained 30 days)
3. On PR failure, posts a comment listing all errors and warnings

---

## xsoar_config.json Expected Shape

```json
{
  "integrations": [
    {
      "brand": "Cortex XDR - IR",
      "instance_name": "xdr_pov",
      "params": { ... }
    },
    {
      "brand": "Active Directory Query v2",
      "instance_name": "ad_pov",
      "params": { ... }
    }
  ],
  "lists": [
    { "name": "UniversalCommand_Config", "value": "shadow" },
    { "name": "AllowedHosts",             "value": "..." }
  ]
}
```

The validator reads `brand` from each integration entry and `name` from
each list entry. All other fields are ignored.

---

## Declaring Entry Points

Playbooks that are intentionally top-level (not sub-playbooks) will
trigger the orphan warning unless you mark them. Two ways:

**Naming convention (preferred):**
```
EP_NIST_IR.yml          # EP_ prefix → auto-detected as entry point
EP_Phishing.yml
```

**YAML field:**
```yaml
# inside your playbook YAML
name: My Custom Entry Point
entrypoint: true
tasks: ...
```

---

## Shadow Mode Alignment

The Universal Command in each playbook defaults to **Shadow Mode** —
containment, eradication, and recovery actions are logged to warroom +
dataset but vendor commands are **not executed** until PS flips to
Execute Mode.

This validator ensures that even in Shadow Mode, every referenced
integration, list, and sub-playbook is resolvable — so the flip to
Execute Mode is a single config change, not a debug session.

```
Shadow Mode  →  everything resolves, nothing executes
Execute Mode →  everything resolves, everything executes
```

---

## Tips

- Run `--config configs/prod_xsoar_config.json` before PS handoff to
  validate against the production integration inventory, not just the
  PoV config.
- Add `--strict` to your main branch protection rule once the repo
  stabilises.
- The JSON output can be ingested into XSIAM datasets to track playbook
  health over the PoV window as a VD3 / operational efficiency metric.
