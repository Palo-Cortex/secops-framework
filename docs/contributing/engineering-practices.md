# Engineering practices

How changes to this repo are kept small, readable and tested, so a change can be reviewed properly even when changes arrive faster than people can read them.

## Why these rules exist

A pull request is only as safe as its review. When a lot of code changes quickly, the review becomes the limit: reviewers skim, large diffs get approved on trust, and untested behaviour reaches tenants. Every rule here does one of two things. It keeps each change small enough that a person can hold it in their head, or it moves a check from a person to a tool so the person's attention goes where only a person can judge.

## Rules for a change

--8<-- "CONTRIBUTING.md:rules"


## Test data

Use only values that can never belong to anyone:

| Kind | Use |
|---|---|
| Domains | `example.com`, `example.net`, `example.org`, or any name under `.example`, `.test` or `.invalid` ([RFC 2606](https://www.rfc-editor.org/rfc/rfc2606)) |
| IPv4 addresses | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` ([RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)) |
| IPv6 addresses | `2001:db8::/32` ([RFC 3849](https://www.rfc-editor.org/rfc/rfc3849)) |
| Users, hosts, mailboxes | Made-up names on those domains: `analyst@example.com`, `host-01.example` |

No customer names, tenant names, case or issue ids, keys or collector URLs, anywhere in code, tests, fixtures, commits or pull requests.

## High-risk paths

These decide whether something acts on a customer's systems or closes work. A change to any of them is read line by line by a person, not only by tools:

| Path | Why it is high risk |
|---|---|
| `Packs/soc-optimization-unified/Scripts/SOCCommandWrapper/` | The universal command: every vendor action goes through it |
| `Packs/soc-optimization-unified/Lists/SOCFrameworkActions_V3/`, `policies/shadow_mode_policy.json` | Which actions run live and which stay in Shadow Mode |
| `Packs/soc-optimization-unified/Scripts/SOCFWConfig/` | Tenant settings, including the switches above |
| `Packs/soc-optimization-unified/Scripts/SOCFWPhaseExecutor/`, `SOCFWEmergencyResponse/` | Dispatch of changing actions |
| `Packs/soc-framework-nist-ir-ai/Scripts/SOCFWCloseDecision/` | Whether an issue closes without a person |
| `tools/check_contribution.py`, `.github/workflows/` | The gates themselves |

## Automated review

Each pull request gets one automated review pass against a written checklist, before a person looks at it. The checklist starts with the rules above. When a tool starts catching something reliably (a ruff rule, a gate in `check_contribution.py`, a CI job), that item comes off the checklist. The aim is a checklist that shrinks over time, with people spending their review on design and on the high-risk paths.

## Lint

`ruff.toml` at the repo root holds the settings. Run it on the files you changed:

```
ruff check $(git diff --name-only --diff-filter=ACMR origin/main...HEAD -- '*.py')
```

**Expected:** no findings in lines you added. Code already on `main` does not meet these limits yet, so `ruff check .` on the whole repo reports existing findings, and the repo-wide run is not a gate. A file you touch should not end up with more findings than it has on `main`.
