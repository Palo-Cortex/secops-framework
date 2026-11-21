# Engineering practices

How changes to this repo are kept small, readable and tested, so a change can be reviewed properly even when changes arrive faster than people can read them.

## Why these rules exist

A pull request is only as safe as its review. When a lot of code changes quickly, understanding it becomes the slow step: reviewers skim, large diffs get approved on trust, and untested behaviour reaches tenants. So the rule underneath all the others is: don't merge code faster than someone can understand it.

The rules below do that in three ways. They keep each change small enough to hold in your head. They let a person review the intent (the test, the contract, the evidence) instead of every line. And they move every check a tool can do to a tool, so a person's attention goes to the code that can do damage. Deleting code that nobody uses counts as progress.

## Rules for a change

--8<-- "CONTRIBUTING.md:rules"

## Tests first

The failing test is the spec a reviewer reads. A 20-line test that says "given this event, the result should be X" is far quicker to check than the code that produces X, and because the test exists before the code, it can't simply mirror the code's mistakes.

| Kind of change | Tests first? |
|---|---|
| A bug fix | Always. Reproduce the bug as a test that fails on `main`, then fix it |
| A change in what a script or the universal command does | Yes. Write the test, then the change |
| Finding out what a tenant does | No. Explore first, then lock what you found into a test |
| Behaviour only a tenant replay can prove (playbook conditions, grouping, dashboards) | No. The replay and its expected results are the test |

Two habits make the tests worth having:

- **Test the unhappy paths on purpose:** empty input, a missing field, a vendor error, a list that can't be read. Happy paths usually work; failures hide in the rest.
- **Keep fixtures true to the vendor.** A test and the code can agree with each other and both be wrong about what the vendor sends. Build fixtures from real event shapes, never from what the code expects.

## Test data

Use only values that can never belong to anyone:

| Kind | Use |
|---|---|
| Domains | `example.com`, `example.net`, `example.org`, or any name under `.example`, `.test`, `.invalid` ([RFC 2606](https://www.rfc-editor.org/rfc/rfc2606)) or `.local` |
| IPv4 addresses | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` ([RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)), or private space: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| IPv6 addresses | `2001:db8::/32` ([RFC 3849](https://www.rfc-editor.org/rfc/rfc3849)) |
| Users, hosts, mailboxes | Made-up names on those domains: `analyst@example.com`, `host-01.example` |

No customer names, tenant names, case or issue ids, keys or collector URLs, anywhere in code, tests, fixtures, commits or pull requests. Describe a customer issue by what happened, never by who it happened to.

## High-risk paths

These decide whether something acts on a customer's systems or closes work. A change to any of them is read line by line by a person, not only by tools:

| Path | Why it is high risk |
|---|---|
| `Packs/soc-optimization-unified/Scripts/SOCCommandWrapper/` | The universal command: every vendor action goes through it |
| `Packs/soc-optimization-unified/Lists/SOCFrameworkActions_V3/`, `policies/shadow_mode_policy.json` | Which actions run live and which stay in Shadow Mode |
| `Packs/soc-optimization-unified/Scripts/SOCFWConfig/` | Tenant settings, including the switches above |
| `Packs/soc-optimization-unified/Scripts/SOCFWPhaseExecutor/`, `SOCFWEmergencyResponse/` | Dispatch of changing actions |
| `Packs/soc-framework-nist-ir-ai/Scripts/SOCFWCloseDecision/` | Whether an issue closes without a person |
| Correlation rules (`Packs/*/CorrelationRules/`, `schemas/vendors/`) | What becomes an issue, and which issue fields it writes |
| `tools/check_contribution.py`, `.github/workflows/` | The gates themselves |

## Review

Every pull request gets one automated review pass before a person looks at it. The reviewer sees only the diff and [`.github/review-checklist.md`](https://github.com/Palo-Cortex/secops-framework/blob/main/.github/review-checklist.md), never the reasoning of whoever wrote the change, so it reads the change cold.

| Rule | Why |
|---|---|
| One reviewer, one checklist. A new concern is a new checklist line, not a new reviewer | Every reviewer is one more thing to maintain and understand |
| When a tool can check an item reliably (a ruff rule, a gate in `check_contribution.py`, a CI job), the item moves to the tool and comes off the checklist | A rule checks every time; a reviewer checks when it notices. The checklist should get shorter over time |
| An item whose comments are usually dismissed is cut, or turned into a rule | Noise teaches people to ignore the reviewer |
| Docs and dashboards: comments only. High-risk paths: a person reads every line as well | Review effort follows the damage a mistake can do |

## Conventions

The rules people need every day, in one place. The reasons behind refactoring and lean settings are in [Refactoring and keeping the framework lean](refactoring.md); how pages are written is in [Writing documentation](writing-docs.md).

| Area | Convention |
|---|---|
| Branches | One concern per branch, from current `main`. Bring a branch up to date with `git rebase origin/main`, not the GitHub "Update branch" button |
| Commits | One logical step per commit, made before you start the next thing. The message says what changed and why; customer issues are described by what happened, not who |
| Merges | Squash. `[skip release]` in the subject when the change should not cut a release; cut the release once a batch is gated and tested, rather than leaving merged work unreleased |
| Before a pull request | Run `check_contribution.py` against a lab tenant, then run the change on that tenant: the happy path, the unhappy paths, a regression check on what already works, and the tenant's own traffic as noise |
| Comments | Say what a block does and why a non-obvious choice was made. No change history or version notes in code: that is git's job |
| Generated content | Never edit it by hand. A list emitted from `schemas/` is changed in the schema and re-emitted |
| Playbooks | End with a `Done` title task. Changing actions go through the universal command and ship in Shadow Mode |
| Correlation rules | Never write into an issue field the platform owns; `check_issue_field_targets.py` fails the gate if one does |
| Names | New components use the `SOCFW` prefix and no `_V3`. Propose a new name, key, actor or list before building it |

## Lint

`ruff.toml` at the repo root holds the settings: PEP 8 naming and layout, likely bugs, simpler forms, and limits on function size and complexity. Run it on the files you changed:

```
ruff check $(git diff --name-only --diff-filter=ACMR origin/main...HEAD -- '*.py')
```

**Expected:** no findings in lines you added. Code already on `main` does not meet these limits yet, so `ruff check .` on the whole repo reports existing findings, and the repo-wide run is not a gate. A file you touch should not end up with more findings than it has on `main`.

## What is enforced, and what is planned

| Practice | Checked by today | Planned |
|---|---|---|
| Unit tests pass | PR gate and `check_contribution` (`run_pack_tests.py`) | |
| Lint | Review: `ruff check` on the changed files | A CI check that a changed file has no more findings than on `main` |
| Test data | Review | A scan that flags any domain, IP address or email outside the ranges above, replacing the customer-identifier scan |
| Tests first for fixes | Review: the pull request shows the failing run | A CI check that a fix's new tests fail on `main` |
| Automated review | Run by hand against the checklist | Run on every pull request |
