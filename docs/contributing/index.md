# Contributing

How a change gets from your editor to a tenant: author it, run the gate, open a pull request, merge, release. Every step is a command in `tools/`, and the gate tells you which one to run when it fails.

## The flow

1. **Branch** from `main`, one concern per branch. A change that spans two packs is still one branch and one PR; per-pack commits are good hygiene, not a rule.
2. **Author** the change. Generated content is never edited by hand: a list emitted from a schema under `schemas/` is changed by editing the schema and re-emitting; a page with a generated banner is changed by editing what it is generated from.
3. **Gate** with `python3 tools/check_contribution.py` from the repo root. It runs, per changed pack: contribution normalization, correlation-rule preflight, playbook condition lint, `pack_prep` (rule ids, JSON validity, dependency versions, manifest preflight, `demisto-sdk validate`), `check_contracts`, and the docs coverage check; then framework-wide: `validate_shadow_mode --all` and `prep_docs --check`; then it uploads the pack to the tenant in `.env` and verifies the content landed. A failure prints what to fix and the command to re-run.
4. **Test on the tenant**, happy and unhappy paths, before opening the PR. The gate proves the content is well-formed; only a run proves it works.
5. **Pull request** against `main`, with exactly one of `version:patch`, `version:minor`, `version:major` when the change should cut a release, and `[skip release]` in the merge commit subject when it should not (the usual case while a release is being collected). No label means patch.
6. **Merge** by squash or rebase; merge commits are rejected. Merging to `main` with a version label cuts an immutable GitHub Release per changed pack and rebuilds `pack_catalog.json`; tenants install releases through the SOC Framework Pack Manager.

## What is gated, and why

| Gate | Fails when | Why it exists |
|---|---|---|
| `normalize_contribution.py` | A tenant export carries `_copy` suffixes, UUID ids, a non-standard version | Exports are not pack files until normalized |
| `correlation_rule_preflight.py` | A rule would be rejected by the platform with an uninformative error | The platform's `101704` says nothing; this says which field |
| `pack_prep.py` → `demisto-sdk validate --marketplace marketplacev2` | Content breaks the SDK schema | The default marketplace silently skips XSIAM content |
| `check_contracts.py` | A Workflow playbook calls `setIssue`/`setIncident`, or writes another layer's namespace | Layer contracts are what keep lifecycles vendor-generic |
| `check_readme_coverage.py` | A pack adds a script, list or list key that no page or README mentions | Capabilities nobody can find do not exist |
| `validate_shadow_mode.py --all` | A changing action ships live outside the documented policy | Shadow Mode is the safety contract |
| `prep_docs.py --check` | A generated page is stale | The site is built from the repo; drift is a lie on the site |

The CI PR gate repeats the scan for customer data, the version-label check, JSON integrity, shadow mode and SDK validation. It does not deploy anywhere: content reaches a tenant from your gate run, and production from a release.

## Describing contract entries

The lifecycle contracts under `schemas/soc-framework/` (`SOCFrameworkPhaseContract_V3`, the per-lifecycle normalize maps) render into the site's contract pages. Any entry may carry a `description:`; when present it appears as a column in the rendered table. Adding descriptions to the entries that lack them is the most useful small docs change there is, and needs no generator change: edit the YAML, re-emit, run `prep_docs.py`.

## Pages in this section

- [Tools reference](tools.md): every script under `tools/`, generated from its docstring.
- [Editing vendor contracts](editing-vendor-contracts.md): the per-data-source YAML a vendor pack is generated from.
- [CONTRIBUTING.md](https://github.com/Palo-Cortex/secops-framework/blob/main/CONTRIBUTING.md) on GitHub: contributing content exported from a tenant through the GitHub web UI, with no terminal.
