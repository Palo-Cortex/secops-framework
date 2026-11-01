# Contributing to the SOC Framework

Two ways in. If you work in the repo with a terminal, read [Contributing](https://palo-cortex.github.io/secops-framework/contributing/) on the site: branch, gate, pull request, merge, release. If you built content on an XSIAM tenant and want it in the framework without using git, this page is for you: everything happens in the GitHub web UI.

## Before you start

- A GitHub account with access to this repository.
- Your content exported from the XSIAM tenant.
- A few minutes to fill in the pull request description.

## 1. Export your content from XSIAM

| What you built | Where to export it |
|---|---|
| Playbook | Playbooks → open the playbook → Export → Download YAML |
| Script | Scripts → select the script → Export |
| List | Settings → Lists → select the list → Download JSON |
| Correlation rule | Correlation Rules → select the rule → Export YAML |
| Modeling rule | Modeling Rules → select the rule → Export YAML |
| Dashboard | Dashboards → select the dashboard → Export |
| Layout | Case Management → Layouts → select the layout → Export |
| Incident field | Case Management → Fields → select the field → Export |

The export carries tenant artifacts: version numbers, ids, `_copy` suffixes. Leave them; the intake workflow removes them.

## 2. Find the right directory

Every pack lives under `Packs/<pack>/` with one folder per content type: `Playbooks/`, `Scripts/<ScriptName>/`, `Lists/<ListName>/`, `CorrelationRules/`, `ModelingRules/`, `XSIAMDashboards/`, `Layouts/`, `IncidentFields/`.

| Your content | Pack |
|---|---|
| Works for every tenant regardless of vendor or lifecycle: a shared script, list, dashboard or layout | `soc-optimization-unified` |
| Part of the NIST IR AI lifecycle: assessment, close decision, case analysis, its layouts | `soc-framework-nist-ir-ai` |
| Only makes sense with one vendor's integration: a correlation or modeling rule for that data source | That vendor's pack. The current set is in [`pack_catalog.json`](pack_catalog.json) and on the site under [Reference › Vendor packs](https://palo-cortex.github.io/secops-framework/packs/). No pack for your vendor yet: say so in the pull request. |

A test: if the content calls a vendor's commands directly instead of going through the universal command, it belongs in that vendor's pack, not in the framework or a lifecycle pack. If you are not sure, open the pull request anyway and describe what it does; the reviewer places it.

## 3. Upload to GitHub

1. Open the directory in the repository and choose **Add file → Upload files**.
2. Drop the exported file in.
3. Under **Commit changes**, choose **Create a new branch** and name it `contrib/<your-name>/<what-you-built>`.
4. Choose **Propose changes**. GitHub opens the pull request form.

## 4. Fill in the pull request

The template loads automatically; the intake workflow reads it. The fields that matter most: what the content does in two or three sentences, the target pack, the integration instances it needs (exact instance names), and the tenant you tested it on. Leave the Shadow Mode and known-issues fields empty if they do not apply.

## What happens next

1. **Intake runs** (a few minutes). It normalizes your file, strips the tenant artifacts, and commits the cleaned version back to your branch; a commit by `github-actions[bot]` is expected. It deploys the content to the review tenant and labels the pull request `intake:passed` or `intake:failed`, with a comment linking the run.
2. **A reviewer inspects the content on the review tenant** and adds `intake:approved`, which releases the PR gate (validation, shadow-mode check, customer-data scan), or requests changes.
3. **A maintainer merges.** If the merge carries a version label, a release is cut for the pack and tenants can install it through the Pack Manager.

Pushing a new commit removes `intake:approved` and the reviewer approves again against the new content.

| Label | Meaning |
|---|---|
| `intake:passed` | Normalized, validated and deployed to the review tenant; ready for the reviewer. |
| `intake:failed` | Intake hit a validation error; the comment links the run. |
| `intake:approved` | The reviewer has seen it live and released the PR gate. Cleared by any new commit. |

## Common questions

**My file name has `_copy` or a version number.** Upload it as is; intake fixes it.

**My content changes a playbook that is already in the repo.** Upload the full export and say in the description what changed and why; the reviewer diffs it against the current file.

**It does not fit any category above.** Open the pull request and describe it. Better to know than not.

## Questions

Tag a maintainer on the pull request.
