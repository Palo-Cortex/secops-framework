# Contributing to the SOC Framework

This guide is for PS engineers, DCs, and other contributors who have built content
on an XSIAM tenant and want to get it into the framework.

You do not need to know git or use a terminal. Everything happens in the GitHub web UI.

---

## Before You Start

You need:
- A GitHub account with access to this repo
- Content exported from your XSIAM tenant
- A few minutes to fill in the PR description

---

## Step 1 — Export Your Content from XSIAM

Export your content from the XSIAM UI as you normally would.

| What you built | How to export |
|---|---|
| Playbook | Playbooks → open playbook → Export (top right) → Download YAML |
| Script / Automation | Scripts → select script → Export |
| List | Settings → Lists → select list → Export / Download JSON |
| Correlation Rule | Correlation Rules → select rule → Export YAML |
| Modeling Rule | Modeling Rules → select rule → Export YAML |
| XSIAM Dashboard | Dashboards → select dashboard → Export |
| Layout | Case Management → Layouts → select layout → Export |
| Incident Field | Case Management → Fields → select field → Export |

The export will have artifacts from your tenant (version numbers, tenant IDs,
copy suffixes on names). That is expected — the CI pipeline cleans them up.

---

## Step 2 — Find the Right Directory

The repo is organized into three tiers. Put your file in the directory that
matches what you built and which pack it belongs to.

### Tier 1 — SOC Framework Core

Shared infrastructure that every customer gets regardless of vendor or lifecycle.
Scripts, lists, dashboards, layouts all live here.

**Pack: `soc-optimization-unified`**

| What you built | Directory |
|---|---|
| Script / Automation | `Packs/soc-optimization-unified/Scripts/<ScriptName>/` |
| List | `Packs/soc-optimization-unified/Lists/<ListName>/` |
| XSIAM Dashboard | `Packs/soc-optimization-unified/XSIAMDashboards/` |
| Layout | `Packs/soc-optimization-unified/Layouts/` |
| Incident Field | `Packs/soc-optimization-unified/IncidentFields/` |

**Examples:**
- `SOCCommandWrapper.py` → `Packs/soc-optimization-unified/Scripts/SOCCommandWrapper/`
- `SOCFrameworkActions_V3.json` → `Packs/soc-optimization-unified/Lists/SOCFrameworkActions_V3/`
- A new shared lookup list → `Packs/soc-optimization-unified/Lists/<YourListName>/`

---

### Tier 2 — Lifecycle Packs

The incident response process layer. Playbooks that implement the NIST IR 800-61
lifecycle phases (Analysis, Containment, Eradication, Recovery) live here.
If you built a new lifecycle playbook or modified an existing one, it goes here.

**Pack: `soc-framework-nist-ir`**

| What you built | Directory |
|---|---|
| Lifecycle playbook | `Packs/soc-framework-nist-ir/Playbooks/` |
| Layout | `Packs/soc-framework-nist-ir/Layouts/` |
| Incident Field | `Packs/soc-framework-nist-ir/IncidentFields/` |

**Examples:**
- `SOC_Email_Analysis_V3.yml` → `Packs/soc-framework-nist-ir/Playbooks/`
- `SOC_Identity_Containment_V3.yml` → `Packs/soc-framework-nist-ir/Playbooks/`

**How to tell if your playbook belongs here:**
It implements or extends one of the NIST IR phases — Analysis, Containment,
Eradication, or Recovery — and would apply to any vendor, not just one specific
integration. If it calls vendor-specific commands directly without going through
the Universal Command, it probably belongs in a Product Enhancement pack instead.

---

### Tier 3 — Product Enhancements

Vendor-specific content. Right now this means correlation rules and modeling rules
that feed alerts into the framework for a specific vendor integration.
Each vendor has its own pack.

| Vendor | Pack | Directory |
|---|---|---|
| CrowdStrike Falcon | `SocFrameworkCrowdstrikeFalcon` | `Packs/SocFrameworkCrowdstrikeFalcon/CorrelationRules/` |
| Proofpoint TAP | `SocFrameworkProofPointTap` | `Packs/SocFrameworkProofPointTap/CorrelationRules/` |
| Microsoft Defender | `soc-microsoft-defender` | `Packs/soc-microsoft-defender/CorrelationRules/` |
| Microsoft Defender Email | `soc-microsoft-defender-email` | `Packs/soc-microsoft-defender-email/CorrelationRules/` |
| Trend Micro Vision One | `SocFrameworkTrendMicroVisionOne` | `Packs/SocFrameworkTrendMicroVisionOne/CorrelationRules/` |

**Examples:**
- A new CrowdStrike detection rule → `Packs/SocFrameworkCrowdstrikeFalcon/CorrelationRules/`
- A Proofpoint modeling rule → `Packs/SocFrameworkProofPointTap/ModelingRules/`

**How to tell if your content belongs here:**
It only makes sense if the customer has a specific vendor integration installed.
A correlation rule that fires on CrowdStrike Falcon events belongs in the
CrowdStrike pack, not in the NIST IR pack.

---

## Step 3 — Upload to GitHub

1. Go to the correct directory in the repo (links above)
2. Click **Add file → Upload files**
3. Drag your exported file into the upload area
4. Under "Commit changes":
   - Select **"Create a new branch"**
   - Name it something like `contrib/your-name/what-you-built`
5. Click **Propose changes**

GitHub will automatically take you to the PR creation screen.

---

## Step 4 — Fill In the PR Description

The PR template will load automatically. Fill in every section — the CI
pipeline uses your answers to route and validate the content correctly.

The most important fields:
- **What does this do** — a plain English description, 2-3 sentences
- **Target pack** — check the one pack from the list in the template
- **Integration instances required** — exact instance names needed on the tenant
- **Tested on tenant** — which tenant you verified it on

Leave the shadow mode and known issues fields blank if they don't apply.

---

## What Happens After You Open the PR

Your PR moves through two CI workflows with a reviewer gate between them.

**1. Intake CI runs automatically** (a few minutes). It normalizes your file
(strips `_copy` and `_export` suffixes, resets the version, fixes internal
IDs and packIDs) and commits the cleaned-up version back to your PR branch.
You will see an extra commit appear authored by `github-actions[bot]` — that
is expected.

**2. Intake CI deploys your content to the contribution review tenant**
so a reviewer can see it live in the XSIAM UI. The PR gets either an
`intake:passed` or `intake:failed` label, plus a sticky comment with the
result and a link to the workflow logs.

**3. A reviewer inspects the deployed content** on the review tenant.
If everything looks correct they add the `intake:approved` label, which
releases the second CI workflow (validation, prerelease build, deploy
to the final tenant). If changes are needed they request them on the PR.

**4. Once the second workflow passes**, a maintainer merges into main.
A release workflow then bumps the pack version and publishes.

You do not need to do anything after opening the PR unless the reviewer
asks you to make changes. **If you push a new commit at any point, the
`intake:approved` label is removed automatically** and the reviewer needs
to re-approve against the updated content — stale approval is worse than
no approval.

### Labels you will see

| Label | What it means |
|---|---|
| `intake:passed` | Intake CI normalized, validated, and deployed your content to the review tenant. Ready for reviewer to look at. |
| `intake:failed` | Intake CI hit a validation error. See the sticky PR comment for the workflow run link. |
| `intake:approved` | Reviewer has inspected the live content and unblocked the rest of the pipeline. Removed automatically on any new commit. |

---

## Common Questions

**My file has `_copy` or a version number in the name. Is that a problem?**
No. The intake CI strips those automatically and commits the cleaned-up
version back to your PR branch as a separate commit (authored by
`github-actions[bot]`). Upload the file as-is from your XSIAM export.

**I'm not sure which pack my playbook belongs to.**
Fill in the PR description with what the playbook does and which integrations
it uses. The reviewer will determine the right pack during review.

**My content modifies an existing playbook that's already in the repo.**
Upload the full export of the modified playbook. The reviewer will diff it
against the current version and merge the changes manually. Note in the PR
description what you changed and why.

**I built something that doesn't fit any of the categories above.**
Open the PR anyway and describe what you built. We'd rather know about it
than have you hold it back.

**I need to contribute content for a vendor that doesn't have a pack yet.**
Note that in the PR description. If the content is solid, we'll create the pack.

---

## Questions

Reach out in Slack or tag a maintainer on the PR.
