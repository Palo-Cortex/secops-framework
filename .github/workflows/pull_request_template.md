<!--
  SOC Framework — Contribution PR
  Fill in every section marked REQUIRED.
  CI uses your answers to validate and route the content.
  Sections marked OPTIONAL can be left blank if they don't apply.
-->

## What does this content do? (REQUIRED)
<!--
  2-3 sentences. Plain English. What problem does it solve?
  Example: "Evaluates Proofpoint TAP email exposure level — determines
  whether a threat was clicked, delivered, or blocked, and identifies
  the blast radius across affected mailboxes."
-->


## Content type (REQUIRED)
<!-- Check all that apply -->
- [ ] Playbook
- [ ] Script / Automation
- [ ] List (lookup table or config list)
- [ ] Correlation Rule
- [ ] Modeling Rule
- [ ] XSIAM Dashboard
- [ ] Layout
- [ ] Incident Field
- [ ] Other (describe below)

## Target pack (REQUIRED)
<!--
  Check exactly one. See CONTRIBUTING.md if you are unsure.
  Not sure? Check the box for "I need help routing this" at the bottom.
-->

**SOC Framework** — shared by every tenant regardless of vendor or lifecycle
- [ ] `soc-optimization-unified`

**NIST IR AI** — the lifecycle: assessment, close decision, case analysis, its layouts
- [ ] `soc-framework-nist-ir-ai`

**Vendor pack** — only makes sense with one vendor's integration
- [ ] `Packs/` id: `______________` (the current set is in `pack_catalog.json`)
- [ ] New pack needed (describe below)

## Integration instances required (REQUIRED if applicable)
<!--
  List the exact integration instance names the reviewer needs
  configured on the test tenant before loading your content.
  Use the instance name as it appears in XSIAM Settings → Integrations.
  Example:
    - CrowdStrike Falcon
    - Proofpoint TAP v2
    - Microsoft Graph Security
  Leave blank if your content has no integration dependencies (e.g. a pure list).
-->


## Tested on tenant (REQUIRED)
<!--
  Which XSIAM tenant did you build and test this on?
  Example: brumxdr, skynet, customer-poc-tenant
-->


## What changed from the current version? (REQUIRED if modifying existing content)
<!--
  If you are submitting an update to a playbook or script that already
  exists in the repo, describe what you changed and why.
  If this is entirely new content, leave this blank.
-->


## Shadow mode (REQUIRED for playbooks and scripts with actions)
<!--
  Every changing action (isolate, revoke, block, retract, close, star,
  assign) ships shadowed for every actor in SOCFrameworkActions_V3, so it
  prints to the War Room and writes its execution row but does not call the
  vendor until it is switched on. Read-only actions ship live.
-->
- [ ] Every changing action this content adds or calls ships shadowed for every actor
- [ ] This content has no actions that affect shadow mode
- [ ] I am not sure — please review

## Dependencies on other framework content (OPTIONAL)
<!--
  Does your content depend on specific lists, scripts, or playbooks
  that must already be installed?
  Example: "Requires SOCFWHighValueUsers list to exist (can be empty)"
-->


## Known issues or limitations (OPTIONAL)
<!--
  Anything the reviewer should know before loading to the test tenant.
  Example: "soc-get-email-events has no Proofpoint TAP response yet —
  requires Microsoft Graph Security instance to return results."
-->


## New pack needed? (OPTIONAL)
<!--
  If you checked "New pack needed" above, describe the vendor and
  what content you are contributing. A maintainer will create the pack.
-->


---
- [ ] I need help figuring out where this belongs (reviewer will route it)
