# SOC Framework – NIST IR (800-61)

**Pack ID:** `soc-framework-nist-ir` | **Version:** 1.4.6 | **Platform:** Cortex XSIAM

---

## Overview

This pack implements the **NIST SP 800-61 Incident Response lifecycle** as a set of modular, composable playbooks for Cortex XSIAM. It provides a structured, repeatable response process across the full IR lifecycle — Detection & Analysis, Containment, Eradication, and Recovery — for every security category the SOC Framework covers.

Rather than building one monolithic playbook per threat scenario, this pack separates **methodology** (NIST lifecycle) from **vendor execution** (action packs) and from **infrastructure** (SOC Framework Core). Scenarios such as endpoint compromise, phishing, identity abuse, and lateral movement all enter the same lifecycle and progress through the same structured phases. Vendor-specific commands are abstracted through `SOCCommandWrapper` and the `SOCFrameworkActions_V3` list, so the same lifecycle logic executes correctly regardless of which security product is in the environment.

---

## Architecture

### The Four-Layer Model

```
┌─────────────────────────────────────────────────────────────┐
│  ENTRY POINT (EP_)                                          │
│  EP_IR_NIST (800-61)_V3                                     │
│  • Assigned to the automation trigger                       │
│  • Calls Foundation Upon Trigger chain                      │
│  • Routes to the NIST IR Lifecycle via category match       │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  LIFECYCLE (SOC_NIST_IR_(800-61)_V3)                        │
│  • Top-level NIST phase controller                          │
│  • Runs: Analysis → Containment → Eradication → Recovery    │
│  • Routes to category-specific Workflow playbooks           │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  WORKFLOW / BUSINESS LOGIC  (SOC_{Category}_{Phase}_V3)     │
│  • Category-specific analysis and evaluation logic          │
│  • Signal characterization, verdict resolution,             │
│    spread evaluation, exposure analysis                     │
│  • Routes to Action Playbooks via SOCCommandWrapper         │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  FOUNDATION (soc-optimization-unified)                      │
│  • Enrichment, dedup, normalize, classify                   │
│  • Runs on every alert before the lifecycle starts          │
│  • Only layer that reads issue.* fields                     │
└─────────────────────────────────────────────────────────────┘
```

**Key contract:** Only Foundation playbooks read `issue.*` fields. All Workflow and Action playbooks consume `SOCFramework.*` context keys written by Foundation. This contract is enforced throughout the pack and is validated in CI.

---

## Shadow Mode & the Universal Command

All response actions in this pack execute through **`SOCCommandWrapper`** — the Universal Command. Action selection is controlled by two lists in `soc-optimization-unified`:

| List | Purpose |
|---|---|
| `SOCFrameworkActions_V3` | Per-action `shadow_mode: true/false`. **This is the shadow mode source of truth.** |
| `SOCExecutionList_V3` | Branch routing only (`execute_branch`). Has nothing to do with shadow mode. |

**Default state: Shadow Mode ON.** With shadow mode enabled, every action call writes its intent to the war room and to the `xsiam_socfw_ir_execution_raw` dataset — but the vendor command does not execute. This is intentional. During a Proof of Value engagement, analysts can see exactly which containment, eradication, and recovery actions *would* fire when the signal is real, without touching production systems.

**Production flip:** Set `"shadow_mode": false` on individual actions in `SOCFrameworkActions_V3`. This can be done action-by-action, allowing a phased transition — for example, enabling containment commands while keeping eradication in shadow mode until the team has reviewed the patterns. This same pattern also applies to progressive enablement in other logging-before-blocking scenarios (e.g., router ACL enforcement, DNS RPZ, DLP policy).

---

## Coverage by Category

Each security category has a full set of phase playbooks: Analysis, Containment, Eradication, and Recovery.

| Category | Analysis Depth | Key Actions |
|---|---|---|
| **Endpoint** | Signal characterization, compromise evaluation, verdict resolution, spread evaluation | Isolate endpoint, kill process, block indicators, file existence check, deisolate |
| **Email** | Signal characterization, exposure evaluation, forensics evaluation, IOC enrichment, spread evaluation, verdict resolution | Delete message, block sender, revoke tokens |
| **Identity** | MITRE tactic routing, AI Prompt verdict | Reset password, revoke tokens, disable user, enable user, clear sessions |
| **Network** | Analysis and phase playbooks included | Block indicators, terminate sessions |
| **SaaS** | Analysis and phase playbooks included | Revoke access, remediate |
| **Workload** | Analysis and phase playbooks included | Isolate workload, remove artifact |
| **Data** | Analysis and phase playbooks included | Quarantine data, restrict access |

### Endpoint Signal-Type Routing (v1.4.0+)

The Endpoint chain differentiates three signal types established during Signal Characterization and routes Containment, Eradication, and Recovery actions accordingly:

| Signal Type | Containment | Eradication | Recovery |
|---|---|---|---|
| `behavior_memory` | Block indicators (hash block via EDR policy) | Kill process + revoke tokens if TA0006 detected | Enable user, set 72h monitoring scope (no isolation) |
| `process_execution` | Kill process | Kill process + validate artifact removal | Confirm artifact cleanup |
| `file_malware` | Isolate endpoint (existing path) | Remove file | Deisolate endpoint |

This prevents unnecessary host isolation for memory-based and injection-based attacks while ensuring credential remediation fires when Credential Access tactics are present.

---

## Playbook Inventory

### Entry Point

| Playbook | Layer | Description |
|---|---|---|
| `EP_IR_NIST (800-61)_V3` | Entry Point | Automation trigger target. Calls Foundation Upon Trigger, routes to NIST IR Lifecycle via MITRE tactic or category match. |

### Lifecycle Controller

| Playbook | Layer | Description |
|---|---|---|
| `SOC NIST IR (800-61)_V3` | Lifecycle | Top-level NIST phase controller. Orchestrates Analysis → Containment → Eradication → Recovery across all categories. |
| `SOC Initialize Investigation Context_V3` | Lifecycle | Establishes investigation context before phase execution. |

### Analysis Phase

| Playbook | Category | Description |
|---|---|---|
| `SOC Analysis_V3` | Router | Routes to category Analysis workflow based on product category. |
| `SOC Analysis Evaluation_V3` | Router | Evaluates analysis completeness and confidence. |
| `SOC EndPoint Analysis_V3` | Endpoint | Orchestrates endpoint analysis sub-chain. Issue count high-confidence override at ≥ 10 events. |
| `SOC Endpoint Signal Characterization_V3` | Endpoint | Classifies signal type: `behavior_memory`, `process_execution`, `file_malware`. Routes CrowdStrike CSTA tactic IDs and MITRE T1003/T1550/T1055 to `behavior_memory`. |
| `SOC Endpoint Compromise Evaluation_V3` | Endpoint | Evaluates compromise likelihood using file verdict, tactic breadth gate (TA0011+TA0003, TA0002+TA0008), and CrowdStrike event density. |
| `SOC Endpoint Verdict Resolution_V3` | Endpoint | Aggregates TI and WildFire verdict into `Analysis.Endpoint.verdict`. |
| `SOC EndPoint Spread Evaluation_V3` | Endpoint | Evaluates lateral spread risk. |
| `SOC Email Analysis_V3` | Email | Orchestrates email analysis sub-chain. |
| `SOC Email Signal Characterization_V3` | Email | Classifies email signal type. |
| `SOC Email Exposure Evaluation_V3` | Email | Evaluates mailbox exposure scope; writes `Analysis.Email.RecipientScope`. |
| `SOC Email Forensics Evaluation_V3` | Email | Pulls email forensics and threat artifacts. |
| `SOC Email IOC Enrichment_V3` | Email | Enriches email IOCs against threat intel. |
| `SOC Email Spread Evaluation_V3` | Email | Maps recipient scope to spread level. Null-safe: defaults `MailboxCount` to `0`. |
| `SOC Email Verdict Resolution_V3` | Email | Resolves click/delivery counts to a recommended action. Null-safe: defaults counts to `0`. |
| `SOC Identity Analysis_V3` | Identity | MITRE tactic routing + AI Prompt verdict for identity threats. |
| `SOC Network Analysis_V3` | Network | Network threat analysis. |
| `SOC SaaS Analysis_V3` | SaaS | SaaS application threat analysis. |
| `SOC Workload Analysis_V3` | Workload | Cloud workload threat analysis. |
| `SOC Data Analysis_V3` | Data | Data security threat analysis. |

### Containment Phase

| Playbook | Category | Description |
|---|---|---|
| `SOC Containment_V3` | Router | Routes to category Containment workflow. |
| `SOC Containment Evaluation_V3` | Router | Evaluates containment completeness. |
| `SOC Endpoint Containment_V3` | Endpoint | Signal-type-aware containment: block indicators (`behavior_memory`), kill process (`process_execution`), or isolate endpoint (`file_malware`). |
| `SOC Email Containment_V3` | Email | Email containment actions. |
| `SOC Identity Containment_V3` | Identity | Identity containment: disable user, revoke tokens. Reads `SOCFramework.Artifacts.UserName` — not `issue.*`. |
| `SOC Network Containment_V3` | Network | Network containment actions. |
| `SOC SaaS Containment_V3` | SaaS | SaaS access containment. |
| `SOC Workload Containment_V3` | Workload | Workload isolation. |
| `SOC Data Containment_V3` | Data | Data access restriction. |

### Eradication Phase

| Playbook | Category | Description |
|---|---|---|
| `SOC Eradication_V3` | Router | Routes to category Eradication workflow. |
| `SOC EndPoint Eradication_V3` | Endpoint | Signal-type-aware eradication. Credential access check (TA0006) triggers `soc-revoke-tokens` before `soc-kill-process` on `behavior_memory` signals. |
| `SOC Email Eradication_V3` | Email | Email eradication: delete messages, clean artifacts. |
| `SOC Identity Eradication_V3` | Identity | Identity eradication: reset password + revoke tokens. |
| `SOC Network Eradication_V3` | Network | Network eradication. |
| `SOC SaaS Eradication_V3` | SaaS | SaaS eradication. |
| `SOC Workload Eradication_V3` | Workload | Workload artifact removal. |
| `SOC Data Eradication_V3` | Data | Data eradication. |

### Recovery Phase

| Playbook | Category | Description |
|---|---|---|
| `SOC Recovery_V3` | Router | Routes to category Recovery workflow. |
| `SOC EndPoint Recovery_V3` | Endpoint | Signal-type-aware recovery: enable user + monitoring scope (`behavior_memory`), artifact validation (`process_execution`), deisolate endpoint (`file_malware`). |
| `SOC Email Recovery_V3` | Email | Email recovery and user notification. |
| `SOC Identity Recovery_V3` | Identity | Identity recovery: enable user. Gates on `Eradication.attempted=true`. |
| `SOC Network Recovery_V3` | Network | Network recovery. |
| `SOC SaaS Recovery_V3` | SaaS | SaaS access restoration. |
| `SOC Workload Recovery_V3` | Workload | Workload restoration. |
| `SOC Data Recovery_V3` | Data | Data access restoration. |

---

## Incident Fields

These case fields are written by phase playbooks and displayed in the NIST IR case layout. They are the primary audit trail for what happened and when.

| Field | Written By | Purpose |
|---|---|---|
| `Analysis_Timestamp` | Analysis phase | Timestamp when analysis verdict was reached (MTTD anchor) |
| `Analysis_Story` | Analysis phase | Human-readable summary of analysis findings |
| `Analysis_Spread_Level` | Spread Evaluation | `isolated`, `multi_user`, or `tenant_wide` |
| `Analysis_Blast_Radius` | Analysis phase | Count of affected entities |
| `Analysis_Case_Risk_Score` | Analysis phase | Composite risk score used by downstream routing |
| `Analysis_Response_Recommendation` | Verdict Resolution | Recommended next action |
| `Containment_Timestamp` | Containment phase | Timestamp when containment action executed (MTTC anchor) |
| `Containment_Actions` | Containment phase | List of containment actions taken |
| `Containment_Story` | Containment phase | Human-readable containment summary |
| `Eradication_Timestamp` | Eradication phase | Timestamp of eradication completion |
| `Eradication_Actions` | Eradication phase | List of eradication actions taken |
| `Eradication_Story` | Eradication phase | Human-readable eradication summary |
| `Recovery_Timestamp` | Recovery phase | Timestamp of recovery completion (MTTR anchor) |
| `Recovery_Actions` | Recovery phase | List of recovery actions taken |
| `Recovery_Story` | Recovery phase | Human-readable recovery summary |

---

## Scripts

These scripts power the case layout display. They format context values from the `SOCFramework.*` namespace into readable markdown blocks that appear on the case wall.

| Script | Description |
|---|---|
| `SOCFramework_displayAnalysis` | Renders Analysis phase summary on case layout |
| `SOCFramework_displayContainment` | Renders Containment phase summary on case layout |
| `SOCFramework_displayEradication` | Renders Eradication phase summary on case layout |
| `SOCFramework_displayRecovery` | Renders Recovery phase summary on case layout |
| `SOCFramework_displayEndpointStatus` | Renders endpoint isolation status on case layout |
| `SOCFramework_ManualIsolateEndpoint` | Manual analyst action: isolate endpoint from the case layout |
| `SOCFramework_ManualDeisolateEndpoint` | Manual analyst action: deisolate endpoint from the case layout |

---

## Value Driver Alignment

Every phase of this pack maps to Palo Alto Networks Command of the Message Value Drivers.

| Phase | Value Driver | Metric |
|---|---|---|
| Analysis | VD1 Reduce Risk, VD3 Efficiency | MTTD (Analysis_Timestamp), FP rate via confidence scoring |
| Containment | VD1 Reduce Risk, VD3 Efficiency | MTTC (Containment_Timestamp), spread stopped |
| Eradication | VD1 Reduce Risk, VD4 Secure Growth | Persistence cleared, attack surface risk reduced |
| Recovery | VD1 Reduce Risk, VD3 Efficiency | MTTR (Recovery_Timestamp), systems restored |
| Shadow Mode | VD2 Simplify Ops | Safe flow testing, progressive enablement without disruption |

These metrics feed the **XSIAM SOC Value Metrics Dashboard** in `soc-optimization-unified` via the `xsiam_socfw_ir_execution_raw` dataset (Universal Command) and the `xsiam_playbookmetrics_raw` dataset (JOB - Store Playbook Metrics in Dataset V3). The `value_tags.json` lookup joins analyst time-per-action to execution records to produce hours-saved calculations.

---

## Dependencies

| Pack | Role |
|---|---|
| `soc-optimization-unified` | **Required.** Foundation layer: Upon Trigger chain, SOCCommandWrapper, SOCFrameworkActions_V3, SOCExecutionList_V3, SOCProductCategoryMap_V3, value_tags lookup, Value Metrics dashboard. Must be installed first. |
| Vendor action packs | **Optional.** Install the packs for your environment. Each vendor pack contributes action commands that `SOCCommandWrapper` routes to. |

**Supported vendor action packs:**
- `SocFrameworkCrowdstrikeFalcon`
- `SocFrameworkProofPointTap`
- `soc-microsoft-defender`
- `soc-microsoft-defender-email`
- `SocFrameworkTrendMicroVisionOne`

---

## Installation

### Using SOC Framework Pack Manager (Recommended)

From the XSIAM Playground war room:

```
# 1. Install foundation layer first
!SOCFWPackManager action=apply pack_id=soc-optimization-unified

# 2. Install the NIST IR lifecycle pack
!SOCFWPackManager action=apply pack_id=soc-framework-nist-ir

# 3. Install vendor packs for your environment
!SOCFWPackManager action=apply pack_id=SocFrameworkCrowdstrikeFalcon
!SOCFWPackManager action=apply pack_id=SocFrameworkProofPointTap

# 4. Sync the value_tags lookup
!SOCFWPackManager action=sync-tags
```

### Manual Installation

1. Download the pack zip from the [GitHub Releases page](https://github.com/Palo-Cortex/secops-framework/releases)
2. Install via **Settings → Content Packs → Upload Pack**
3. Apply configuration from `xsoar_config.json` manually if not using the Pack Manager

### Post-Installation

Two tenant-level configurations are required after pack installation (Automation Rule + Layout Rule). See [POST_CONFIG_README.md](POST_CONFIG_README.md) for step-by-step instructions.

---

## Configuration

### Flipping Shadow Mode per Action

Shadow mode is controlled per-action in the `SOCFrameworkActions_V3` XSIAM List. To enable a specific action for production execution:

1. Navigate to **Settings → Advanced → Lists**
2. Open `SOCFrameworkActions_V3`
3. Find the action by its `command` key (e.g., `soc-isolate-endpoint`)
4. Set `"shadow_mode": false`

This change takes effect immediately on the next execution of that action — no playbook restart required. The `SOCExecutionList_V3` list controls branch routing only; it has no effect on shadow mode. This per-action granularity supports progressive production enablement — for example, enabling containment commands while keeping eradication in shadow mode until the team has reviewed execution patterns.

---

## Release Notes

### 1.4.0 — Signal-Type-Aware Endpoint Response

Introduced signal-type routing across all Endpoint phase playbooks. The `behavior_memory`, `process_execution`, and `file_malware` signal types established during Signal Characterization now drive distinct Containment, Eradication, and Recovery paths. Key additions: CrowdStrike CSTA tactic routing in Signal Characterization; tactic breadth gate in Compromise Evaluation; credential access (TA0006) check triggering token revocation in Eradication; monitoring-scope-based recovery for memory signals. Fixed a critical dead end at Recovery task 18 that silently skipped all recovery actions on every alert.

### 1.3.0 — Email Lifecycle Production Readiness

Delivered the Email NIST IR lifecycle to production readiness. Fixed analyst-blocking null-input pauses in Spread Evaluation and Verdict Resolution. Closed a critical context handoff gap where `Analysis.Email.RecipientScope` was never written by Exposure Evaluation, causing Spread Evaluation to always default to `single_entity`. Resolved `issue.*` contract violations in Containment and Identity Containment playbooks.

### 1.1.0 — Endpoint Analysis Bug Fixes

Resolved three runtime failures in `SOC_Endpoint_Compromise_Evaluation_V3` caused by array-typed context values passed to scalar string operators. Fixed SHA256 input (array→joined scalar), verdict input source (artifacts array→`Analysis.Endpoint.verdict` scalar), and `in`/`notIn` operator type mismatch on the "No Evidence?" condition.

---


## Design Principles

- **Modular:** Each phase, category, and evaluation is a separate playbook. Swap or extend one without touching the others.
- **Composable:** Entry Point → Lifecycle → Workflow → Action. Each layer has a single responsibility and a documented context contract.
- **Reusable:** Category Workflow playbooks are not scenario-specific. The Email Analysis workflow runs whether the alert came from an abuse mailbox submission or an email security product alert.
- **Lean:** This pack contains only what XSIAM cannot do natively. Grouping, scoring, starring, auto-close, and correlation are native XSIAM capabilities — the Framework does not replicate them.
- **Vendor-agnostic at the routing layer:** No vendor names appear in Lifecycle or Workflow playbooks. Routing is by category (`Endpoint`, `Email`, `Identity`). Vendors are referenced only in action packs.
