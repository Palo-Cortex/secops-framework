---
title: "Framework and Lifecycle"
---

# Framework and Lifecycle

Two things run on a tenant and they are easy to confuse because they ship together and one is useless without the other. The SOC Framework is the operating layer: it makes any security-operations lifecycle vendor-agnostic, safe to run, and measurable. A lifecycle, such as NIST IR AI, is the sequence of decisions about one issue or one case. The lifecycle decides *what to ask and when to act*; the framework decides *how an action is carried out, on which vendor, whether it really runs, and what gets recorded*.

## 1. Definitions

**SOC Framework (SOCFW).** A set of lists, scripts, integrations and one dataset that any lifecycle can be built on. It knows nothing about phases, verdicts or incident response. It knows about data sources, categories, artifacts, actions, vendors, actors, shadow flags, minutes and rows. Replace the lifecycle with a posture lifecycle or an exposure lifecycle and every part of the framework still has a job.

**Lifecycle.** A sequence of decisions, in a fixed order, scoped to an issue or a case, that calls framework actions when its policy says so. NIST IR AI is one lifecycle; it follows NIST 800-61's phases and uses AI for assessment and analysis. Its entry point, its prompts, its decisions, its jobs, its layouts and its dashboards all belong to it, even though every one of them calls the framework. Replace the framework underneath and the lifecycle has to be rewritten.

## 2. The test

Ask these in order; the first yes decides.

1. Does it name a phase, a verdict, or *when* something should happen? → Lifecycle.
2. Would it still exist, unchanged, if NIST IR were replaced by a different lifecycle? → Framework.
3. Is it a list the framework reads generically but a lifecycle fills with its own content (a normalize map keyed by lifecycle, a phase policy)? → The *mechanism* is framework; the *content* is the lifecycle's.

Two consequences of the test:

- `EP_IR_NIST - AI` is lifecycle content. It is the first thing that runs on an issue and it calls the framework's Foundation chain, but it decides the order of assessment, emergency response, elevate and close, so it is NIST IR's.
- Shadow Mode is framework. It never mentions containment; it gates *changing actions* for an *actor*. A lifecycle calls `soc-isolate-endpoint` in its containment phase; the framework decides whether that call touches the vendor.

## 3. Who owns what

| Framework | Lifecycle (NIST IR AI) |
|---|---|
| The contract: `SOCFramework.Product.*`, `SOCFramework.Artifacts.*`; product classification; normalize and enrichment maps (keyed by lifecycle, filled by it) | The entry point `EP_IR_NIST - AI` and the automation rule that starts it |
| The universal command `SOCCommandWrapper`; the action registry `SOCFrameworkActions_V3`; action class and product maps; vendor resolution; dispatch | The two prompts and the aiTasks that bind them |
| Shadow Mode per action and per actor; the tenant override `SOCFWTenantConfig`; `!SOCFWConfig`; deployment modes | The decisions: issue assessment, promote and render, emergency response, elevate case, close decision, and the order they run in |
| Policy *mechanisms*: authority levels, environment tiers, the phase plan builder and executor | Policy *content*: which phases exist, which actions each may call, the closure bar (`SOCFWClosurePolicy`), the elevate and emergency rules |
| The execution dataset `xsiam_socfw_ir_execution_raw`, the case ledger, the dataset writers, the collectors | The case analysis job, the case analysis phase, the case verdict |
| Value accounting: `SOCActionTimeMap_V3`, minutes on every row | The issue and case layouts, the layout rule, the feedback and containment buttons |
| Health check, framework health dashboard, Package Manager | The lifecycle's dashboards (`NIST IR - … (AI)`), which read the framework's dataset |
| Auto Triage and Analyst Assignment jobs (they act on cases through framework actions, with no phase) | The phase contract `SOCFrameworkPhaseContract_V3` (what each NIST phase reads and writes) |

## 4. Why the line matters

**For operators:** a switch lives on one side only. "Why did this not contain?" is a framework question (actor flag, vendor, customer value, artifact) until the framework shows the action was never asked for, at which point it is a lifecycle question (policy, verdict, confidence). Reading the two in that order is the whole of troubleshooting.

**For authors:** a new lifecycle writes no vendor code, no shadow logic and no dataset code. It writes a normalize map section, a phase contract, an entry point and its decisions, and it calls actions by name.

**For the product conversation:** everything in the framework column is a candidate for a platform capability, because it is generic: a normalized context model, a vendor-agnostic action registry with per-action, per-actor simulation, an execution ledger with analyst minutes, a tenant configuration override that survives upgrades. Everything in the lifecycle column is content that would run on top of those capabilities. The framework column is the list to take to product; the lifecycle column is what stays as packs.

## Where to go next

<div class="grid cards" markdown>

-   **Evaluate**

    ---

    Stand the framework up on a tenant and make XSIAM's value visible without changing anything.

    [The evaluation, end to end →](evaluate/index.md)

-   **Deploy to production**

    ---

    Keep producing the same measures in production and bridge the gaps on this estate.

    [Deploy to production →](deploy/index.md)

-   **Build on the framework**

    ---

    Write content that fits the framework and get it through the gates.

    [Build on the framework →](build/index.md)

-   **Reference**

    ---

    One page per capability: SOC Framework, NIST IR AI, vendor packs. Something not behaving? Start at [Support](support/index.md).

    [Reference →](reference/index.md)

</div>

**[→ Install & Setup](https://github.com/Palo-Cortex/secops-framework/blob/main/Packs/soc-optimization-unified/POST_CONFIG_README.md)**

---

Verified against **soc-optimization-unified 3.31.1**, **soc-framework-nist-ir-ai 1.6.0** and `ai/nist-ir` source · Internal mapping: Notion, SOC Framework — Documentation › the boundary rule
