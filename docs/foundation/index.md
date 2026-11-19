# Foundation

`soc-optimization-unified` is the SOC Framework itself: the layer every lifecycle and vendor pack builds on.

## What it holds

| Piece | Where |
| --- | --- |
| The Universal Command, which runs every action through one script | `SOCCommandWrapper` |
| Shadow Mode, set per action and per caller | `SOCFrameworkActions_V3` |
| The normalizer, which reads a lifecycle's normalize map | `SOCNormalizeFromList` |
| The execution record every dashboard reads | `xsiam_socfw_ir_execution_raw`, written by `SOCCommandWrapper` |
| Action categories for the dashboards | `SOCActionTimeMap_V3` |

The foundation knows nothing about a specific product or lifecycle. A lifecycle pack adds the phases on top of it, and vendor packs add the detections that feed them.

## The lifecycle on top

The lifecycle pack is `soc-framework-nist-ir-ai`; see [NIST IR AI](../soc-framework-nist-ir-ai/nist-ir-ai.md). The earlier NIST IR pack, `soc-framework-nist-ir`, is retired and is not listed in the pack catalog.

## When to read the lifecycle's lists

| Task | Read |
| --- | --- |
| Adding a vendor pack | `SOCFrameworkNormalizeMap_NIST_IR`, for the fields the pack must fill and where they go |
| Changing what a phase reads or writes | `SOCFrameworkPhaseContract_V3`. Don't break the contract |
| Building a dashboard | The `xsiam_socfw_ir_execution_raw` dataset, with categories from `SOCActionTimeMap_V3` |

All three lists ship in `soc-framework-nist-ir-ai`, except `SOCActionTimeMap_V3`, which ships in `soc-optimization-unified`.
