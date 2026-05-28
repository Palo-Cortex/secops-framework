# SOCFrameworkEnrichmentMap_NIST_IR

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_schema_docs.py` to regenerate. -->

| Field | Value |
|---|---|
| Pack | `soc-framework-nist-ir` |
| List Name | `SOCFrameworkEnrichmentMap_NIST_IR` |
| Source | [`schemas/soc-framework/soc-framework-nist-ir/SOCFrameworkEnrichmentMap_NIST_IR.yaml`](https://github.com/Palo-Cortex/secops-framework/blob/main/schemas/soc-framework/soc-framework-nist-ir/SOCFrameworkEnrichmentMap_NIST_IR.yaml) |

Upon Trigger enrichment lanes for the NIST IR lifecycle. Each lane fires a built-in reputation command (|||<lane>) against the union of its source paths from SOCFramework.Artifacts.*. Lifecycle-agnostic engine + thin dispatcher in soc-optimization-unified.
