# SOC Trend Micro Vision One Integration Enhancement for Cortex XSIAM

This pack enhances the native **Trend Micro Vision One (TMV1)** integration within **Palo Alto Networks Cortex XSIAM**. It provides correlation rules, modeling rules, and data model extensions that align Vision One telemetry with the SOC Framework, enabling automated triage, MITRE-mapped detection, and full NIST IR lifecycle execution.

---

## Prerequisites

- **Trend Micro Vision One** integration installed and configured via Marketplace
- API credentials with access to Alerts, Endpoints, and Indicators
- SOC Framework packs installed: `soc-optimization-unified` and `soc-framework-nist-ir`
- If using a custom connector or data broker, disable redundant alert fetch on the native integration

---

## What's Included

| Component | Description |
|---|---|
| **Correlation Rule** | `SOC Trend Micro Vision One V3` — single unified rule covering all SAE workbench alerts. Filters on `alert_provider = SAE`, extracts MITRE tactic/technique, resolves hostname, user, cmdline, and file indicators from the nested JSON payload. |
| **Modeling Rule** | `SOCTrendMicroVisionOneModelingRules` — maps Vision One alert data to XDM schema across three alert types: workbench alerts, search detection alerts, and observed attack technique alerts. |
| **Layouts** | Custom analyst layouts: `displayVisionOneAlert_xsiam`, `displayVisionOneIndicators_xsiam`, `displayVisionOneHostStatus_xsiam` |

---

## How It Fits the SOC Framework

```
Trend Micro Vision One (data source)
        │
        ▼
trend_micro_vision_one_v3_generic_alert_raw  (raw dataset)
        │
        ▼
SOCTrendMicroVisionOneModelingRules          (XDM normalization)
        │
        ▼
SOC Trend Micro Vision One V3               (correlation rule → XSIAM alert)
        │
        ▼
EP_IR_NIST (800-61)_V3                      (SOC Framework entry point)
        │
        ▼
Foundation → Analysis → Containment → Eradication → Recovery
```

Vision One alerts are classified as **Endpoint** category by `Foundation_-_Product_Classification_V3` and route to `SOC_Endpoint_Analysis_V3` through the NIST IR lifecycle. All Containment, Eradication, and Recovery actions run in **Shadow Mode** by default — actions are logged to the warroom and `xsiam_socfw_ir_execution_raw` dataset but vendor commands do not execute until Shadow Mode is disabled in `SOCFrameworkActions_V3`.

---

## Correlation Rule — Key Design Decisions

**Single rule covering all SAE workbench alert types.** Vision One's `alert_provider = SAE` gate ensures only actionable workbench detections generate XSIAM alerts — raw telemetry events are excluded.

**MITRE tactic resolution in XQL.** The rule extracts the MITRE technique ID from `matched_rules[0].matched_filters[0].mitre_technique_ids[0]`, strips sub-technique suffixes (e.g. `T1547.001` → `T1547`), and resolves the parent tactic name and TA-number via array lookup. This populates `mitretacticid`, `mitretacticname`, `mitretechniqueid`, and `mitretechniquename` on the XSIAM alert, which the SOC Framework Analysis playbooks use for MITRE-based routing.

**Suppression on `id` (workbench alert ID) for 1 hour.** Prevents duplicate alert generation for persistent open workbench items that re-evaluate without new events.

**Indicator extraction without `arraymap`/`indexof`.** The XQL uses `arrayfilter` + `arrayindex` to extract the first host, user, cmdline, SHA256, remote IP, domain, and parent process indicators. This avoids the performance cost of full array mapping on every alert.

---

## Modeling Rule — Key Design Decisions

**Three filter blocks for three Vision One alert types:**
- `workbench` — entity/indicator-driven alerts from the Vision One console
- `search_detection` — alerts from Vision One's search-based detection engine
- `observed_attack_technique` — OAT alerts from behavioral analysis

**Hostname uses `entity_value.name`, not `entity_value.guid`.** The `entity_id` field for host entities is a GUID (`5088F315-47E1-...`) which belongs in `xdm.source.host.device_id` only. The human-readable name (`N73CG1B4`) goes into `xdm.source.host.hostname`. Using the GUID as hostname breaks UEBA and BIOC entity correlation silently.

---

## Validation Steps

1. Confirm dataset ingestion: **Data → Datasets → `trend_micro_vision_one_v3_generic_alert_raw`**
2. Confirm modeling rule is active: **Data → Modeling Rules → `SOC TrendMicro VisionOne Modeling Rule`**
3. Confirm correlation rule is enabled: **Detection & Correlation → Correlation Rules → `SOC Trend Micro Vision One V3`**
4. Confirm layout rule is configured (see POST_CONFIG_README)
5. Trigger a test alert and verify `mitretacticid`, `agent_hostname`, and `actor_effective_username` are populated on the XSIAM alert

---

## Related Resources

- [Trend Micro Vision One API Documentation](https://automation.trendmicro.com/xdr/api/)
- [Cortex XSIAM Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsiam)
- [SOC Framework Repository](https://github.com/Palo-Cortex/secops-framework)
