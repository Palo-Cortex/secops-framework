# SOC Framework Posture Lifecycle

Cloud posture lifecycle (NIST SP 800-40 Rev 4)

## Pack contents

- **Schemas** (in `schemas/soc-framework/soc-framework-posture/`):
  - `SOCFrameworkNormalizeMap_POSTURE.yaml`
  - `SOCFrameworkEnrichmentMap_POSTURE.yaml`
  - `SOCFrameworkDedupContract_POSTURE.yaml`
  - `SOCFrameworkPhaseContract_POSTURE.yaml`
- **Entry Point playbook:** `EP_Posture`
- **Phase playbooks:** `SOC_Identify`, `SOC_Plan`, `SOC_Execute`, `SOC_Verify`
- **Dataset:** `xsiam_socfw_posture_execution_raw` (per-lifecycle, RBAC-isolated;
  auto-derived from XSIAM convention `<vendor>_<product>_raw`)
- **System XQL HTTP Collector instance:** `socfw_posture_execution`
  (provisioned at pack install via xsoar_config.json; XSIAM
  server-provisions the URL; keyless, XSIAM-internal auth — NOT the
  generic "HTTP Collector" integration which requires API keys)

## Next steps

1. Author the four schemas with this lifecycle's actual contract content.
2. Run `tools/generate_soc_framework_content.py emit --pack soc-framework-posture`
   to materialize the lists from schemas.
3. Author the phase playbook bodies (the scaffolded stubs are minimal).

## Architecture references

- `docs/architecture/cross-lifecycle-surfaces.md` — tier model, blast-radius
  rubric, known violations and resolutions.
