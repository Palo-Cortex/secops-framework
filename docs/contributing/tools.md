# Tools reference

<!-- GENERATED FILE — do not edit by hand. Run `python tools/generate_tools_reference.py` to regenerate; the rows come from each tool's docstring. -->

Every script under `tools/`, with what it does in its own words. `check_contribution.py` is the gate that runs before every commit; the rest are what it calls, the generators behind `prep_docs.py`, and the authoring and replay tools. Run any of them with `--help` for its arguments.

| Tool | What it does | Usage |
|---|---|---|
| `SOCFramework_AIVerdictSummary.py` | UNVERIFIED — no docstring |  |
| `SOCFramework_IdentityScoreAnalysis.py` | UNVERIFIED — no docstring |  |
| `build_campaign_from_tsv.py` | UNVERIFIED — no docstring |  |
| `build_pack_catalog.py` | UNVERIFIED — no docstring |  |
| `build_proofpoint_scenarios.py` | Build 6 realistic Proofpoint TAP TSV test scenario files. |  |
| `build_unhappy_path_scenarios.py` | Build the unhappy-path TSVs for the close/leave branches. | `python3 tools/build_unhappy_path_scenarios.py` |
| `bump_pack_version.py` | UNVERIFIED — no docstring |  |
| `check_contracts.py` | SOC Framework layer contract validator. | `python3 tools/check_contracts.py`<br>`python3 tools/check_contracts.py --dry-run`<br>`python3 tools/check_contracts.py --strict` |
| `check_contribution.py` | Pre-merge contribution validation orchestrator. | `python3 tools/check_contribution.py`<br>`python3 tools/check_contribution.py --no-upload`<br>`python3 tools/check_contribution.py --input Packs/soc-framework-nist-ir` |
| `check_dependency_versions.py` | Compares version strings embedded in each pack's xsoar_config.json URLs against the current versions in pack_catalog.json. | `python tools/check_dependency_versions.py`<br>`python tools/check_dependency_versions.py --pack my-pack`<br>`python tools/check_dependency_versions.py --fix` |
| `check_foundation_continueonerror.py` | SOC Framework CI guard — Foundation playbook continueonerror enforcement. | `python3 tools/check_foundation_continueonerror.py --pack Packs/soc-optimization-unified`<br>`python3 tools/check_foundation_continueonerror.py --file Packs/.../Foundation_-_Upon_Trigger_V3.yml`<br>`python3 tools/check_foundation_continueonerror.py --pack Packs/soc-optimization-unified --ci` |
| `check_readme_coverage.py` | Docs gate: anything a pack PR adds must be mentioned in that pack's docs. | `python tools/check_readme_coverage.py Packs/soc-optimization-unified`<br>`python tools/check_readme_coverage.py Packs/<pack> --base origin/main` |
| `correlation_rule_grouping_check.py` | Single question: does this correlation rule map the correct fields to group? | `python3 tools/correlation_rule_grouping_check.py --input rules.json`<br>`python3 tools/correlation_rule_grouping_check.py --input rules.json --only-broken`<br>`python3 tools/correlation_rule_grouping_check.py --input rules.json         --format csv --output grouping.csv` |
| `correlation_rule_preflight.py` | SOC Framework correlation rule validator Catches platform-level issues that demisto-sdk validate misses. | `python3 tools/correlation_rule_preflight.py Packs/soc-crowdstrike-falcon`<br>`python3 tools/correlation_rule_preflight.py "Packs/soc-crowdstrike-falcon/CorrelationRules/SOC CrowdStrike Falcon - Endpoint Alerts.yml"` |
| `emit_lifecycle_content.py` | Convenience wrapper around tools/generate_soc_framework_content.py that runs emit (or validate) on ALL schemas for a lifecycle pack in a single command. | `python3 tools/emit_lifecycle_content.py soc-framework-posture`<br>`python3 tools/emit_lifecycle_content.py soc-framework-posture --validate-only`<br>`python3 tools/emit_lifecycle_content.py soc-framework-posture --schema NormalizeMap` |
| `ep_nist_dependency_map.py` | Goal: Starting from a single "entry" playbook (e.g. | `python3 tools/ep_nist_dependency_map.py     --root-pack Packs/soc-framework-nist-ir     --root-playbook-name "EP_IR_NIST (800-61)_V3"     --other-pack Packs/soc-optimization-unified` |
| `extract_normalizer_contracts.py` | UNVERIFIED — no docstring |  |
| `fix_errors.py` | Automates fixing demisto-sdk validation and parsing errors. |  |
| `fix_xsoar_config_ids.py` | one-shot migration Finds every xsoar_config.json under Packs/ and corrects any custom_packs entry whose 'id' contains a version segment. | `python3 tools/fix_xsoar_config_ids.py`<br>`python3 tools/fix_xsoar_config_ids.py --fix`<br>`python3 tools/fix_xsoar_config_ids.py --fix --packs SocFrameworkCrowdstrikeFalcon,soc-optimization-unified` |
| `generate_capability_catalog.py` | Render the capability catalog from ``docs/capabilities.yml``. | `python tools/generate_capability_catalog.py`<br>`python tools/generate_capability_catalog.py --check` |
| `generate_home_page.py` | Generate docs/index.md from docs/index.md.template. | `python tools/generate_home_page.py`<br>`python tools/generate_home_page.py --check` |
| `generate_mkdocs_nav.py` | Generate mkdocs.yml from mkdocs.yml.template and docs/nav.yml. | `python tools/generate_mkdocs_nav.py`<br>`python tools/generate_mkdocs_nav.py --check` |
| `generate_pack_overviews.py` | Generate per-pack overview docs from xsoar_config.json. | `python tools/generate_pack_overviews.py`<br>`python tools/generate_pack_overviews.py --check`<br>`python tools/generate_pack_overviews.py --pack ID` |
| `generate_schema_docs.py` | Generate Swagger-style markdown documentation for SOC Framework schemas. | `python tools/generate_schema_docs.py`<br>`python tools/generate_schema_docs.py --check`<br>`python tools/generate_schema_docs.py --schema PATH` |
| `generate_soc_framework_content.py` | Generic generator for SOC Framework Lists. |  |
| `generate_tools_reference.py` | Generate docs/contributing/tools.md from the docstrings in tools/*.py and tools/*.sh. | `python tools/generate_tools_reference.py`<br>`python tools/generate_tools_reference.py --check` |
| `generate_vendor_content.py` | Generate XSIAM vendor pack content (modeling rules + correlation rules) from a SOC Framework per-data-source mapping YAML. |  |
| `identity_census.py` | which identifier FORMS does each source emit? |  |
| `identity_e2e.py` | E2E: rule issue.* -> SOCFramework.* -> Entity Enrichment tasks -> layout. |  |
| `init_pack.py` | SOC Framework Pack Initializer Wraps `demisto-sdk init --pack --xsiam` and post-processes the result for SOC Framework conventions: - Correct pack_metadata.json with framework fields + dependencies - Prune SDK-generated directories not used by this pack type - Pre-create content subdirectories for the chosen pack type - Wire a stub entry into xsoar_config.json custom_packs - Emit a ready-to-run next-steps checklist Pack types vendor      Thin vendor layer. | `python3 tools/init_pack.py --name SocFrameworkZscalerZPA --type vendor`<br>`python3 tools/init_pack.py --name SocFrameworkAcmeSIEM --type vendor --desc "ACME SIEM correlation rules"`<br>`python3 tools/init_pack.py --name soc-framework-nist-ir-v4 --type nist-ir` |
| `layout_harness.py` | Local layout harness — runs the REAL normalize engine and the REAL panel script offline against a mocked incident context. | `python3 tools/layout_harness.py --category email`<br>`python3 tools/layout_harness.py --category endpoint --enrich`<br>`python3 tools/layout_harness.py --category identity --cie` |
| `new_vendor_pack.py` | One-shot vendor pack creator from a schema YAML Orchestrates the full new-vendor-pack flow. | `python3 tools/new_vendor_pack.py \`<br>`python3 tools/new_vendor_pack.py --schema <path> --dry-run`<br>`python3 tools/new_vendor_pack.py --schema <path> --skip-catalog` |
| `normalize_contribution.py` | Strips XSIAM UI export artifacts from contributed playbooks and list JSONs. | `python3 tools/normalize_contribution.py`<br>`python3 tools/normalize_contribution.py --dry-run`<br>`python3 tools/normalize_contribution.py --input Packs/soc-framework-nist-ir/Playbooks/SOC_Email_Exposure_Evaluation_V3_copy.yml` |
| `normalize_ruleid_adopted.py` | Behavior: - Correlation rule YAML schema enforcement (fromversion: 6.10.0, rule_id: 0, global_rule_id present, rogue id:/ruleid: keys removed). | `python3 tools/normalize_ruleid_adopted.py --root Packs/soc-framework-nist-ir --fix`<br>`python3 tools/normalize_ruleid_adopted.py --root Packs/soc-framework-nist-ir`<br>`python3 tools/normalize_ruleid_adopted.py --root Packs/soc-framework-nist-ir --pack-id soc-framework-nist-ir --fix` |
| `pack_prep.py` | UNVERIFIED — docstring has no summary line | `python3 tools/pack_prep.py Packs/SocFrameworkCrowdstrikeFalcon` |
| `platform_health_check.sh` | Pre-upload platform API health check Verifies XSIAM API endpoints are responding AND (when the pack contains correlation rules) that the correlation rule write path works. | `bash tools/platform_health_check.sh [pack_path]` |
| `playbook_condition_lint.py` | SOC Framework playbook condition & context validator Catches playbook YAML patterns that parse cleanly but silently fail at runtime. | `python3 tools/playbook_condition_lint.py Packs/soc-framework-nist-ir`<br>`python3 tools/playbook_condition_lint.py Packs/soc-framework-nist-ir/Playbooks/SOC_Endpoint_Containment_V3.yml`<br>`python3 tools/playbook_condition_lint.py Packs/soc-framework-nist-ir Packs/soc-optimization-unified` |
| `playbook_simulator.py` | Static execution engine for XSIAM SOC Framework playbooks. |  |
| `preflight_xsoar_config.py` | Validates xsoar_config.json for one or more packs before deployment. | `python3 tools/preflight_xsoar_config.py Packs/SocFrameworkProofPointTap`<br>`python3 tools/preflight_xsoar_config.py Packs/SocFrameworkProofPointTap Packs/SocFrameworkCrowdstrikeFalcon`<br>`python3 tools/preflight_xsoar_config.py --packs "SocFrameworkProofPointTap,soc-optimization-unified"` |
| `prep_docs.py` | Refresh every generated documentation file in the right order. | `python tools/prep_docs.py`<br>`python tools/prep_docs.py --check`<br>`python tools/prep_docs.py --quiet` |
| `release_pack.sh` | Promote a pack from dev iteration to a tagged release. | `bash tools/release_pack.sh Packs/soc-framework-nist-ir minor`<br>`bash tools/release_pack.sh Packs/soc-optimization-unified major` |
| `replay_scenario.py` | XSIAM Attack Scenario Replay Tool Replays one or multiple data sources into XSIAM via HTTP Collector. | `python3 tools/replay_scenario.py --manifest scenarios/turla_carbon_full_chain.yml`<br>`python3 tools/replay_scenario.py --manifest scenarios/turla_carbon_full_chain.yml --compress-window 30m`<br>`python3 tools/replay_scenario.py --manifest scenarios/turla_carbon_cs_only.yml --dry-run` |
| `run_tests.py` | SOC Framework Test Runner — with live XQL execution via XSIAM API. | `python3 tools/run_tests.py --all`<br>`python3 tools/run_tests.py --happy`<br>`python3 tools/run_tests.py --unhappy` |
| `sanitize_tsv.py` | Scan and sanitize TSV replay files for public repo safety. | `python3 tools/sanitize_tsv.py input_tsv/`<br>`python3 tools/sanitize_tsv.py input_tsv/CrowdStrike-MITRE-Turla-Carbon-in-XSIAM.tsv`<br>`python3 tools/sanitize_tsv.py input_tsv/ --fix --output-dir input_tsv_sanitized/` |
| `scaffold_lifecycle.py` | Stamp a new SOC Framework lifecycle pack. | `python3 tools/scaffold_lifecycle.py \`<br>`python3 tools/scaffold_lifecycle.py --lifecycle-id posture --lifecycle-name "Posture" \` |
| `schema_mutation_test.py` | Empirically test how an XSIAM dataset reacts to schema changes, without touching any production dataset. | `python3 tools/schema_mutation_test.py --env .env-brumxdr-schematest`<br>`python3 tools/schema_mutation_test.py --env .env-brumxdr-schematest --test T3`<br>`python3 tools/schema_mutation_test.py --env .env-brumxdr-schematest --all` |
| `sdk_classify.py` | UNVERIFIED — no docstring |  |
| `send_pan_dss_seed.sh` | Seed socfw identity source data into pan_dss_raw via the brumxdr HTTP Collector. |  |
| `send_test_events.py` | UNVERIFIED — no docstring |  |
| `tsv_to_json.py` | Convert a CrowdStrike TSV export into a JSON array of flat objects suitable for XSIAM HTTP Collector test ingest, with optional theme-based anonymization (e.g. | `python3 tools/tsv_to_json.py     --input "XQL-QUERY-124577 - 2025_11_11 (1).tsv"     --output tools/crowdstrike_sample_execution.json     --limit 10`<br>`python3 tools/tsv_to_json.py     --input "XQL-QUERY-124577 - 2025_11_11 (1).tsv"     --output tools/crowdstrike_sample_execution_marvel.json     --limit 10     --theme marvel` |
| `tsv_to_json_proofpoint.py` | Convert a Proofpoint TAP TSV export into a JSON array suitable for XSIAM HTTP Collector ingest via send_test_events.py. | `python3 tools/tsv_to_json_proofpoint.py --input scenario.tsv --output scenario.json`<br>`python3 tools/tsv_to_json_proofpoint.py --input scenario.tsv --output scenario.json --limit 5` |
| `upload_package.sh` | Upload a pack to an XSIAM tenant via demisto-sdk (no zipfiles). | `bash tools/upload_package.sh Packs/soc-framework-nist-ir`<br>`bash tools/upload_package.sh Packs/soc-optimization-unified` |
| `validate_catalog_urls.py` | Validates that every pack in pack_catalog.json has: 1. |  |
| `validate_pack_catalog.py` | Pack metadata and catalog integrity checks. |  |
| `validate_playbooks.py` | XSIAM / XSOAR SOC Framework — Playbook Integrity Validator Checks: 1. | `python tools/validate_playbooks.py --root Packs/soc-optimization-unified` |
| `validate_shadow_mode.py` | Pre-commit / CI gate for the SOC Framework Universal Command shadow mode architecture. | `python3 tools/validate_shadow_mode.py`<br>`python3 tools/validate_shadow_mode.py Packs/soc-framework-nist-ir`<br>`python3 tools/validate_shadow_mode.py --all` |
| `validate_xsoar_configs.py` | CI gate for xsoar_config.json in every pack Rules enforced: 1. | `python tools/validate_xsoar_configs.py`<br>`python tools/validate_xsoar_configs.py --packs soc-optimization-unified,soc-framework-nist-ir` |
| `verify_pack_zip.py` | release gate: prove a built pack zip actually contains the pack's content before it is published. | `python3 tools/verify_pack_zip.py --pack-root Packs/<pack> --zip dist/<pack>-vX.Y.Z.zip` |
| `verify_tenant_content.py` | Confirm every script and list in the repo's SOCFW packs is present on the tenant. | `python3 tools/verify_tenant_content.py Packs/soc-framework-nist-ir-ai`<br>`python3 tools/verify_tenant_content.py` |
| `xql_tenant_check.py` | Validate correlation rule XQL against a live tenant's dataset schema. |  |

## Without a docstring

These need a module docstring before they can be described here:

- `SOCFramework_AIVerdictSummary.py`
- `SOCFramework_IdentityScoreAnalysis.py`
- `build_campaign_from_tsv.py`
- `build_pack_catalog.py`
- `bump_pack_version.py`
- `extract_normalizer_contracts.py`
- `sdk_classify.py`
- `send_test_events.py`
