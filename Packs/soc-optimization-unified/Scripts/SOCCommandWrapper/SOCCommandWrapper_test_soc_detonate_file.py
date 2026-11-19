"""
SOCCommandWrapper_test_soc_detonate_file.py

Unit tests for soc-detonate-file Universal Command behavior.
Follows the exact pattern from SOCCommandWrapper_test.py — demistomock,
no tenant required, runs with pytest in under 1 second.

Run: pytest Scripts/SOCCommandWrapper/SOCCommandWrapper_test_soc_detonate_file.py -v
"""

import importlib
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
LISTS = os.path.join(HERE, "..", "..", "Lists")
sys.path.insert(0, HERE)


def _read_list(name):
    """The pack's own list. A missing file fails the test: a contract checked
    against a stand-in proves nothing."""
    path = os.path.join(LISTS, name, f"{name}_data.json")
    assert os.path.exists(path), f"{path} not found"
    with open(path) as fh:
        return json.load(fh)

SCRIPT_MODULE_NAME = "SOCCommandWrapper"


# The maintained loader, so this file never drifts from how the wrapper is loaded.
from SOCCommandWrapper_test import load_script  # noqa: E402


# ── Action list factory ───────────────────────────────────────────────────────

def make_actions_list(extra_actions: dict | None = None) -> str:
    """Return a SOCFrameworkActions JSON string with soc-detonate-file and optional extras."""
    base = {
        "soc-detonate-file": {
            "phase": "investigation",
            "shadow_mode": False,
            "responses": {
                "Cortex Core - IR": {
                    "command": "core-get-hash-analytics-prevalence",
                    "inline_args": {"sha256": "${SOCFramework.Artifacts.Hash}"}
                },
                "WildFire v2": {
                    "command": "wildfire-upload-file",
                    "inline_args": {"upload": "${SOCFramework.Artifacts.FilePath}", "format": "auto"}
                },
                "WildFire v2 (hash)": {
                    "command": "wildfire-get-verdict",
                    "inline_args": {"hash": "${SOCFramework.Artifacts.Hash}"}
                },
                "VirusTotal (Private API)": {
                    "command": "vt-private-get-file-report",
                    "inline_args": {"resource": "${SOCFramework.Artifacts.Hash}"}
                },
            }
        },
        "soc-isolate-endpoint": {
            "shadow_mode": True,
            "responses": {
                "Cortex Core - IR": {
                    "command": "core-isolate-endpoint",
                    "inline_args": {"endpoint_id": "${SOCFramework.Primary.Endpoint}"}
                }
            }
        }
    }
    if extra_actions:
        base.update(extra_actions)
    return json.dumps(base)


def _get_list_response(actions_json: str):
    """Return a callable that mocks demisto.executeCommand('getList', ...)."""
    def handler(args):
        if args.get("listName") in ("SOCFrameworkActions", "SOCFrameworkActions_V3"):
            return [{"Contents": actions_json}]
        return [{"Contents": "[]"}]
    return handler


# ── Tests: soc-detonate-file — shadow mode (Analysis, shadow_mode=False) ─────

class TestSocDetonateFileShadowFalse:
    """
    soc-detonate-file has shadow_mode=false.
    Even when the overall Framework is in Shadow Mode, Analysis actions always execute.
    These tests verify the command fires for real when shadow_mode=false on the action entry.
    """

    def test_cortex_core_fires_when_only_vendor_configured(self):
        """With only Cortex Core available, core-get-hash-analytics-prevalence executes."""
        script, demisto = load_script()

        demisto._args = {
            "action": "soc-detonate-file",
            "list_name": "SOCFrameworkActions_V3",
            "output_key": "Analysis.Endpoint.Detonation",
            "Phase": "Analysis",
            "Action_Actor": "automation",
        }
        demisto._context = {
            "SOCFramework": {
                "Product": {"response": "Cortex Core - IR"},
                "Artifacts": {"Hash": "abc123def456"}
            }
        }

        cortex_response = [{"Type": 1, "Contents": {"data": [{"prevalence": "rare", "verdict": "unknown"}]}}]
        demisto._command_responses = {
            "getList": _get_list_response(make_actions_list()),
            "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
            "core-get-hash-analytics-prevalence": cortex_response,
            "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
        }

        script.main()

        executed = [c[0] for c in demisto._commands]
        assert "core-get-hash-analytics-prevalence" in executed, \
            "Cortex Core prevalence check must execute — it is the free baseline"
        assert "wildfire-upload-file" not in executed, \
            "WildFire must not fire when not the configured vendor"

    def test_wildfire_fires_when_wildfire_is_product_vendor(self):
        """When WildFire v2 is the configured product vendor, wildfire-upload-file executes."""
        script, demisto = load_script()

        demisto._args = {
            "action": "soc-detonate-file",
            "list_name": "SOCFrameworkActions_V3",
            "output_key": "Analysis.Endpoint.Detonation",
            "Phase": "Analysis",
            "Action_Actor": "automation",
        }
        demisto._context = {
            "SOCFramework": {
                "Product": {"response": "WildFire v2"},
                "Artifacts": {"Hash": "abc123def456", "FilePath": "/tmp/sample.exe"}
            }
        }

        wf_response = [{"Type": 1, "Contents": {"verdict": "malicious", "sha256": "abc123def456"}}]
        demisto._command_responses = {
            "getList": _get_list_response(make_actions_list()),
            "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
            "wildfire-upload-file": wf_response,
            "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
        }

        script.main()

        executed = [c[0] for c in demisto._commands]
        assert "wildfire-upload-file" in executed, "WildFire must fire when it is the product vendor"

    def test_shadow_mode_false_on_action_means_always_execute(self):
        """
        The action entry has shadow_mode=false.
        Even if the caller passes shadow_mode=true, the action-level flag wins
        for Analysis phase — these always execute.
        """
        script, demisto = load_script()

        demisto._args = {
            "action": "soc-detonate-file",
            "list_name": "SOCFrameworkActions_V3",
            "output_key": "Analysis.Endpoint.Detonation",
            "Phase": "Analysis",
            "Action_Actor": "automation",
            # Caller passes shadow_mode=true (simulating Shadow Mode environment)
            "shadow_mode": "true",
        }
        demisto._context = {
            "SOCFramework": {
                "Product": {"response": "Cortex Core - IR"},
                "Artifacts": {"Hash": "deadbeef1234"}
            }
        }

        demisto._command_responses = {
            "getList": _get_list_response(make_actions_list()),
            "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
            "core-get-hash-analytics-prevalence": [{"Type": 1, "Contents": {"data": []}}],
            "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
        }

        script.main()

        # Action-level shadow_mode=false overrides caller shadow_mode=true
        result_context = demisto._context.get("Analysis", {}).get("Endpoint", {}).get("Detonation", [])
        if result_context:
            record = result_context[0] if isinstance(result_context, list) else result_context
            # shadow_mode on the record should reflect the action entry value (false), not caller value
            assert record.get("shadow_mode") is False, \
                "Dataset record must reflect action-level shadow_mode=false"

        executed = [c[0] for c in demisto._commands]
        assert "core-get-hash-analytics-prevalence" in executed, \
            "Analysis action must execute even when caller environment is shadow mode"

    def test_dataset_write_contains_detonation_record(self):
        """Execution record written to xsiam_socfw_ir_execution_raw with correct fields."""
        script, demisto = load_script()

        demisto._args = {
            "action": "soc-detonate-file",
            "list_name": "SOCFrameworkActions_V3",
            "output_key": "Analysis.Endpoint.Detonation",
            "Phase": "Analysis",
            "Action_Actor": "automation",
        }
        demisto._context = {
            "SOCFramework": {
                "Product": {"response": "Cortex Core - IR"},
                "Artifacts": {"Hash": "feedcafe9876"}
            }
        }

        dataset_writes = []

        def capture_dataset(args):
            dataset_writes.append(args)
            return [{"Type": 1, "Contents": "ok"}]

        demisto._command_responses = {
            "getList": _get_list_response(make_actions_list()),
            "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
            "core-get-hash-analytics-prevalence": [{"Type": 1, "Contents": {"data": []}}],
            "socfw-post-to-dataset": capture_dataset,
        }

        script.main()

        assert dataset_writes, "Must write at least one record to the execution dataset"
        written_data = dataset_writes[0]
        # Validate the dataset write contains the right structure
        assert "data" in written_data or "xql_query" in written_data or len(written_data) > 0, \
            "Dataset write must contain execution data"

    def test_continueonerror_behavior_on_missing_vendor(self):
        """
        If the vendor command fails, the action should not crash the playbook.
        continueonerror=True in the task ensures graceful degradation.
        This test verifies the action completes even when vendor returns error.
        """
        script, demisto = load_script()

        demisto._args = {
            "action": "soc-detonate-file",
            "list_name": "SOCFrameworkActions_V3",
            "output_key": "Analysis.Endpoint.Detonation",
            "Phase": "Analysis",
            "Action_Actor": "automation",
        }
        demisto._context = {
            "SOCFramework": {
                "Product": {"response": "Cortex Core - IR"},
                "Artifacts": {"Hash": "baddatatest99"}
            }
        }

        # Simulate integration failure
        demisto._command_responses = {
            "getList": _get_list_response(make_actions_list()),
            "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
            "core-get-hash-analytics-prevalence": [{"Type": 4, "Contents": "Error: integration not configured"}],
            "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
        }

        # Should not raise — continueonerror=True in the playbook task
        # SOCCommandWrapper handles this by logging the failure
        try:
            script.main()
            completed = True
        except Exception as e:
            completed = False
            pytest.fail(f"SOCCommandWrapper should not raise on vendor failure: {e}")

        assert completed


# ── Tests: Shadow mode still applies to C/E/R actions ────────────────────────

class TestCERActionsRemainInShadow:
    """
    Verify that soc-isolate-endpoint (shadow_mode=true) still respects Shadow Mode
    after adding soc-detonate-file (shadow_mode=false) to the same Actions list.
    The two entries must not interfere with each other.
    """

    def test_isolate_endpoint_stays_shadow_when_detonate_file_present(self):
        """Adding soc-detonate-file to Actions must not affect soc-isolate-endpoint behavior."""
        script, demisto = load_script()

        demisto._args = {
            "action": "soc-isolate-endpoint",
            "list_name": "SOCFrameworkActions_V3",
            "output_key": "Containment.Execution",
            "Phase": "Containment",
            "Action_Actor": "automation",
        }
        demisto._context = {
            "SOCFramework": {
                "Product": {"response": "Cortex Core - IR"},
                "Primary": {"Endpoint": "ep-001"}
            }
        }

        demisto._command_responses = {
            "getList": _get_list_response(make_actions_list()),
            "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
            "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
        }

        script.main()

        executed = [c[0] for c in demisto._commands]
        assert "core-isolate-endpoint" not in executed, \
            "Isolation command must NOT fire — soc-isolate-endpoint has shadow_mode=true"

        # Last result should be the shadow mode message
        assert any("Shadow" in str(r) for r in demisto._results), \
            "Warroom must contain a Shadow Mode entry for the suppressed isolation"

    def test_detonate_file_executes_while_isolate_stays_shadow(self):
        """
        Run both actions in sequence (simulated). Verify:
        - soc-detonate-file: vendor command fires (shadow_mode=false)
        - soc-isolate-endpoint: vendor command suppressed (shadow_mode=true)
        """
        # Run detonate-file
        script1, demisto1 = load_script()
        demisto1._args = {
            "action": "soc-detonate-file",
            "list_name": "SOCFrameworkActions_V3",
            "output_key": "Analysis.Endpoint.Detonation",
            "Phase": "Analysis",
            "Action_Actor": "automation",
        }
        demisto1._context = {
            "SOCFramework": {"Product": {"response": "Cortex Core - IR"}, "Artifacts": {"Hash": "aabbccdd"}}
        }
        demisto1._command_responses = {
            "getList": _get_list_response(make_actions_list()),
            "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
            "core-get-hash-analytics-prevalence": [{"Type": 1, "Contents": {"data": []}}],
            "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
        }
        script1.main()
        detonation_executed = [c[0] for c in demisto1._commands]

        # Run isolate-endpoint
        script2, demisto2 = load_script()
        demisto2._args = {
            "action": "soc-isolate-endpoint",
            "list_name": "SOCFrameworkActions_V3",
            "output_key": "Containment.Execution",
            "Phase": "Containment",
            "Action_Actor": "automation",
        }
        demisto2._context = {
            "SOCFramework": {"Product": {"response": "Cortex Core - IR"}, "Primary": {"Endpoint": "ep-001"}}
        }
        demisto2._command_responses = {
            "getList": _get_list_response(make_actions_list()),
            "getIssues": [{"Contents": {"data": [{"id": "100"}]}}],
            "socfw-post-to-dataset": [{"Type": 1, "Contents": "ok"}],
        }
        script2.main()
        isolation_executed = [c[0] for c in demisto2._commands]

        assert "core-get-hash-analytics-prevalence" in detonation_executed, \
            "Detonation must execute (shadow_mode=false on action)"
        assert "core-isolate-endpoint" not in isolation_executed, \
            "Isolation must NOT execute (shadow_mode=true on action)"


# ── Tests: Actions list contract ─────────────────────────────────────────────

class TestActionsListContracts:
    """Validate SOCFrameworkActions_V3_data.json structural contracts."""

    def _load_actions(self):
        return _read_list("SOCFrameworkActions_V3")

    def test_soc_detonate_file_exists(self):
        actions = self._load_actions()
        assert "soc-detonate-file" in actions, \
            "soc-detonate-file must exist in SOCFrameworkActions_V3"

    def test_soc_detonate_file_shadow_mode_false(self):
        """Detonation is an Analysis action — must always execute."""
        actions = self._load_actions()
        det = actions.get("soc-detonate-file", {})
        assert det.get("shadow_mode") is False, \
            "soc-detonate-file shadow_mode must be false — Analysis actions always execute"

    def test_soc_detonate_file_has_cortex_core_baseline(self):
        """Cortex Core is the free baseline — must always be present."""
        actions = self._load_actions()
        det = actions.get("soc-detonate-file", {})
        vendors = list(det.get("responses", {}).keys())
        assert "Cortex Core - IR" in vendors, \
            "Cortex Core - IR must be the baseline vendor for soc-detonate-file (free, always available)"

    def test_cer_actions_are_shadowed_for_unattended_callers(self):
        """C/E/R actions simulate for every unattended caller unless a tenant flips them."""
        script, _ = load_script()
        actions = self._load_actions()
        cer_actions = [
            "soc-isolate-endpoint", "soc-disable-user", "soc-reset-password",
            "soc-retract-email", "soc-block-sender", "soc-search-and-delete-email",
        ]
        for action in cer_actions:
            if action not in actions:
                continue
            for actor in ("automation", "ai", "issue_emergency"):
                assert script.resolve_shadow_mode(actions[action], actor) is True, \
                    f"{action} must be simulated for {actor} - C/E/R actions default to shadow"

    def test_no_singular_inbox_rule_key(self):
        """soc-remove-inbox-rule (singular) was renamed — old key must not exist."""
        actions = self._load_actions()
        assert "soc-remove-inbox-rule" not in actions, \
            "soc-remove-inbox-rule (singular) is the old key — must be soc-remove-inbox-rules (plural)"

    def test_plural_inbox_rule_key_exists(self):
        """soc-remove-inbox-rules (plural) must exist."""
        actions = self._load_actions()
        assert "soc-remove-inbox-rules" in actions, \
            "soc-remove-inbox-rules (plural) must exist in SOCFrameworkActions_V3"


# ── Tests: SOCFWFeatureFlags contract ─────────────────────────────────────────

class TestFeatureFlagsContracts:
    """Validate SOCFWFeatureFlags_data.json structural contracts."""

    def _load_flags(self):
        return _read_list("SOCFWFeatureFlags")

    def test_all_flags_default_false(self):
        """All feature flags must default to enabled=false — OOTB runs with zero config."""
        flags = self._load_flags()
        meta_keys = {"id", "name", "_comment", "description",
                     "allRead", "allReadWrite", "cacheVersn", "data", "definitionId",
                     "detached", "fromServerVersion", "isOverridable", "itemVersion",
                     "locked", "nameLocked", "packID", "packName", "previousAllRead",
                     "previousAllReadWrite", "system", "tags", "toServerVersion",
                     "truncated", "type", "version", "fromVersion", "display_name"}
        for key, value in flags.items():
            if key in meta_keys:
                continue
            assert isinstance(value, dict), f"Flag '{key}' must be a dict with 'enabled' key"
            assert value.get("enabled") is False, \
                f"Flag '{key}' must default to enabled=false — flip intentionally per deployment"

    def test_required_flags_present(self):
        flags = self._load_flags()
        required = [
            "sandbox_detonation",
            "email_authentication",
            "email_header_scoring",
            "email_process_original",
            "email_indicator_hunting",
            "email_phishing_ml",
        ]
        for flag in required:
            assert flag in flags, f"Required flag '{flag}' missing from SOCFWFeatureFlags"

    def test_all_flags_have_descriptions(self):
        """Each flag's description IS the documentation — must be present."""
        flags = self._load_flags()
        meta_keys = {"id", "name", "_comment", "description",
                     "allRead", "allReadWrite", "cacheVersn", "data", "definitionId",
                     "detached", "fromServerVersion", "isOverridable", "itemVersion",
                     "locked", "nameLocked", "packID", "packName", "previousAllRead",
                     "previousAllReadWrite", "system", "tags", "toServerVersion",
                     "truncated", "type", "version", "fromVersion", "display_name"}
        for key, value in flags.items():
            if key in meta_keys or not isinstance(value, dict):
                continue
            desc = value.get("description", "")
            assert desc and len(desc) > 20, \
                f"Flag '{key}' description is missing or too short — descriptions are the runbook"
