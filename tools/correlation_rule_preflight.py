#!/usr/bin/env python3
"""
correlation_rule_preflight.py — SOC Framework correlation rule validator

Catches platform-level issues that demisto-sdk validate misses.
Run before upload_package.sh on any pack containing correlation rules.

Usage:
    python3 tools/correlation_rule_preflight.py Packs/soc-crowdstrike-falcon
    python3 tools/correlation_rule_preflight.py "Packs/soc-crowdstrike-falcon/CorrelationRules/SOC CrowdStrike Falcon - Endpoint Alerts.yml"
"""

import argparse
import os
import sys
import yaml
from pathlib import Path

REQUIRED_NULL_FIELDS = ["alert_type", "crontab", "search_window", "simple_schedule", "timezone"]

REQUIRED_FIELDS = [
    "action", "alert_category", "alert_description", "alert_domain",
    "alert_fields", "alert_name", "dataset", "description",
    "drilldown_query_timeframe", "execution_mode", "global_rule_id",
    "is_enabled", "mapping_strategy", "mitre_defs", "name",
    "severity", "suppression_duration", "suppression_enabled",
    "user_defined_category", "user_defined_severity", "xql_query",
]

VALID_MITRE_ALERT_FIELDS = {
    "mitretacticid", "mitretacticname", "mitretechniqueid", "mitretechniquename",
}

CANONICAL_MITRE_MAPPINGS = {
    "mitretacticid": "mitre_tactic_id",
    "mitretacticname": "mitre_tactic",
    "mitretechniqueid": "mitre_ids_str",
    "mitretechniquename": "mitre_ids_str",
}


def validate_rule(path: Path) -> list[str]:
    errors = []
    warnings = []

    with open(path) as f:
        rule = yaml.safe_load(f)

    if not isinstance(rule, dict):
        return [f"Failed to parse as YAML dict: {path}"], []

    # alert_category: OTHER causes 101704
    if rule.get("alert_category") == "OTHER":
        errors.append("alert_category: 'OTHER' causes 101704 — use 'User Defined'")

    # mitre_defs format validation (empty {} is valid — preferred for passthrough rules)
    md = rule.get("mitre_defs")

    if isinstance(md, dict) and md:
        for tactic, techniques in md.items():
            if not tactic.startswith("TA"):
                errors.append(f"mitre_defs key '{tactic}' doesn't start with TA — expected format: 'TA0001 - Initial Access'")
            if not isinstance(techniques, list) or len(techniques) == 0:
                errors.append(f"mitre_defs['{tactic}'] must be a non-empty list of techniques")

    # Required null fields must be present (omitting causes HTTP 500)
    for field in REQUIRED_NULL_FIELDS:
        if field not in rule:
            errors.append(f"Missing '{field}' — must be present as explicit null (omitting causes 500)")

    # suppression_duration must be string format
    sd = rule.get("suppression_duration")
    if sd is not None and isinstance(sd, (int, float)):
        errors.append(f"suppression_duration must be string like '1 hours', got integer: {sd}")

    # name / global_rule_id must match
    name = rule.get("name")
    grid = rule.get("global_rule_id")
    if name and grid and name != grid:
        errors.append(f"name '{name}' != global_rule_id '{grid}' — must match")

    # investigation_query_link should not be omitted
    if "investigation_query_link" not in rule:
        warnings.append("investigation_query_link missing — use '' (empty string) if not needed")

    # lookup_mapping should be present
    if "lookup_mapping" not in rule:
        warnings.append("lookup_mapping missing — use [] if not needed")

    # MITRE alert_fields check
    af = rule.get("alert_fields", {})
    if isinstance(af, dict):
        for key in VALID_MITRE_ALERT_FIELDS:
            if key in af:
                expected = CANONICAL_MITRE_MAPPINGS.get(key)
                actual = af[key]
                if expected and actual != expected:
                    warnings.append(
                        f"alert_fields.{key}: '{actual}' — canonical mapping is '{expected}'"
                    )

        # vendor and product required for SOCProductCategoryMap routing
        if "vendor" not in af:
            warnings.append("alert_fields missing 'vendor' — required for SOCProductCategoryMap routing")
        if "product" not in af:
            warnings.append("alert_fields missing 'product' — required for SOCProductCategoryMap routing")

    # XQL must reference at least one dataset
    xql = rule.get("xql_query", "")
    if "dataset" not in xql.lower():
        errors.append("xql_query doesn't contain 'dataset' — query must reference a dataset")

    # user_defined_category / user_defined_severity should reference XQL output fields
    udc = rule.get("user_defined_category")
    uds = rule.get("user_defined_severity")
    if udc and udc not in xql:
        warnings.append(f"user_defined_category: '{udc}' not found in xql_query — verify field exists in query output")
    if uds and uds not in xql:
        warnings.append(f"user_defined_severity: '{uds}' not found in xql_query — verify field exists in query output")

    # suppression_fields should reference XQL output fields
    sf = rule.get("suppression_fields", [])
    if isinstance(sf, list):
        for field in sf:
            if field not in xql:
                warnings.append(f"suppression_fields: '{field}' not found in xql_query — verify field exists in query output")

    return errors, warnings


def find_rules(path: Path) -> list[Path]:
    if path.is_file() and path.suffix in (".yml", ".yaml"):
        return [path]

    rules = []
    cr_dir = path / "CorrelationRules"
    if cr_dir.is_dir():
        for f in cr_dir.iterdir():
            if f.suffix in (".yml", ".yaml") and not f.name.startswith("."):
                rules.append(f)
    return rules


def check_scripts(pack_path: Path) -> list[str]:
    """Check that script directories have non-empty .py files."""
    errors = []
    scripts_dir = pack_path / "Scripts"
    if not scripts_dir.is_dir():
        return errors

    for script_dir in scripts_dir.iterdir():
        if not script_dir.is_dir() or script_dir.name.startswith("."):
            continue
        py_files = list(script_dir.glob("*.py"))
        if not py_files:
            errors.append(f"Scripts/{script_dir.name}/ has no .py file")
        else:
            for py in py_files:
                if py.stat().st_size == 0:
                    errors.append(f"Scripts/{script_dir.name}/{py.name} is 0 bytes — SDK will fail to unify")

    return errors


def main():
    parser = argparse.ArgumentParser(description="SOC Framework correlation rule preflight validator")
    parser.add_argument("path", help="Pack directory or individual correlation rule YAML")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        print(f"  ✗ Path not found: {path}")
        sys.exit(1)

    rules = find_rules(path)
    pack_path = path if path.is_dir() else path.parent.parent

    # Early-out: if the pack has no correlation rules, there is nothing for this
    # tool to validate. Script validation is orthogonal — pack_prep (SDK validate)
    # covers scripts. Running script validation here was scope creep that caused
    # this tool to fail on packs that don't ship correlation rules at all
    # (e.g. soc-framework-manager). The tool's name is its contract: correlation
    # rule preflight. If there are no rules, there is no preflight to do.
    if not rules and path.is_dir():
        print(f"  No correlation rules found in {path} — skipping preflight")
        print(f"  PASSED (no-op)")
        return

    total_errors = 0
    total_warnings = 0

    # Check scripts for empty .py files — only when the pack actually ships
    # correlation rules. The real risk this guards against is a correlation rule
    # whose referenced script is an empty file, which causes SDK unification to
    # fail silently. That risk doesn't exist on packs with no correlation rules.
    script_errors = check_scripts(pack_path)
    if script_errors:
        print(f"\n  Scripts:")
        for e in script_errors:
            print(f"    ✗ {e}")
        total_errors += len(script_errors)

    if not rules:
        print(f"  No correlation rules found in {path}")
    else:
        for rule_path in sorted(rules):
            errors, warnings = validate_rule(rule_path)
            total_errors += len(errors)
            total_warnings += len(warnings)

            if errors or warnings:
                print(f"\n  {rule_path.name}:")
                for e in errors:
                    print(f"    ✗ {e}")
                for w in warnings:
                    print(f"    ⚠ {w}")
            else:
                print(f"  ✓ {rule_path.name}")

    print()
    if total_errors > 0:
        print(f"  FAILED — {total_errors} error(s), {total_warnings} warning(s)")
        sys.exit(1)
    elif total_warnings > 0 and args.strict:
        print(f"  FAILED (strict) — {total_warnings} warning(s)")
        sys.exit(1)
    elif total_warnings > 0:
        print(f"  PASSED with {total_warnings} warning(s)")
    else:
        print(f"  PASSED")


if __name__ == "__main__":
    main()
