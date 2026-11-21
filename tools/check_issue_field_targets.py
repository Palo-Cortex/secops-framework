#!/usr/bin/env python3
"""Fail a correlation rule that writes into an issue field the platform owns.

A rule's alert_fields map event values into issue fields. Some of those fields
belong to the platform: single-selects with fixed values (hostos accepts only
AGENT_OS_* and NO_HOST) and the fields that hold the issue's own playbook and
lifecycle state. Writing into one does not fail anywhere: the rule saves, the
pack installs and the rule alerts. Mapping device_platform_name into hostos
left about half the issues in every burst with their playbook never started.

The list lives in policies/restricted_issue_fields.json. Blocked fields fail;
warn fields print a warning. The check reads both the emitted rules and the
vendor contracts, because a rule emitted from a contract is rewritten on the
next emit.

  python3 tools/check_issue_field_targets.py Packs/soc-crowdstrike-falcon
  python3 tools/check_issue_field_targets.py            # every pack and contract
"""
import argparse
import glob
import json
import os
import sys

import yaml

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
POLICY = os.path.join(REPO, "policies", "restricted_issue_fields.json")


def load_policy(path=POLICY):
    with open(path) as fh:
        p = json.load(fh)
    return p.get("blocked", {}), p.get("warn", {})


def rule_targets(rule_path):
    """(issue field, source) pairs from an emitted rule's alert_fields."""
    with open(rule_path) as fh:
        rule = yaml.safe_load(fh) or {}
    fields = rule.get("alert_fields") or {}
    return [(str(k).lower(), v) for k, v in fields.items()]


def _walk_issue_fields(node, out):
    if isinstance(node, dict):
        if "issue_field" in node:
            out.append((str(node["issue_field"]).lower(), node.get("source")))
        for v in node.values():
            _walk_issue_fields(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_issue_fields(v, out)


def contract_targets(contract_path):
    """(issue field, source) pairs from every issue_field entry in a contract."""
    with open(contract_path) as fh:
        doc = yaml.safe_load(fh) or {}
    out = []
    _walk_issue_fields(doc.get("correlation_rules") or doc.get("correlation_rule") or [], out)
    return doc.get("pack"), out


def collect(pack_dirs):
    """Yield (file, issue field, source) for the given packs and their contracts."""
    names = {os.path.basename(os.path.normpath(p)) for p in pack_dirs}
    for pack in pack_dirs:
        for f in sorted(glob.glob(os.path.join(pack, "CorrelationRules", "*.yml"))):
            for field, src in rule_targets(f):
                yield os.path.relpath(f, REPO), field, src
    for f in sorted(glob.glob(os.path.join(REPO, "schemas", "vendors", "*", "*.yaml"))):
        pack, pairs = contract_targets(f)
        if pack in names:
            for field, src in pairs:
                yield os.path.relpath(f, REPO), field, src


def check(pack_dirs, policy=POLICY):
    blocked, warn = load_policy(policy)
    errors, warnings = [], []
    for path, field, src in collect(pack_dirs):
        if field in blocked:
            errors.append((path, field, src, blocked[field]))
        elif field in warn:
            warnings.append((path, field, src, warn[field]))
    return errors, warnings


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("packs", nargs="*", help="pack directories (default: every Packs/*)")
    ap.add_argument("--policy", default=POLICY)
    args = ap.parse_args(argv)
    packs = args.packs or sorted(p for p in glob.glob(os.path.join(REPO, "Packs", "*")) if os.path.isdir(p))
    packs = [os.path.abspath(p) for p in packs]

    errors, warnings = check(packs, args.policy)
    for path, field, src, why in warnings:
        print(f"  WARN  {path}: {field} <- {src}\n        {why}")
    for path, field, src, why in errors:
        print(f"  FAIL  {path}: {field} <- {src}\n        {why}")
    if errors:
        print(f"\n  {len(errors)} mapping(s) write into a platform-owned issue field. Remove the mapping"
              "\n  from the contract, re-emit the rule, and gate again. A rule copied onto a tenant"
              "\n  needs the same line removed by hand.")
        return 1
    print(f"  OK  no blocked issue-field targets in {len(packs)} pack(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
