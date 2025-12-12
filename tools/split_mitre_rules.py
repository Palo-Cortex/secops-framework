#!/usr/bin/env python3
"""
split_mitre_rules.py (FIXED)

- Splits one XSIAM correlation rule YAML into per-tactic rules + optional catch-all.
- Inserts a filter immediately AFTER the Split Anchor assignment lines:
    mitre_tactic       =
    mitre_tactic_id    =
    mitre_technique    =
    mitre_technique_id =

Fixes:
- SafeDumper representer registration for LiteralStr (prevents RepresenterError)
- Regex matching for real assignment lines (prevents substring collisions)
- Force xql_query to YAML literal block scalar '|'
- Prevent duplicate filter injection on re-run
"""

import argparse
import copy
import os
import re
import sys
from typing import Dict, List, Tuple, Optional

import yaml

TACTICS: List[Tuple[str, str]] = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

# --- YAML helper: force xql_query to dump as literal block scalar (|) ---
class LiteralStr(str):
    pass

def _literal_str_representer(dumper: yaml.Dumper, data: LiteralStr):
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style="|")

# IMPORTANT: register on SafeDumper (safe_dump uses SafeDumper)
yaml.SafeDumper.add_representer(LiteralStr, _literal_str_representer)


# --- Regex patterns to match REAL assignment lines (not substrings) ---
ASSIGN_PATTERNS = {
    "mitre_tactic": re.compile(r"^\s*mitre_tactic\s*=", re.IGNORECASE),
    "mitre_tactic_id": re.compile(r"^\s*mitre_tactic_id\s*=", re.IGNORECASE),
    "mitre_technique": re.compile(r"^\s*mitre_technique\s*=", re.IGNORECASE),
    "mitre_technique_id": re.compile(r"^\s*mitre_technique_id\s*=", re.IGNORECASE),
}

SPLIT_FILTER_MARKER = re.compile(
    r'^\s*\|\s*filter\s+mitre_tactic_id\s*=\s*".*?"\s+or\s+mitre_tactic\s*=\s*".*?"\s*$',
    re.IGNORECASE,
)
CATCHALL_FILTER_MARKER = re.compile(
    r'^\s*\|\s*filter\s+mitre_tactic_id\s*=\s*""\s+and\s+mitre_tactic\s*=\s*""\s*$',
    re.IGNORECASE,
)

def _already_has_filter(lines: List[str], filter_line: str) -> bool:
    if any(l.strip() == filter_line.strip() for l in lines):
        return True
    if 'mitre_tactic_id = "" and mitre_tactic = ""' in filter_line:
        return any(CATCHALL_FILTER_MARKER.match(l) for l in lines)
    return any(SPLIT_FILTER_MARKER.match(l) for l in lines)


def insert_filter_after_split_anchor(xql_query: str, filter_line: str) -> str:
    lines = xql_query.split("\n")

    if _already_has_filter(lines, filter_line):
        return xql_query

    indices: Dict[str, Optional[int]] = {k: None for k in ASSIGN_PATTERNS.keys()}

    for idx, line in enumerate(lines):
        for key, pat in ASSIGN_PATTERNS.items():
            if indices[key] is None and pat.search(line):
                indices[key] = idx

    missing = [k for k, v in indices.items() if v is None]
    if missing:
        raise ValueError(
            "Split Anchor not found. Missing assignment line(s): "
            + ", ".join(missing)
            + "\nYour base XQL must include explicit lines like:\n"
              "  mitre_tactic       = ...\n"
              "  mitre_tactic_id    = ...\n"
              "  mitre_technique    = ...\n"
              "  mitre_technique_id = ...\n"
        )

    insert_idx = max(v for v in indices.values() if v is not None) + 1
    new_lines = lines[:insert_idx] + [filter_line] + lines[insert_idx:]
    return "\n".join(new_lines)


def sanitize_global_id(s: str) -> str:
    s = (s or "").strip().replace(" ", "_")
    s = re.sub(r"[^A-Za-z0-9._-]", "_", s)
    s = re.sub(r"__+", "_", s)
    return s


def make_tactic_rule(base_rule: dict, tactic_id: str, tactic_name: str) -> dict:
    rule = copy.deepcopy(base_rule)

    base_name = base_rule.get("name", "")
    base_global_id = base_rule.get("global_rule_id", "")
    base_mitre = base_rule.get("mitre_defs", {}) or {}
    base_xql = str(base_rule.get("xql_query", ""))

    rule["name"] = f"{base_name} - {tactic_name}"
    gid = sanitize_global_id(base_global_id)
    rule["global_rule_id"] = f"{gid}_{tactic_id.lower()}"

    key = f"{tactic_id} - {tactic_name}"
    rule["mitre_defs"] = {key: base_mitre.get(key, [])}

    filter_line = f'| filter mitre_tactic_id = "{tactic_id}" or mitre_tactic = "{tactic_name}"'
    rule["xql_query"] = LiteralStr(insert_filter_after_split_anchor(base_xql, filter_line))
    return rule


def make_catch_all_rule(base_rule: dict) -> dict:
    rule = copy.deepcopy(base_rule)

    base_name = base_rule.get("name", "")
    base_global_id = base_rule.get("global_rule_id", "")
    base_xql = str(base_rule.get("xql_query", ""))

    rule["name"] = f"{base_name} - Other or Unknown Tactic"
    gid = sanitize_global_id(base_global_id)
    rule["global_rule_id"] = f"{gid}_other"
    rule.pop("mitre_defs", None)

    filter_line = '| filter mitre_tactic_id = "" and mitre_tactic = ""'
    rule["xql_query"] = LiteralStr(insert_filter_after_split_anchor(base_xql, filter_line))
    return rule


def load_base_rule(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        if not data:
            raise ValueError("YAML file contains an empty list; no rule to process.")
        if not isinstance(data[0], dict):
            raise ValueError("First item in YAML list is not a dict; cannot use as a rule.")
        return data[0]

    raise ValueError("YAML root is neither a dict nor a list of dicts; unsupported format.")


def dump_rule(path: str, rule: dict) -> None:
    if "xql_query" in rule and not isinstance(rule["xql_query"], LiteralStr):
        rule["xql_query"] = LiteralStr(str(rule["xql_query"]))

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            rule,
            f,
            sort_keys=False,
            default_flow_style=False,
            width=10_000,
            allow_unicode=True,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Split a correlation rule into per-tactic rules + catch-all.")
    parser.add_argument("-i", "--input", required=True, help="Base rule YAML (must include Split Anchor).")
    parser.add_argument("-o", "--out-dir", required=True, help="Output directory for generated rules.")
    parser.add_argument("--no-catch-all", action="store_true", help="Do not generate the catch-all rule.")
    parser.add_argument("--only-tactics", help="Comma-separated list of tactic IDs (e.g. 'TA0002,TA0040').")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"ERROR: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.out_dir, exist_ok=True)

    base_rule = load_base_rule(args.input)
    if "xql_query" not in base_rule:
        print("ERROR: input YAML does not have an 'xql_query' field.", file=sys.stderr)
        sys.exit(1)

    base_stem = os.path.splitext(os.path.basename(args.input))[0]

    tactics = TACTICS
    if args.only_tactics:
        wanted = set(t.strip().upper() for t in args.only_tactics.split(",") if t.strip())
        tactics = [t for t in TACTICS if t[0] in wanted]

    for tid, tname in tactics:
        rule = make_tactic_rule(base_rule, tid, tname)
        out_path = os.path.join(args.out_dir, f"{base_stem}_{tid.lower()}.yml")
        dump_rule(out_path, rule)
        print(f"Wrote tactic rule: {tid} - {tname} -> {out_path}")

    if not args.no_catch_all:
        catch = make_catch_all_rule(base_rule)
        out_path = os.path.join(args.out_dir, f"{base_stem}_other.yml")
        dump_rule(out_path, catch)
        print(f"Wrote catch-all rule -> {out_path}")


if __name__ == "__main__":
    main()
