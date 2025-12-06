#!/usr/bin/env python3
"""
split_mitre_rules.py

Take ONE working XSIAM correlation rule (YAML) and generate:

  - One rule per MITRE ATT&CK tactic
  - One catch-all rule when no tactic is provided

Contract / assumptions:

- The base rule's xql_query contains a MITRE normalization block that assigns:
    mitre_tactic
    mitre_tactic_id
    mitre_technique
    mitre_technique_id

  Example pattern:

    // XSIAM MITRE Normalization
    | alter
        tactic                 = if(tactic = "Malware","Execution",tactic),
        mitre_tactic           = tactic,
        mitre_tactic_id        = tactic_id,
        mitre_technique        = technique,
        mitre_technique_id     = technique_id

- We insert a filter line *immediately after* the last of those four
  assignment lines.

Per generated rule we change ONLY:

  - name
  - global_rule_id
  - mitre_defs   (removed entirely for catch-all)
  - xql_query    (inject ONE `| filter ...` line after the MITRE normalization block)

If we cannot find ALL FOUR assignments (mitre_tactic, mitre_tactic_id,
mitre_technique, mitre_technique_id) in the query, we raise an error.
"""

import argparse
import copy
import os
import sys

import yaml

# Enterprise ATT&CK tactics we care about
TACTICS = [
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


def insert_filter_after_mitre_normalization(xql_query, filter_line):
    """
    Find the block where mitre_tactic, mitre_tactic_id, mitre_technique,
    mitre_technique_id are being assigned and insert `filter_line`
    immediately AFTER that block.

    We detect this by locating the line indices that contain each of:
        "mitre_tactic"
        "mitre_tactic_id"
        "mitre_technique"
        "mitre_technique_id"

    If any of these four are missing, we raise a ValueError.

    The filter line is inserted after the *last* of those lines.
    """
    lines = xql_query.split("\n")

    keys = {
        "mitre_tactic": None,
        "mitre_tactic_id": None,
        "mitre_technique": None,
        "mitre_technique_id": None,
    }

    for idx, line in enumerate(lines):
        for k in keys:
            if keys[k] is None and k in line:
                keys[k] = idx

    missing = [k for k, v in keys.items() if v is None]
    if missing:
        raise ValueError(
            "Could not find assignments for all MITRE fields in xql_query. "
            "Missing: %s" % ", ".join(missing)
        )

    insert_idx = max(keys.values()) + 1  # insert after the last assignment line
    new_lines = lines[:insert_idx] + [filter_line] + lines[insert_idx:]
    return "\n".join(new_lines)


def make_tactic_rule(base_rule, tactic_id, tactic_name):
    """
    Clone base rule for a single MITRE tactic.

    Changes:
      - name
      - global_rule_id
      - mitre_defs
      - xql_query (insert '| filter mitre_tactic_id = "<ID>" or mitre_tactic = "<Name>"'
                   immediately after MITRE normalization block)
    """
    rule = copy.deepcopy(base_rule)

    base_name = base_rule.get("name", "")
    base_global_id = base_rule.get("global_rule_id", "")
    base_mitre = base_rule.get("mitre_defs", {}) or {}
    base_xql = base_rule.get("xql_query", "")

    # Name
    rule["name"] = "%s - %s" % (base_name, tactic_name)

    # global_rule_id
    rule["global_rule_id"] = "%s_%s" % (base_global_id, tactic_id.lower())

    # mitre_defs (scope to this tactic)
    key = "%s - %s" % (tactic_id, tactic_name)
    techniques = base_mitre.get(key, [])
    rule["mitre_defs"] = {key: techniques}

    # xql_query: filter on normalized MITRE fields
    filter_line = (
            '| filter mitre_tactic_id = "%s" or mitre_tactic = "%s"'
            % (tactic_id, tactic_name)
    )
    rule["xql_query"] = insert_filter_after_mitre_normalization(base_xql, filter_line)

    return rule


def make_catch_all_rule(base_rule):
    """
    Clone base rule for a catch-all rule:

      - Name: <base_name> - Other or Unknown Tactic
      - global_rule_id: <base_global_id>_other
      - mitre_defs removed
      - xql_query: insert a "no MITRE tactic provided" filter after normalization block:

            | filter mitre_tactic_id = "" and mitre_tactic = ""

        This guarantees no overlap with any specific tactic rule.
    """
    rule = copy.deepcopy(base_rule)

    base_name = base_rule.get("name", "")
    base_global_id = base_rule.get("global_rule_id", "")
    base_xql = base_rule.get("xql_query", "")

    rule["name"] = "%s - Other or Unknown Tactic" % base_name
    rule["global_rule_id"] = "%s_other" % base_global_id
    rule.pop("mitre_defs", None)

    # Catch-all ONLY when MITRE tactic truly not provided
    filter_line = '| filter mitre_tactic_id = "" and mitre_tactic = ""'

    rule["xql_query"] = insert_filter_after_mitre_normalization(base_xql, filter_line)

    return rule


def load_base_rule(path):
    """
    Load YAML from `path`.

    If the top-level is:
      - a dict -> return it
      - a list -> return the first element (must exist)
    Otherwise, raise.
    """
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


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Split a single XSIAM correlation rule into per-MITRE-tactic rules + "
            "catch-all, inserting a mitre_tactic/mitre_tactic_id filter immediately "
            "after the MITRE normalization block. Raises an error if that block "
            "isn't found."
        ),
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Base rule YAML (the one that installs today).",
    )
    parser.add_argument(
        "-o", "--out-dir", required=True,
        help="Output directory for generated rules.",
    )
    parser.add_argument(
        "--no-catch-all",
        action="store_true",
        help="Do not generate the catch-all rule.",
    )
    parser.add_argument(
        "--only-tactics",
        help="Comma-separated list of tactic IDs (e.g. 'TA0002,TA0040'). "
             "Defaults to all tactics in the script.",
    )
    args = parser.parse_args()

    in_path = args.input
    out_dir = args.out_dir

    if not os.path.exists(in_path):
        print("ERROR: Input file not found: %s" % in_path, file=sys.stderr)
        sys.exit(1)

    os.makedirs(out_dir, exist_ok=True)

    # Load base rule (handles dict OR list-of-dict YAML)
    base_rule = load_base_rule(in_path)

    if "xql_query" not in base_rule:
        print("ERROR: input YAML does not have an 'xql_query' field.", file=sys.stderr)
        sys.exit(1)

    base_stem = os.path.splitext(os.path.basename(in_path))[0]

    # Tactic subset
    tactics = TACTICS
    if args.only_tactics:
        wanted = set(t.strip().upper() for t in args.only_tactics.split(","))
        tactics = [t for t in TACTICS if t[0] in wanted]

    # Per-tactic rules
    for tid, tname in tactics:
        rule = make_tactic_rule(base_rule, tid, tname)
        out_name = "%s_%s.yml" % (base_stem, tid.lower())
        out_path = os.path.join(out_dir, out_name)
        with open(out_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(rule, f, sort_keys=False)
        print("Wrote tactic rule: %s - %s -> %s" % (tid, tname, out_path))

    # Catch-all rule
    if not args.no_catch_all:
        catch = make_catch_all_rule(base_rule)
        out_name = "%s_other.yml" % base_stem
        out_path = os.path.join(out_dir, out_name)
        with open(out_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(catch, f, sort_keys=False)
        print("Wrote catch-all rule: Other or Unknown Tactic -> %s" % out_path)


if __name__ == "__main__":
    main()
