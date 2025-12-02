#!/usr/bin/env python3
"""
json_to_correlation_yml.py

Convert exported XSIAM correlation rule JSON into YAML suitable
as a starting point for pack content.

- If the JSON root is a *list*, each element becomes a separate YAML document.
- If the JSON root is an *object*:
    - If it has a "rules" key that is a list, we treat that as the rules list.
    - Otherwise we emit a single YAML document.

This script also normalizes each rule so demisto-sdk validate
will accept it as a correlation rule pack item, by:

- Ensuring a non-empty 'global_rule_id' (used as the rule's logical id).
- Forcing rule_id = 0.
- Adding fromVersion if missing.
- Marking adopted: true (optional but matches your working template).

Usage:
    python json_to_correlation_yml.py rules.json > rules.yml
    python json_to_correlation_yml.py rules.json -o Packs/soc-crowdstrike-falcon/CorrelationRules/MyRule.yml
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

try:
    import yaml
except ImportError:
    print("This script requires PyYAML. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def normalize_root(obj: Any) -> List[Dict[str, Any]]:
    """
    Normalize the JSON root into a list of rule objects.

    - If already a list -> return as-is.
    - If dict with 'rules' key that is a list -> use that.
    - Else -> wrap single object in a list.
    """
    if isinstance(obj, list):
        return obj

    if isinstance(obj, dict) and isinstance(obj.get("rules"), list):
        return obj["rules"]

    return [obj]


def massage_rule(rule: Dict[str, Any], idx: int) -> Dict[str, Any]:
    """
    Take a raw correlation rule export (like the JSON you pasted)
    and make it look like a pack correlation rule, using your
    working YAML as a behavioral template.

    - Ensure non-empty 'name'.
    - Ensure non-empty 'global_rule_id' (this is what demisto-sdk uses as "id").
    - Normalize 'rule_id' to 0 for pack content.
    - Add fromVersion if missing.
    - Add adopted: true if missing.
    - Optionally strip some tenant-only noise keys.
    """
    r = dict(rule)  # shallow copy so we don't mutate the original

    # 1) Ensure name
    name = r.get("name") or f"Correlation Rule {idx + 1}"
    r["name"] = name

    # 2) Ensure global_rule_id (critical for demisto-sdk's Pack -> CorrelationRule -> id mapping)
    if not r.get("global_rule_id"):
        # You can adjust this if you want a different naming convention
        r["global_rule_id"] = name

    # 3) For pack content, rule_id should be 0 (tenant will assign real id)
    r["rule_id"] = 0

    # 4) Ensure fromVersion (adjust to your baseline XSIAM version)
    if "fromVersion" not in r and "fromversion" not in r:
        r["fromVersion"] = "6.10.0"

    # 5) Mark as adopted so it behaves like your template rule
    if "adopted" not in r:
        r["adopted"] = True

    # 6) Optionally strip tenant-only / noisy keys if they ever appear
    for k in ("_id", "modified", "created", "locked", "system", "packID", "packName"):
        r.pop(k, None)

    return r


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert correlation rule JSON to YAML.")
    parser.add_argument("input", help="Input JSON file exported from XSIAM")
    parser.add_argument(
        "-o",
        "--output",
        help=(
            "Output YAML file (default: stdout). "
            "If the JSON contains multiple rules, emits multiple YAML documents separated by '---'."
        ),
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    data = load_json(input_path)
    rules = normalize_root(data)

    # Decide output stream
    if args.output:
        out_path = Path(args.output)
        out_fh = out_path.open("w", encoding="utf-8")
        close_out = True
    else:
        out_fh = sys.stdout
        close_out = False

    try:
        for idx, raw_rule in enumerate(rules):
            rule = massage_rule(raw_rule, idx)

            yaml.safe_dump(
                rule,
                out_fh,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )

            # Separate multiple rules with '---'
            if idx != len(rules) - 1:
                out_fh.write("\n---\n\n")
    finally:
        if close_out:
            out_fh.close()


if __name__ == "__main__":
    main()
