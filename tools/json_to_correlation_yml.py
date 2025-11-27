#!/usr/bin/env python3
"""
json_to_correlation_yml.py

Tiny helper to convert exported XSIAM correlation rule JSON into YAML
suitable as a starting point for pack content.

- If the JSON root is a *list*, each element becomes a separate YAML document.
- If the JSON root is an *object*:
    - If it has a "rules" key that is a list, we treat that as the rules list.
    - Otherwise we emit a single YAML document.

Usage:
    python json_to_correlation_yml.py rules.json > rules.yml
    python json_to_correlation_yml.py rules.json -o rules.yml
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("This script requires PyYAML. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def normalize_root(obj):
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


def main():
    parser = argparse.ArgumentParser(description="Convert correlation rule JSON to YAML.")
    parser.add_argument("input", help="Input JSON file exported from XSIAM")
    parser.add_argument(
        "-o", "--output",
        help="Output YAML file (default: stdout). If multiple rules, emits multiple docs separated by '---'."
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
        for idx, rule in enumerate(rules):
            # You can customize per-rule massaging here, e.g.:
            # rule.setdefault("contentitemexportablefields", {"contentitemtype": "correlation_rule"})
            # rule.setdefault("fromVersion", "8.6.0")

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
