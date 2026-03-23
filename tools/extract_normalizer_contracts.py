#!/usr/bin/env python3
"""
extract_normalizer_contracts.py
--------------------------------
Reads Foundation normalizer playbooks from the soc-optimization-unified pack
and writes a machine-readable JSON contract documenting every field mapping:

    source (issue.* or blob field)
    → target (SOCFramework.* context key)

Output: tools/output/normalizer_contracts.json

Usage:
    python3 tools/extract_normalizer_contracts.py
    python3 tools/extract_normalizer_contracts.py --root Packs/soc-optimization-unified
    python3 tools/extract_normalizer_contracts.py --out path/to/output.json

The contract JSON is structured as:

{
  "generated": "<ISO timestamp>",
  "pack_version": "<version from pack_metadata.json>",
  "normalizers": {
    "Email": {
      "playbook": "Foundation_-_Normalize_Email_V3",
      "fields": [
        {
          "target": "SOCFramework.Email.sender",
          "source": "issue.fw_email_sender",
          "source_type": "issue_field",
          "nullable": true,
          "notes": ""
        },
        ...
      ]
    },
    "Generic": { ... },
    ...
  },
  "coverage_summary": {
    "Email": { "total": 12, "from_issue": 10, "from_blob": 2, "derived": 0 },
    ...
  }
}

Source types:
  issue_field   — reads from issue.* (guaranteed if MR/correlation rule promotes it)
  blob_field    — reads from a context variable set by the correlation rule blob
  derived       — computed from other fields, no direct issue.* source
  input         — passed as a playbook input from Upon Trigger
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. Run: pip install pyyaml --break-system-packages")
    sys.exit(1)


# ── Constants ──────────────────────────────────────────────────────────────────

NORMALIZER_PREFIX = "Foundation_-_Normalize_"
SET_SCRIPTS = {"SetAndHandleEmpty", "Set", "setIncident"}

# Patterns for classifying source field types
ISSUE_FIELD_RE = re.compile(r"\$\{issue\.([^}]+)\}", re.IGNORECASE)
BLOB_FIELD_RE = re.compile(r"\$\{(?!issue\.)([^}]+)\}", re.IGNORECASE)
SOCFW_KEY_RE = re.compile(r"SOCFramework\.[A-Za-z.]+")


# ── Path detection ─────────────────────────────────────────────────────────────

def detect_repo_root(start: str) -> str:
    try:
        import subprocess
        res = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, check=True
        )
        root = (res.stdout or "").strip()
        if root:
            return root
    except Exception:
        pass
    cur = os.path.abspath(start)
    while True:
        if os.path.isdir(os.path.join(cur, "Packs")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return start
        cur = parent


# ── YAML helpers ───────────────────────────────────────────────────────────────

def load_yaml(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"  WARN: could not parse {path}: {e}")
        return {}


def get_pack_version(pack_root: str) -> str:
    meta_path = os.path.join(pack_root, "pack_metadata.json")
    try:
        with open(meta_path) as f:
            return json.load(f).get("currentVersion", "unknown")
    except Exception:
        return "unknown"


# ── Field extraction ───────────────────────────────────────────────────────────

def classify_source(value_str: str) -> tuple[str, str]:
    """
    Given a raw value string from a playbook task scriptargument,
    return (source_field, source_type).

    source_type is one of: issue_field, blob_field, derived, literal
    """
    if not value_str:
        return ("", "derived")

    # Check for issue.* reference
    m = ISSUE_FIELD_RE.search(value_str)
    if m:
        return (f"issue.{m.group(1)}", "issue_field")

    # Check for other context reference (blob or playbook context)
    m = BLOB_FIELD_RE.search(value_str)
    if m:
        # If it references another SOCFramework key it's derived
        if "SOCFramework." in value_str:
            return (value_str.strip("${}"), "derived")
        return (value_str.strip("${}"), "blob_field")

    # Plain value with no template — treat as derived/constant
    return (value_str, "derived")


def extract_set_tasks(tasks: dict) -> list[dict]:
    """
    Walk all tasks in a playbook and extract Set/SetAndHandleEmpty mappings
    that write to SOCFramework.* keys.
    """
    mappings = []

    for task_id, task_data in tasks.items():
        if not isinstance(task_data, dict):
            continue

        task = task_data.get("task", {})
        script_name = task.get("scriptName", "")

        if script_name not in SET_SCRIPTS:
            continue

        script_args = task_data.get("scriptarguments", {})
        key_arg = script_args.get("key", {})
        value_arg = script_args.get("value", {})

        # Extract target key
        target = ""
        if isinstance(key_arg, dict):
            target = key_arg.get("simple", "")
        elif isinstance(key_arg, str):
            target = key_arg

        # Only capture SOCFramework.* targets
        if not target.startswith("SOCFramework."):
            continue

        # Extract source value
        source_str = ""
        if isinstance(value_arg, dict):
            simple = value_arg.get("simple", "")
            complex_val = value_arg.get("complex", {})
            if simple:
                source_str = simple
            elif complex_val:
                root = complex_val.get("root", "")
                accessor = complex_val.get("accessor", "")
                source_str = f"${{{root}.{accessor}}}" if accessor else f"${{{root}}}"

        source_field, source_type = classify_source(source_str)

        task_name = task.get("name", f"task_{task_id}")
        nullable = task_data.get("continueonerror", False)

        mappings.append({
            "target": target,
            "source": source_field,
            "source_type": source_type,
            "nullable": nullable,
            "task_name": task_name,
            "notes": ""
        })

    return mappings


def extract_input_mappings(playbook: dict) -> list[dict]:
    """
    Extract playbook inputs that map issue.* fields — these are the
    Upon Trigger → normalizer input contracts.
    """
    mappings = []
    for inp in playbook.get("inputs", []):
        key = inp.get("key", "")
        value = inp.get("value", {}) or {}
        simple = value.get("simple", "")
        source_field, source_type = classify_source(simple)
        mappings.append({
            "input_name": key,
            "source": source_field,
            "source_type": source_type,
        })
    return mappings


# ── Category detection ─────────────────────────────────────────────────────────

def detect_category(filename: str) -> str:
    """
    Extract category name from filename.
    Foundation_-_Normalize_Email_V3.yml → Email
    Foundation_-_Normalize_Generic_V3.yml → Generic
    """
    stem = Path(filename).stem  # e.g. Foundation_-_Normalize_Email_V3
    # Strip prefix and version suffix
    name = stem.replace("Foundation_-_Normalize_", "").replace("Foundation_-_Normalize", "")
    # Remove trailing _V<n>
    name = re.sub(r"_V\d+$", "", name)
    return name if name else "Unknown"


# ── Main extraction ────────────────────────────────────────────────────────────

def extract_contracts(pack_root: str) -> dict:
    playbooks_dir = os.path.join(pack_root, "Playbooks")
    if not os.path.isdir(playbooks_dir):
        print(f"ERROR: No Playbooks directory at {playbooks_dir}")
        sys.exit(1)

    contracts = {}

    normalizer_files = [
        f for f in os.listdir(playbooks_dir)
        if f.startswith(NORMALIZER_PREFIX) and f.endswith(".yml")
    ]

    if not normalizer_files:
        print(f"  WARN: No normalizer playbooks found matching {NORMALIZER_PREFIX}*.yml")
        print(f"  Found playbooks: {os.listdir(playbooks_dir)[:10]}")

    for filename in sorted(normalizer_files):
        path = os.path.join(playbooks_dir, filename)
        category = detect_category(filename)
        print(f"  Processing: {filename} → category: {category}")

        playbook = load_yaml(path)
        tasks = playbook.get("tasks", {})

        # Extract Set task mappings (SOCFramework.* writes)
        set_mappings = extract_set_tasks(tasks)

        # Extract input contract (issue.* → playbook inputs)
        input_mappings = extract_input_mappings(playbook)

        # Deduplicate — keep last occurrence per target key
        seen = {}
        for m in set_mappings:
            seen[m["target"]] = m
        deduped = sorted(seen.values(), key=lambda x: x["target"])

        contracts[category] = {
            "playbook": Path(filename).stem,
            "playbook_file": filename,
            "inputs": input_mappings,
            "fields": deduped,
        }

    return contracts


def build_coverage_summary(contracts: dict) -> dict:
    summary = {}
    for category, data in contracts.items():
        fields = data["fields"]
        summary[category] = {
            "total": len(fields),
            "from_issue": sum(1 for f in fields if f["source_type"] == "issue_field"),
            "from_blob": sum(1 for f in fields if f["source_type"] == "blob_field"),
            "derived": sum(1 for f in fields if f["source_type"] == "derived"),
            "nullable": sum(1 for f in fields if f.get("nullable")),
        }
    return summary


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Extract SOC Framework normalizer field contracts to JSON."
    )
    ap.add_argument(
        "--root",
        default=None,
        help="Path to soc-optimization-unified pack root. Auto-detected if not set."
    )
    ap.add_argument(
        "--out",
        default=None,
        help="Output JSON path. Defaults to output/normalizer_contracts.json"
    )
    args = ap.parse_args()

    # Resolve pack root
    if args.root:
        pack_root = os.path.abspath(args.root)
    else:
        repo_root = detect_repo_root(os.getcwd())
        pack_root = os.path.join(repo_root, "Packs", "soc-optimization-unified")

    if not os.path.isdir(pack_root):
        print(f"ERROR: Pack not found at {pack_root}")
        sys.exit(1)

    print(f"\n=== Extracting normalizer contracts from: {pack_root} ===\n")

    # Resolve output path
    if args.out:
        out_path = os.path.abspath(args.out)
    else:
        out_dir = os.path.join(detect_repo_root(os.getcwd()), "output")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "normalizer_contracts.json")

    pack_version = get_pack_version(pack_root)
    contracts = extract_contracts(pack_root)
    coverage = build_coverage_summary(contracts)

    output = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "pack_version": pack_version,
        "pack_root": pack_root,
        "normalizers": contracts,
        "coverage_summary": coverage,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n=== Contract written to: {out_path} ===\n")
    print("Coverage summary:")
    for category, stats in coverage.items():
        print(
            f"  {category:<20} "
            f"total={stats['total']:>3}  "
            f"issue={stats['from_issue']:>3}  "
            f"blob={stats['from_blob']:>3}  "
            f"derived={stats['derived']:>3}  "
            f"nullable={stats['nullable']:>3}"
        )

    # Warn about any targets with no source
    print("\nFields with no source (derived/empty) — review these:")
    for category, data in contracts.items():
        for field in data["fields"]:
            if not field["source"] or field["source_type"] == "derived":
                print(f"  [{category}] {field['target']} ← {field['source'] or '(empty)'}")


if __name__ == "__main__":
    main()
