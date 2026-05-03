#!/usr/bin/env python3
"""
generate_soc_framework_content.py
=================================
Generate XSIAM SOC Framework pack content (Lists) from a per-list mapping YAML.

One YAML file per generated list. Each file declares:
  - identity (pack / list_name / description)
  - categories (lifecycle status + shape per product category)
  - state    (documentation only — framework keys outside the list payload)
  - mappings (the rows emitted into the list_data payload)

Subcommands:
  validate  --mapping <yaml>                          Structural + drift gate
  emit      --mapping <yaml> --pack-root <pack>       Emit list (validates first)
  roundtrip --mapping <yaml> --pack-root <pack>       Regenerate to temp + diff vs shipped

Design tenets (mirrors generate_vendor_content.py):
  * Targeted output assembly — schemas are read with yaml.safe_load,
    list payload is emitted as JSON. yaml.dump is forbidden anywhere
    (reorders keys, corrupts XSIAM Upon Trigger / list semantics).
  * Drift gate: schema `categories` keys must align with distinct
    `category` values in SOCProductCategoryMap_V3. validate exits 1 on
    drift; emit refuses unless --allow-drift.
  * Validation refuses to emit malformed schemas, same as the vendor
    generator's emit path.
"""
from __future__ import annotations

import argparse
import difflib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml


REQUIRED_FILE_FIELDS    = {"pack", "list_name", "description", "categories", "mappings"}
OPTIONAL_FILE_FIELDS    = {"stamps", "mirrors"}
REQUIRED_CATEGORY_FIELDS = {"status", "shape"}
REQUIRED_MAPPING_FIELDS  = {"category", "target", "issue_field", "shape"}
REQUIRED_STAMP_FIELDS    = {"category", "target", "value"}
REQUIRED_MIRROR_FIELDS   = {"category", "target", "source"}
ALLOWED_SHAPES           = {"structured", "flat"}


# ----------------------------- IO helpers ------------------------------------

def load_yaml(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


# ----------------------------- Validation ------------------------------------

def validate_mapping(doc: dict) -> list[str]:
    """Validate the per-list mapping document. Returns list of error strings."""
    errors: list[str] = []

    for f in REQUIRED_FILE_FIELDS:
        if f not in doc:
            errors.append(f"missing required top-level field: {f}")
    if errors:
        return errors

    cats = doc.get("categories", {})
    if not isinstance(cats, dict) or not cats:
        errors.append("categories must be a non-empty mapping")
    else:
        for cat, meta in cats.items():
            if not isinstance(meta, dict):
                errors.append(f"categories.{cat} must be a mapping")
                continue
            for f in REQUIRED_CATEGORY_FIELDS:
                if f not in meta:
                    errors.append(f"categories.{cat} missing required field: {f}")

    mappings = doc.get("mappings", [])
    if not isinstance(mappings, list):
        errors.append("mappings must be a list")
    else:
        seen: set[tuple[str, str]] = set()
        for i, m in enumerate(mappings):
            if not isinstance(m, dict):
                errors.append(f"mappings[{i}] must be a mapping")
                continue
            for f in REQUIRED_MAPPING_FIELDS:
                if f not in m:
                    errors.append(f"mappings[{i}] missing required field: {f}")
            if m.get("shape") not in ALLOWED_SHAPES:
                errors.append(f"mappings[{i}] invalid shape: {m.get('shape')!r}")
            if m.get("category") not in cats:
                errors.append(f"mappings[{i}] references unknown category: {m.get('category')!r}")
            key = (m.get("target"), m.get("issue_field"))
            if key in seen:
                errors.append(f"mappings[{i}] duplicate (target, issue_field): {key}")
            seen.add(key)

    # stamps (optional)
    for i, s in enumerate(doc.get("stamps", []) or []):
        if not isinstance(s, dict):
            errors.append(f"stamps[{i}] must be a mapping")
            continue
        for f in REQUIRED_STAMP_FIELDS:
            if f not in s:
                errors.append(f"stamps[{i}] missing required field: {f}")
        if s.get("category") not in cats:
            errors.append(f"stamps[{i}] references unknown category: {s.get('category')!r}")

    # mirrors (optional)
    for i, m in enumerate(doc.get("mirrors", []) or []):
        if not isinstance(m, dict):
            errors.append(f"mirrors[{i}] must be a mapping")
            continue
        for f in REQUIRED_MIRROR_FIELDS:
            if f not in m:
                errors.append(f"mirrors[{i}] missing required field: {f}")
        if m.get("category") not in cats:
            errors.append(f"mirrors[{i}] references unknown category: {m.get('category')!r}")

    return errors


def load_category_map(pack_root: Path) -> set[str]:
    """Load distinct lowercase category values from SOCProductCategoryMap_V3 in pack_root."""
    p = pack_root / "Lists" / "SOCProductCategoryMap_V3" / "SOCProductCategoryMap_V3_data.json"
    if not p.exists():
        return set()
    data = json.loads(p.read_text())
    return {
        v["category"].lower()
        for v in data.values()
        if isinstance(v, dict) and v.get("category")
    }


def check_category_drift(doc: dict, pack_root: Path) -> tuple[set[str], set[str]]:
    """Return (in_schema_only, in_map_only).

    Asymmetric semantics enforced by the caller:
      - in_schema_only is an ERROR (schema would normalize categories the
        framework's product classification doesn't recognize)
      - in_map_only is INFO (categories with no Foundation_-_Normalize_<Cat>_V3
        playbook yet — expected when scoping incremental rollout)
    """
    schema_cats = set(doc["categories"].keys())
    map_cats    = load_category_map(pack_root)
    if not map_cats:
        return set(), set()  # map missing — caller handles
    return schema_cats - map_cats, map_cats - schema_cats


# ----------------------------- Emission --------------------------------------

def build_list_data(doc: dict) -> dict:
    """Render the schema's mappings/stamps/mirrors as the list payload, grouped by category.

    Each category contains:
      - status, shape (metadata)
      - mappings: [{target, issue_field, shape}, ...]
      - stamps:   [{target, value}, ...]
      - mirrors:  [{target, source}, ...]

    Consumer scripts apply mappings → stamps → mirrors in that order.
    """
    payload: dict[str, dict] = {}
    for cat, meta in doc["categories"].items():
        payload[cat] = {
            "status":   meta["status"],
            "shape":    meta["shape"],
            "mappings": [],
            "stamps":   [],
            "mirrors":  [],
        }
    for m in doc.get("mappings", []) or []:
        payload[m["category"]]["mappings"].append({
            "target":      m["target"],
            "issue_field": m["issue_field"],
            "shape":       m["shape"],
        })
    for s in doc.get("stamps", []) or []:
        payload[s["category"]]["stamps"].append({
            "target": s["target"],
            "value":  s["value"],
        })
    for m in doc.get("mirrors", []) or []:
        payload[m["category"]]["mirrors"].append({
            "target": m["target"],
            "source": m["source"],
        })
    return payload


def list_descriptor(list_name: str, description: str) -> dict:
    """XSIAM List descriptor JSON. Mirrors SOCProductCategoryMap_V3 shape."""
    return {
        "allRead":              True,
        "allReadWrite":         True,
        "cacheVersn":           0,
        "data":                 "-",
        "definitionId":         "",
        "description":          description,
        "detached":             False,
        "fromServerVersion":    "6.5.0",
        "id":                   list_name,
        "isOverridable":        False,
        "itemVersion":          "1.0.0",
        "locked":               False,
        "name":                 list_name,
        "nameLocked":           False,
        "packID":               "",
        "packName":             "",
        "previousAllRead":      True,
        "previousAllReadWrite": True,
        "system":               False,
        "tags":                 None,
        "toServerVersion":      "",
        "truncated":            False,
        "type":                 "json",
        "version":              -1,
        "fromVersion":          "6.5.0",
        "display_name":         list_name,
    }


def emit_list(doc: dict, pack_root: Path) -> list[Path]:
    """Emit list descriptor + data files. Returns paths emitted."""
    list_name = doc["list_name"]
    list_dir  = pack_root / "Lists" / list_name
    list_dir.mkdir(parents=True, exist_ok=True)

    descriptor_path = list_dir / f"{list_name}.json"
    data_path       = list_dir / f"{list_name}_data.json"

    write_json(descriptor_path, list_descriptor(list_name, doc["description"]))
    write_json(data_path,       build_list_data(doc))

    return [descriptor_path, data_path]


def emit_all(doc: dict, pack_root: Path) -> list[Path]:
    """Top-level emit entry. Mirrors generate_vendor_content.emit_all signature."""
    return emit_list(doc, pack_root)


# ----------------------------- Roundtrip -------------------------------------

def _normalize(text: str) -> str:
    out = []
    for line in text.splitlines():
        line = line.rstrip()
        if line.strip():
            out.append(line)
    return "\n".join(out)


def roundtrip(mapping_path: Path, pack_root: Path) -> int:
    doc = load_yaml(mapping_path)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp) / "regen"
        regenerated = emit_all(doc, tmp_root)

        drift_lines: list[str] = []
        for regen_path in regenerated:
            rel = regen_path.relative_to(tmp_root)
            shipped = pack_root / rel
            if not shipped.exists():
                drift_lines.append(f"shipped file missing: {shipped}")
                continue
            r_norm = _normalize(regen_path.read_text())
            s_norm = _normalize(shipped.read_text())
            if r_norm != s_norm:
                drift_lines.append(f"DRIFT: {rel}")
                diff = list(difflib.unified_diff(
                    s_norm.splitlines(), r_norm.splitlines(),
                    fromfile=f"shipped/{rel}", tofile=f"regen/{rel}",
                    lineterm="", n=2,
                ))
                drift_lines.extend(diff[:30])
            else:
                drift_lines.append(f"OK: {rel}")

    print("\n".join(drift_lines))
    return 0 if all("DRIFT" not in l and "missing" not in l for l in drift_lines) else 1


# ----------------------------- CLI -------------------------------------------

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="generate_soc_framework_content")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_val = sub.add_parser("validate", help="Validate mapping document + check drift")
    p_val.add_argument("--mapping",   type=Path, required=True)
    p_val.add_argument("--pack-root", type=Path, required=False,
                       help="Optional: pack root for drift check against SOCProductCategoryMap_V3")

    p_emit = sub.add_parser("emit", help="Emit list (validates first)")
    p_emit.add_argument("--mapping",     type=Path, required=True)
    p_emit.add_argument("--pack-root",   type=Path, required=True)
    p_emit.add_argument("--allow-drift", action="store_true",
                        help="Emit even if categories diverge from SOCProductCategoryMap_V3")

    p_rt = sub.add_parser("roundtrip", help="Regenerate to temp + diff vs shipped")
    p_rt.add_argument("--mapping",   type=Path, required=True)
    p_rt.add_argument("--pack-root", type=Path, required=True)

    args = parser.parse_args(argv)
    doc = load_yaml(args.mapping)

    # Structural validation
    errors = validate_mapping(doc)
    if errors:
        print("VALIDATION FAILED:")
        for e in errors:
            print(f"  - {e}")
        if args.cmd in ("emit", "roundtrip"):
            return 1
        return 1

    # Drift check applies only to validate + emit. Roundtrip is about
    # schema/shipped sync, not category alignment.
    drift_pack_root = getattr(args, "pack_root", None) if args.cmd in ("validate", "emit") else None
    if drift_pack_root and (drift_pack_root / "Lists" / "SOCProductCategoryMap_V3").exists():
        schema_only, map_only = check_category_drift(doc, drift_pack_root)
        # Asymmetric: schema_only is the failure mode. map_only is informational.
        if schema_only:
            print("CATEGORY DRIFT — schema declares categories not in SOCProductCategoryMap_V3:")
            print(f"  {sorted(schema_only)}")
            print("  These would normalize data the framework's product classification")
            print("  doesn't recognize. Add ds_* entries to the map, or remove from schema.")
            if args.cmd == "emit" and not args.allow_drift:
                print("\nABORTED. Reconcile or use --allow-drift.", file=sys.stderr)
                return 2
            if args.cmd == "validate":
                return 1
            print("WARNING: --allow-drift set, emitting despite divergence.\n", file=sys.stderr)
        if map_only:
            print(f"INFO: categories in map but not yet in schema: {sorted(map_only)}")
            print("      (future categories — schema scope expands when their normalizer ships)")

    if args.cmd == "validate":
        print("VALIDATION OK")
        return 0

    if args.cmd == "emit":
        emitted = emit_all(doc, args.pack_root)
        for p in emitted:
            print(f"  emitted: {p}")
        data = build_list_data(doc)
        print(f"\n{doc['list_name']}: {len(data)} categories")
        for cat, c in data.items():
            print(f"  {cat:<10}  mappings={len(c['mappings']):3d}  "
                  f"stamps={len(c['stamps']):2d}  mirrors={len(c['mirrors']):2d}  "
                  f"status={c['status']}")
        return 0

    if args.cmd == "roundtrip":
        return roundtrip(args.mapping, args.pack_root)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
