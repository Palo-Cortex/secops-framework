#!/usr/bin/env python3
"""
generate_soc_framework_content.py
=================================
Generic generator for SOC Framework Lists. Each schema in
schemas/soc-framework/<pack>/<list>.yaml is self-describing — the generator
never needs per-app code changes.

REGISTRY MODEL
--------------
schemas/soc-framework/ is the registry. To add a new application (NIST IR,
threat-hunting, posture-management, agentic AI, ...), drop a new YAML in
schemas/soc-framework/<pack>/<list>.yaml. The generator reads it as-is.

SCHEMA STRUCTURE
----------------
Three top-level fields are reserved (consumed by the generator):

    pack:          target pack to emit into
    list_name:     XSIAM List name to emit
    description:   list description

Optionally, schemas may declare a `validation:` block describing structural
constraints. The generator enforces these generically:

    validation:
      required_blocks: [phases, categories, routing, writes]
      blocks:
        routing:
          type: list
          item_required: [phase, category, sub_playbook]
        phases:
          type: mapping
          item_required: [orchestrator, purpose]
      drift_gates:
        - kind: categories_subset_of_product_map
          source_block: categories         # for list-of-strings categories
          source_field: ~                  # or set if categories is mapping; ~ means use top-level keys
        - kind: routing_playbooks_exist
          block: routing
          field: sub_playbook
        - kind: cross_reference
          from_block: reads_from_phases
          from_field: source
          partition_field: from_phase
          to_block: writes
          to_field: target
          to_partition_field: phase

Everything not in the reserved set OR `validation:` is the LIST PAYLOAD —
emitted to <list_name>_data.json verbatim, as a JSON object whose top-level
keys are the schema's other top-level keys.

Schemas may shape their payload however they want. Two patterns common today:
  - Flat-rows-with-discriminator: top-level keys are list-of-objects with a
    discriminator field (e.g. `mappings: [{category: endpoint, ...}, ...]`).
    Generator does not regroup — it emits as-is.
  - Pre-grouped-by-key: schema author groups under a top-level dict per key.
    Generator emits as-is.

The default is "emit as-is". Schemas that want post-processing (e.g. group
mappings by category) declare it under `emit:` (see EMIT TRANSFORMS below).

EMIT TRANSFORMS (optional)
--------------------------
    emit:
      group_by:
        - block: mappings        # take this list
          key: category          # group on this field
          into: by_category      # under this name in output
          drop_key_in_items: true
        - block: routing
          key: phase
          into: routing_by_phase

If `emit:` is absent, the schema's body is emitted as-is. The transforms
are declarative — generator interprets them, no code per app.

DRIFT GATES (optional)
----------------------
Three generic drift kinds the generator implements (extensible by adding to
DRIFT_GATES table; not extensible per app — drift kinds are platform-level):

    categories_subset_of_product_map
        Asserts the schema's category list/keys is a subset of the distinct
        `category` values in SOCProductCategoryMap_V3 (auto-discovered via
        sibling soc-optimization-unified pack). map-only categories are INFO.

    routing_playbooks_exist
        Asserts every value at <block>[*].<field> resolves to a playbook YAML
        in <pack_root>/Playbooks/.

    cross_reference
        Asserts <from_block>[*].<from_field> exists in <to_block>[*].<to_field>
        when partitioned by <partition_field> == <to_partition_field>.

Subcommands:
  validate  --mapping <yaml>                          Structural + drift gate
  emit      --mapping <yaml> --pack-root <pack>       Emit list (validates first)
  roundtrip --mapping <yaml> --pack-root <pack>       Regenerate to temp + diff vs shipped

DESIGN TENETS
-------------
  * yaml.safe_load only. yaml.dump forbidden (reorders keys; breaks XSIAM).
  * Schema is the contract. Generator is dumb on purpose.
  * Three reserved keys (pack, list_name, description). Optional `validation:`
    and `emit:`. Everything else is payload.
  * No per-application code in this file. Adding NIST IR or any future app =
    drop a YAML; generator never changes.
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


RESERVED = {"pack", "list_name", "description", "validation", "emit"}


# ============================================================================
# IO
# ============================================================================

def load_yaml(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


# ============================================================================
# Common-required validation
# ============================================================================

COMMON_REQUIRED = {"pack", "list_name", "description"}


def validate_common(doc: dict) -> list[str]:
    errors: list[str] = []
    for f in COMMON_REQUIRED:
        if f not in doc:
            errors.append(f"missing required common field: {f}")
    return errors


# ============================================================================
# Declarative structural validation
# ============================================================================

def validate_structure(doc: dict) -> list[str]:
    """Apply the schema's own `validation:` block.

    `validation:` is optional. If present, the generator enforces
    `required_blocks` and per-block `item_required` fields generically.
    """
    spec = doc.get("validation") or {}
    errors: list[str] = []

    for block_name in spec.get("required_blocks") or []:
        if block_name not in doc:
            errors.append(f"missing required block: {block_name}")

    for block_name, block_spec in (spec.get("blocks") or {}).items():
        if block_name not in doc:
            continue  # required-ness is handled above; absence here is fine
        block = doc[block_name]
        kind = block_spec.get("type", "list")
        item_required = block_spec.get("item_required") or []

        if kind == "list":
            if not isinstance(block, list):
                errors.append(f"{block_name}: expected list, got {type(block).__name__}")
                continue
            for i, item in enumerate(block):
                if not isinstance(item, dict):
                    errors.append(f"{block_name}[{i}]: expected mapping")
                    continue
                for f in item_required:
                    if f not in item:
                        errors.append(f"{block_name}[{i}]: missing required field {f!r}")
        elif kind == "mapping":
            if not isinstance(block, dict):
                errors.append(f"{block_name}: expected mapping, got {type(block).__name__}")
                continue
            for key, item in block.items():
                if not isinstance(item, dict):
                    errors.append(f"{block_name}.{key}: expected mapping")
                    continue
                for f in item_required:
                    if f not in item:
                        errors.append(f"{block_name}.{key}: missing required field {f!r}")
        else:
            errors.append(f"{block_name}: unknown block type {kind!r}")

    return errors


# ============================================================================
# Declarative drift gates
# ============================================================================
# Each entry in `validation.drift_gates` declares one of these kinds.
# Generator implements them; schema authors only declare which apply.

def load_category_map(soc_unified_pack_root: Path) -> set[str]:
    p = soc_unified_pack_root / "Lists" / "SOCProductCategoryMap_V3" / "SOCProductCategoryMap_V3_data.json"
    if not p.exists():
        return set()
    data = json.loads(p.read_text())
    return {
        v["category"].lower()
        for v in data.values()
        if isinstance(v, dict) and v.get("category")
    }


def discover_soc_unified_root(target_pack_root: Path) -> Path | None:
    if target_pack_root.name == "soc-optimization-unified":
        return target_pack_root
    sibling = target_pack_root.parent / "soc-optimization-unified"
    if (sibling / "Lists" / "SOCProductCategoryMap_V3").exists():
        return sibling
    return None


def gate_categories_subset_of_product_map(doc: dict, gate: dict, pack_root: Path) -> list[tuple[str, str]]:
    """Schema's category set must be ⊆ SOCProductCategoryMap_V3 distinct categories.

    Reads either a list-of-strings block or the top-level keys of a mapping
    block. Configured by:

        source_block: categories
        source_field: ~        # or specify a field if items are dicts
    """
    map_root = discover_soc_unified_root(pack_root)
    if map_root is None:
        return []
    map_cats = load_category_map(map_root)
    if not map_cats:
        return []

    source_block = gate.get("source_block", "categories")
    source_field = gate.get("source_field")
    block = doc.get(source_block)
    if block is None:
        return [("error", f"drift gate references missing block: {source_block}")]

    schema_cats: set[str] = set()
    if isinstance(block, list):
        if source_field:
            for item in block:
                if isinstance(item, dict) and item.get(source_field):
                    schema_cats.add(str(item[source_field]))
        else:
            schema_cats = {str(x) for x in block}
    elif isinstance(block, dict):
        schema_cats = set(block.keys())

    schema_only = schema_cats - map_cats
    map_only    = map_cats - schema_cats
    out: list[tuple[str, str]] = []
    if schema_only:
        out.append(("error", f"schema categories not in SOCProductCategoryMap_V3: {sorted(schema_only)}"))
    if map_only:
        out.append(("info",  f"categories in map but not in schema: {sorted(map_only)} (future)"))
    return out


def gate_routing_playbooks_exist(doc: dict, gate: dict, pack_root: Path) -> list[tuple[str, str]]:
    """Every value at <block>[*].<field> must resolve to a playbook YAML.

    Configured by:
        block: routing
        field: sub_playbook
    """
    block_name = gate.get("block")
    field      = gate.get("field")
    if not (block_name and field):
        return [("error", f"routing_playbooks_exist gate missing block/field: {gate}")]

    pb_dir = pack_root / "Playbooks"
    if not pb_dir.exists():
        return []

    present = {p.stem for p in pb_dir.glob("*.yml")}
    missing: list[str] = []
    for item in doc.get(block_name, []) or []:
        if not isinstance(item, dict):
            continue
        ref = (item.get(field) or "").strip()
        if not ref:
            continue
        # XSIAM playbook ids use spaces; filenames use underscores. Try both.
        if not ({ref, ref.replace(" ", "_")} & present):
            missing.append(ref)
    if missing:
        return [("error", f"{block_name}.{field} references missing playbooks: {sorted(set(missing))}")]
    return []


def gate_cross_reference(doc: dict, gate: dict, pack_root: Path) -> list[tuple[str, str]]:
    """Every <from_block>[*].<from_field> must exist in <to_block>[*].<to_field>,
    matched by <partition_field> == <to_partition_field>.

    Used for e.g. reads_from_phases.source ∈ writes.target (per phase).

    Configured by:
        from_block: reads_from_phases
        from_field: source
        partition_field: from_phase
        to_block: writes
        to_field: target
        to_partition_field: phase
    """
    fb = gate["from_block"]; ff = gate["from_field"]
    pf = gate.get("partition_field")
    tb = gate["to_block"];   tf = gate["to_field"]
    tpf = gate.get("to_partition_field", pf)

    # Build to-side index: {partition_value -> {field_values}}
    to_index: dict[Any, set[str]] = {}
    for item in doc.get(tb, []) or []:
        if not isinstance(item, dict):
            continue
        part = item.get(tpf) if tpf else None
        val = item.get(tf)
        if val is None:
            continue
        to_index.setdefault(part, set()).add(val)

    missing: list[str] = []
    for item in doc.get(fb, []) or []:
        if not isinstance(item, dict):
            continue
        part = item.get(pf) if pf else None
        val = item.get(ff)
        if val is None:
            continue
        if val not in to_index.get(part, set()):
            missing.append(f"{val!r} (partition {part!r})")
    if missing:
        return [("error", f"{fb}.{ff} not found in {tb}.{tf}: {sorted(set(missing))[:10]}")]
    return []


DRIFT_GATES = {
    "categories_subset_of_product_map": gate_categories_subset_of_product_map,
    "routing_playbooks_exist":          gate_routing_playbooks_exist,
    "cross_reference":                  gate_cross_reference,
}


def run_drift_gates(doc: dict, pack_root: Path) -> list[tuple[str, str]]:
    spec = doc.get("validation") or {}
    out: list[tuple[str, str]] = []
    for gate in spec.get("drift_gates") or []:
        kind = gate.get("kind")
        impl = DRIFT_GATES.get(kind)
        if impl is None:
            out.append(("error", f"unknown drift gate kind: {kind!r}; supported: {sorted(DRIFT_GATES)}"))
            continue
        out.extend(impl(doc, gate, pack_root))
    return out


# ============================================================================
# Payload assembly — emit-as-is + optional declarative transforms
# ============================================================================

def _apply_group_by(payload: dict, transforms: list[dict]) -> dict:
    """Apply `group_by` transforms in declaration order.

    Each transform reshapes one block from a flat list into a dict keyed by
    a field's value. The original block is replaced with the grouped result
    (under the new key if `into:` is set, otherwise in place).
    """
    for t in transforms or []:
        block = t.get("block"); key = t.get("key")
        into = t.get("into") or block
        drop = bool(t.get("drop_key_in_items", False))
        if not (block and key) or block not in payload:
            continue
        items = payload.get(block) or []
        grouped: dict[Any, list] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            k = item.get(key)
            entry = {kk: vv for kk, vv in item.items() if not (drop and kk == key)}
            grouped.setdefault(k, []).append(entry)
        payload[into] = grouped
        if into != block:
            payload.pop(block, None)
    return payload


def build_payload(doc: dict) -> dict:
    """Strip reserved fields, apply emit transforms, return the list payload."""
    payload = {k: v for k, v in doc.items() if k not in RESERVED}
    emit_spec = doc.get("emit") or {}
    if emit_spec.get("group_by"):
        payload = _apply_group_by(payload, emit_spec["group_by"])
    return payload


# ============================================================================
# Emission (shared)
# ============================================================================

def list_descriptor(list_name: str, description: str) -> dict:
    return {
        "allRead": True, "allReadWrite": True, "cacheVersn": 0, "data": "-",
        "definitionId": "", "description": description, "detached": False,
        "fromServerVersion": "6.5.0", "id": list_name, "isOverridable": False,
        "itemVersion": "1.0.0", "locked": False, "name": list_name,
        "nameLocked": False, "packID": "", "packName": "",
        "previousAllRead": True, "previousAllReadWrite": True, "system": False,
        "tags": None, "toServerVersion": "", "truncated": False, "type": "json",
        "version": -1, "fromVersion": "6.5.0", "display_name": list_name,
    }


def emit_list(doc: dict, payload: dict, pack_root: Path) -> list[Path]:
    list_name = doc["list_name"]
    list_dir  = pack_root / "Lists" / list_name
    list_dir.mkdir(parents=True, exist_ok=True)
    descriptor_path = list_dir / f"{list_name}.json"
    data_path       = list_dir / f"{list_name}_data.json"
    write_json(descriptor_path, list_descriptor(list_name, doc["description"]))
    write_json(data_path, payload)
    return [descriptor_path, data_path]


def emit_all(doc: dict, pack_root: Path) -> list[Path]:
    return emit_list(doc, build_payload(doc), pack_root)


# ============================================================================
# Roundtrip (shared)
# ============================================================================

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
                drift_lines.append(f"shipped file missing: {shipped}"); continue
            r_norm = _normalize(regen_path.read_text())
            s_norm = _normalize(shipped.read_text())
            if r_norm != s_norm:
                drift_lines.append(f"DRIFT: {rel}")
                diff = list(difflib.unified_diff(
                    s_norm.splitlines(), r_norm.splitlines(),
                    fromfile=f"shipped/{rel}", tofile=f"regen/{rel}",
                    lineterm="", n=2))
                drift_lines.extend(diff[:30])
            else:
                drift_lines.append(f"OK: {rel}")
    print("\n".join(drift_lines))
    return 0 if all("DRIFT" not in l and "missing" not in l for l in drift_lines) else 1


# ============================================================================
# Summary — generic, reads emit shape and reports counts
# ============================================================================

def render_summary(doc: dict, payload: dict) -> str:
    lines = [f"{doc['list_name']}:"]
    for k, v in payload.items():
        if isinstance(v, list):
            lines.append(f"  {k}: {len(v)} entries")
        elif isinstance(v, dict):
            lines.append(f"  {k}: {len(v)} groups")
            for sub_k, sub_v in v.items():
                if isinstance(sub_v, list):
                    lines.append(f"    {sub_k}: {len(sub_v)}")
        else:
            lines.append(f"  {k}: {v!r}")
    return "\n".join(lines)


# ============================================================================
# CLI
# ============================================================================

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="generate_soc_framework_content")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_val = sub.add_parser("validate", help="Validate schema + check drift")
    p_val.add_argument("--mapping", type=Path, required=True)
    p_val.add_argument("--pack-root", type=Path, required=False)

    p_emit = sub.add_parser("emit", help="Emit list (validates first)")
    p_emit.add_argument("--mapping", type=Path, required=True)
    p_emit.add_argument("--pack-root", type=Path, required=True)
    p_emit.add_argument("--allow-drift", action="store_true")

    p_rt = sub.add_parser("roundtrip", help="Regenerate to temp + diff vs shipped")
    p_rt.add_argument("--mapping", type=Path, required=True)
    p_rt.add_argument("--pack-root", type=Path, required=True)

    args = parser.parse_args(argv)
    doc = load_yaml(args.mapping)

    errors = validate_common(doc) + validate_structure(doc)
    if errors:
        print("VALIDATION FAILED:")
        for e in errors: print(f"  - {e}")
        return 1

    if args.cmd in ("validate", "emit") and getattr(args, "pack_root", None):
        drift_results = run_drift_gates(doc, args.pack_root)
        had_error = False
        for level, msg in drift_results:
            if level == "error":
                print(f"DRIFT ERROR: {msg}")
                had_error = True
            else:
                print(f"INFO: {msg}")
        if had_error:
            if args.cmd == "emit" and not args.allow_drift:
                print("\nABORTED. Reconcile or use --allow-drift.", file=sys.stderr)
                return 2
            if args.cmd == "validate":
                return 1
            print("WARNING: --allow-drift set, emitting despite drift.\n", file=sys.stderr)

    if args.cmd == "validate":
        print("VALIDATION OK")
        return 0

    if args.cmd == "emit":
        emitted = emit_all(doc, args.pack_root)
        for p in emitted: print(f"  emitted: {p}")
        payload = build_payload(doc)
        print(); print(render_summary(doc, payload))
        return 0

    if args.cmd == "roundtrip":
        return roundtrip(args.mapping, args.pack_root)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
