#!/usr/bin/env python3
"""
generate_vendor_content.py
==========================
Generate XSIAM vendor pack content (modeling rules + correlation rules) from
a SOC Framework per-data-source mapping YAML.

One YAML file per vendor data source. Each file declares:
  - shared metadata (vendor / product / data_source / category)
  - raw_schema (vendor field inventory, shared between rules)
  - modeling_rule (optional — emits .xif + .yml + _schema.json triple)
  - correlation_rules (optional list — each entry emits one .yml)

Subcommands:
  validate  --mapping <yaml>                          Structural + cross-rule check
  emit      --mapping <yaml> --pack-root <pack>       Emit all declared rules
  roundtrip --mapping <yaml> --pack-root <pack>       Emit to temp + diff vs shipped

Design tenets (per skill):
  * Targeted string assembly — never yaml.dump for emitted XSIAM YAML
    (reorders keys; corrupts Upon Trigger / multi-MODEL semantics).
  * raw_schema is a SUPERSET of what the modeling rule references.
    The emitted _schema.json is the SUBSET actually referenced.
  * Subtype-aware validation: passthrough enforces mitre_defs == {} and
    the four MITRE alert_fields entries; analytics enforces mitre_defs
    populated and investigation_query_link present.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml


REQUIRED_FILE_FIELDS = {
    "vendor", "product", "data_source", "category", "raw_schema",
}
REQUIRED_MODELING_BLOCK_FIELDS = {
    "fromversion", "modeling_rule_id", "modeling_rule_name",
    "fields", "contributes",
}
REQUIRED_CORRELATION_BLOCK_FIELDS = {
    "subtype", "fromversion", "global_rule_id", "name", "description",
    "schema_constants", "alert_name", "alert_description", "alert_fields",
    "contributes",
}


# ----------------------------- IO helpers ------------------------------------

def load_yaml(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not content.endswith("\n"):
        content += "\n"
    path.write_text(content)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


# ----------------------------- Validation ------------------------------------

def validate_mapping(doc: dict) -> list[str]:
    """Validate the combined per-data-source mapping document."""
    errors: list[str] = []

    for f in REQUIRED_FILE_FIELDS:
        if f not in doc:
            errors.append(f"Missing required file-level field: {f}")

    if "modeling_rule" not in doc and not doc.get("correlation_rules"):
        errors.append(
            "File must declare at least one of: modeling_rule, correlation_rules."
        )

    raw_schema = doc.get("raw_schema", {})

    # ----- Modeling rule block -----
    mr = doc.get("modeling_rule")
    if mr is not None:
        # raw_xif passthrough mode skips fields/filter validation — the .xif
        # body is authoritative. Required structural metadata still applies.
        is_raw = bool(mr.get("raw_xif"))
        required_fields = REQUIRED_MODELING_BLOCK_FIELDS - ({"fields"} if is_raw else set())
        for f in required_fields:
            if f not in mr:
                errors.append(f"modeling_rule.{f} is required")
        for entry in mr.get("fields", []):
            for src in entry.get("sources", []):
                if src not in raw_schema:
                    errors.append(
                        f"modeling_rule field source '{src}' "
                        f"(target {entry.get('xdm_path')}) is not declared "
                        f"in raw_schema."
                    )

    # ----- Correlation rules entries -----
    for i, cr in enumerate(doc.get("correlation_rules") or []):
        prefix = f"correlation_rules[{i}]"
        for f in REQUIRED_CORRELATION_BLOCK_FIELDS:
            if f not in cr:
                errors.append(f"{prefix}.{f} is required")

        subtype = cr.get("subtype")
        mitre_defs = cr.get("mitre_defs", {})

        if subtype == "passthrough":
            # mitre_defs and MITRE alert_fields on passthrough are author preferences:
            # - When the vendor ships MITRE per-alert (e.g. CrowdStrike Falcon's
            #   tactic/technique fields), rules typically populate the four MITRE
            #   alert_fields and emit mitre_defs: {}.
            # - When the vendor doesn't ship MITRE per-alert (e.g. Proofpoint TAP),
            #   rules typically leave alert_fields without MITRE and populate
            #   mitre_defs: with the rule author's intended coverage.
            # Both are acceptable. Validator only checks structural requirements.
            pre_alter = cr.get("pre_alter", "")
            if "vendor_name" not in pre_alter or "product_name" not in pre_alter:
                errors.append(
                    f"{prefix}: passthrough rules MUST set vendor_name and "
                    f"product_name in pre_alter — SOCProductCategoryMap_V3 "
                    f"routes on these."
                )

        elif subtype == "analytics":
            if not mitre_defs:
                errors.append(
                    f"{prefix}: analytics rules MUST declare mitre_defs."
                )
            if not cr.get("investigation_query_link"):
                errors.append(
                    f"{prefix}: analytics rules MUST provide "
                    f"investigation_query_link."
                )

        elif subtype is not None:
            errors.append(
                f"{prefix}.subtype must be 'passthrough' or 'analytics'"
            )

        # Cross-validate alert_fields buckets against raw_schema + pre_alter
        pre_alter = cr.get("pre_alter", "")
        computed_cols = _extract_computed_columns(pre_alter)
        for af in cr.get("alert_fields", []):
            bucket = af.get("bucket")
            src = af.get("source")
            if bucket == "raw":
                if src not in raw_schema:
                    errors.append(
                        f"{prefix}: alert_field issue.{af['issue_field']} "
                        f"declares bucket=raw but source '{src}' is not in "
                        f"raw_schema."
                    )
            elif bucket == "computed":
                if src not in computed_cols:
                    errors.append(
                        f"{prefix}: alert_field issue.{af['issue_field']} "
                        f"declares bucket=computed but source '{src}' is not "
                        f"produced by pre_alter."
                    )

    return errors


def _extract_computed_columns(pre_alter: str) -> set[str]:
    cols: set[str] = set()
    for m in re.finditer(r"\|\s*alter\b(.+?)(?=\|\s*\w|\Z)", pre_alter, re.DOTALL):
        chain = m.group(1)
        depth, buf, parts = 0, "", []
        for ch in chain:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            if ch == "," and depth == 0:
                parts.append(buf); buf = ""
            else:
                buf += ch
        parts.append(buf)
        for p in parts:
            m2 = re.match(r"\s*(\w+)\s*=", p)
            if m2:
                cols.add(m2.group(1))
    return cols


# ----------------------------- Modeling rule emit ----------------------------

def emit_modeling_rule(doc: dict, pack_root: Path) -> dict[str, Path]:
    mr = doc["modeling_rule"]
    # directory_name overrides the default (id with underscores stripped) —
    # required when shipped pack uses a different convention (e.g. plural
    # 'SOCCrowdStrikeFalconModelingRules' vs id 'SOC_CrowdStrikeFalcon_ModelingRule').
    rule_dir_name = mr.get("directory_name") or mr["modeling_rule_id"].replace("_", "")
    out_dir = pack_root / "ModelingRules" / rule_dir_name

    xif_path    = out_dir / f"{rule_dir_name}.xif"
    yml_path    = out_dir / f"{rule_dir_name}.yml"
    schema_path = out_dir / f"{rule_dir_name}_schema.json"

    write_text(xif_path,    _build_xif(doc))
    write_text(yml_path,    _build_modeling_yml(doc))
    write_json(schema_path, _build_modeling_schema_json(doc))

    return {"xif": xif_path, "yml": yml_path, "schema_json": schema_path}


def _build_xif(doc: dict) -> str:
    """Emit XSIAM modeling rule (.xif) content.

    Three authoring modes:

    Mode 1 — Structured single-part (most vendors): author
    `modeling_rule.fields[]` with optional `modeling_rule.filter`. Generator
    emits one filter+alter pipeline using XQLm grammar.

    Mode 2 — Raw passthrough (multi-part or hand-tuned vendors): set
    `modeling_rule.raw_xif: |` with the literal .xif body (may contain
    multiple parts, comments, etc). Generator passes through verbatim,
    prepending [MODEL:] directive only if not already present in the
    raw body. Used for Trend Micro Vision One (3-part rule, ~420 lines)
    and similar vendors whose .xif is too complex to decompose into
    structured fields. The contract value moves to the `contributes:`
    declaration alongside; what the .xif actually does is documented
    inline by example.

    XQLm grammar (Mode 1 only) — XSIAM treats top-level statements as
    'parts'. Every part must have a filter stage; standalone statements
    without filters are rejected at install time.

    Pattern A — no filter clause (single part, no filter required):
        [MODEL: dataset=<name>]
        alter
        <xdm.path> = <expr>,
        ...;

    Pattern B — with filter clause (filter and alter MUST be one pipeline,
    stitched with `|`. Otherwise the alter is treated as a separate part
    with no filter stage and install fails with:
        "For datamodel rules with multiple parts, each part must have a
         filter stage"):
        [MODEL: dataset=<name>]
        filter <expr>
        | alter
            <xdm.path> = <expr>,
            ...;

    Critical rules:
      - Bare 'alter' (no leading pipe) is ONLY valid in Pattern A.
      - 'filter X' is NOT terminated with ';' when followed by '| alter' —
        the pipe makes them one statement.
      - When a filter is present, '| alter' MUST use the leading pipe.
    """
    mr = doc["modeling_rule"]
    ds = doc["data_source"]

    # Mode 2 — raw passthrough. Caller supplied a complete .xif body.
    raw = mr.get("raw_xif")
    if raw:
        body = raw.rstrip("\n")
        if body.lstrip().startswith("[MODEL"):
            return body + "\n"
        # Strip leading blank lines from body — the [MODEL:] line is followed
        # by exactly one blank line, then the body content begins. YAML literal
        # blocks can introduce extra leading whitespace.
        body = body.lstrip("\n")
        return f"[MODEL: dataset={ds}]\n\n{body}\n"

    # Mode 1 — structured single-part emit
    lines = [f'[MODEL: dataset={ds}]']
    flt = mr.get("filter")
    fields = mr.get("fields", [])

    if flt and fields:
        # Pattern B — filter pipes into alter as one part
        lines.append(f'filter {flt["expression"]}')
        lines.append("| alter")
        body_parts = [f"    {f['xdm_path']} = {f['expression']}" for f in fields]
        lines.append(",\n".join(body_parts) + ";")
    elif fields:
        # Pattern A — bare alter, no filter
        lines.append("alter")
        body_parts = [f"{f['xdm_path']} = {f['expression']}" for f in fields]
        lines.append(",\n".join(body_parts) + ";")
    elif flt:
        # filter only — terminate with ;
        lines.append(f'filter {flt["expression"]};')

    return "\n".join(lines)


def _build_modeling_yml(doc: dict) -> str:
    mr = doc["modeling_rule"]
    return (
        f'fromversion: {mr["fromversion"]}\n'
        f'id: {mr["modeling_rule_id"]}\n'
        f'name: {mr["modeling_rule_name"]}\n'
        f"rules: ''\n"
        f"schema: ''"
    )


def _build_modeling_schema_json(doc: dict) -> dict:
    """Emit _schema.json declaring every confirmed-real dataset field.

    XSIAM treats the modeling rule's _schema.json as the dataset contract.
    Both the modeling rule AND any correlation rule sourcing the same dataset
    are validated against this schema at install time. If a correlation rule
    references a column the schema doesn't declare → 101704.

    Schema includes every field from raw_schema EXCEPT those marked
    `status: inferred_from_correlation` (which are best-effort guesses about
    fields the correlation rule references but we couldn't confirm exist in
    the vendor's actual dataset). Declaring an inferred field that isn't
    really there could cause its own install rejection on stricter tenants.

    Fields with `status: declared_unused` ARE included — shipped pack
    schemas often declare unused fields for forward compatibility.
    """
    raw = doc.get("raw_schema", {})
    out_fields: dict[str, dict] = {}
    for fname, meta in raw.items():
        if meta.get("status") == "inferred_from_correlation":
            continue
        out_fields[fname] = {
            "type": meta["type"],
            "is_array": meta["is_array"],
        }

    return {doc["data_source"]: out_fields}


# ----------------------------- Correlation rule emit -------------------------

def emit_correlation_rules(doc: dict, pack_root: Path) -> list[Path]:
    out_paths: list[Path] = []
    for cr in doc.get("correlation_rules") or []:
        out_path = pack_root / "CorrelationRules" / f'{cr["name"]}.yml'
        write_text(out_path, _build_correlation_yml(doc, cr))
        out_paths.append(out_path)
    return out_paths


def _build_correlation_yml(doc: dict, cr: dict) -> str:
    """Targeted string assembly. yaml.dump is BANNED here."""
    sc = cr["schema_constants"]
    lines: list[str] = []

    # Note: pack_prep strips id:/ruleid: from correlation rules as "rogue" keys.
    # Framework canon is global_rule_id only at the top of the file.
    lines.append(f'rule_id: {sc["rule_id"]}')
    lines.append(f'fromversion: {cr["fromversion"]}')

    if cr.get("tags"):
        lines.append("tags:")
        for tag in cr["tags"]:
            lines.append(f"  - {tag}")

    lines.append(f'action: {sc["action"]}')
    lines.append(f'alert_category: {sc["alert_category"]}')
    lines.append(f'alert_description: {cr["alert_description"]}')
    lines.append(f'alert_domain: {sc["alert_domain"]}')

    lines.append("alert_fields:")
    for af in cr["alert_fields"]:
        lines.append(f'  {af["issue_field"]}: {af["source"]}')

    lines.append(f'alert_name: {cr["alert_name"]}')
    lines.append(f'alert_type: {_yaml_scalar(cr.get("alert_type"))}')
    lines.append(f'crontab: {_yaml_scalar(cr.get("crontab"))}')
    lines.append(f'dataset: {cr.get("dataset", "alerts")}')
    lines.append(f'name: {cr["name"]}')
    lines.append("description: >-")
    for desc_line in _wrap(cr["description"], 78):
        lines.append(f'  {desc_line}')

    lines.append(f'drilldown_query_timeframe: {sc.get("drilldown_query_timeframe", "ALERT")}')
    lines.append(f'execution_mode: {sc["execution_mode"]}')
    lines.append(f'global_rule_id: {cr["global_rule_id"]}')

    iql = cr.get("investigation_query_link", "")
    if iql:
        lines.append("investigation_query_link: |-")
        for il in _strip_xql_comments(iql).splitlines():
            lines.append(f"  {il}")
    else:
        lines.append("investigation_query_link: ''")

    lines.append(f'is_enabled: {str(sc["is_enabled"]).lower()}')
    lines.append("lookup_mapping: []")
    lines.append(f'mapping_strategy: {sc["mapping_strategy"]}')

    mitre = cr.get("mitre_defs", {})
    if not mitre:
        lines.append("mitre_defs: {}")
    else:
        lines.append("mitre_defs:")
        for tactic, techs in mitre.items():
            lines.append(f'  {tactic}:')
            for t in techs:
                lines.append(f'  - {t}')

    lines.append(f'search_window: {_yaml_scalar(cr.get("search_window"))}')
    lines.append(f'severity: {sc.get("severity", "User Defined")}')
    lines.append(f'simple_schedule: {_yaml_scalar(cr.get("simple_schedule"))}')

    sup = cr.get("suppression", {})
    if sup.get("enabled"):
        lines.append(f'suppression_duration: {sup["duration"]}')
        lines.append(f'suppression_enabled: true')
        lines.append("suppression_fields:")
        for sf in sup["fields"]:
            lines.append(f'- {sf}')
    else:
        lines.append("suppression_enabled: false")

    lines.append(f'timezone: {_yaml_scalar(cr.get("timezone"))}')
    if sc.get("user_defined_category"):
        lines.append(f'user_defined_category: {sc["user_defined_category"]}')
    if sc.get("user_defined_severity"):
        lines.append(f'user_defined_severity: {sc["user_defined_severity"]}')

    lines.append("xql_query: |")
    lines.append(f'  dataset = {doc["data_source"]}')
    if cr.get("pre_alter"):
        for pl in _strip_xql_comments(cr["pre_alter"]).splitlines():
            lines.append(f"  {pl}" if pl.strip() else "")
    if cr.get("final_projection"):
        lines.append("  | fields")
        proj = ", ".join(
            "*" if c == "*" else c for c in cr["final_projection"]
        )
        lines.append(f"      {proj}")

    return "\n".join(lines)


def _strip_xql_comments(xql: str) -> str:
    """Remove // line comments and /* */ block comments from XQL.
    Comments in the YAML mapping are for human authors; they never reach
    the emitted rule. Collapses runs of resulting blank lines."""
    # Block comments first (non-greedy across lines)
    xql = re.sub(r"/\*.*?\*/", "", xql, flags=re.DOTALL)
    # Line comments — strip from `//` to end-of-line
    out_lines = []
    for line in xql.splitlines():
        # Find // outside of any quoted string
        in_str = False
        quote = None
        cut = None
        for i, ch in enumerate(line):
            if in_str:
                if ch == quote and (i == 0 or line[i-1] != "\\"):
                    in_str = False
            elif ch in ('"', "'"):
                in_str = True
                quote = ch
            elif ch == "/" and i + 1 < len(line) and line[i+1] == "/":
                cut = i
                break
        if cut is not None:
            line = line[:cut].rstrip()
        out_lines.append(line)
    # Collapse multiple consecutive blank lines into one
    cleaned = []
    prev_blank = False
    for line in out_lines:
        if not line.strip():
            if prev_blank:
                continue
            prev_blank = True
        else:
            prev_blank = False
        cleaned.append(line)
    # Trim leading/trailing blanks
    while cleaned and not cleaned[0].strip():
        cleaned.pop(0)
    while cleaned and not cleaned[-1].strip():
        cleaned.pop()
    return "\n".join(cleaned)


def _yaml_scalar(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return str(v).lower()
    return str(v)


def _wrap(text: str, width: int) -> list[str]:
    out: list[str] = []
    for paragraph in text.split("\n"):
        words = paragraph.split()
        line = ""
        for w in words:
            if line and len(line) + 1 + len(w) > width:
                out.append(line); line = w
            else:
                line = f"{line} {w}".strip()
        if line:
            out.append(line)
    return out


# ----------------------------- Emit + Round-trip -----------------------------

def emit_all(doc: dict, pack_root: Path) -> list[Path]:
    out: list[Path] = []
    if doc.get("modeling_rule"):
        out.extend(emit_modeling_rule(doc, pack_root).values())
    out.extend(emit_correlation_rules(doc, pack_root))
    return out


def roundtrip(mapping_path: Path, pack_root: Path) -> int:
    import tempfile

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
                import difflib
                diff = list(difflib.unified_diff(
                    s_norm.splitlines(), r_norm.splitlines(),
                    fromfile=f"shipped/{rel}", tofile=f"regen/{rel}",
                    lineterm="", n=2
                ))
                drift_lines.extend(diff[:30])
            else:
                drift_lines.append(f"OK: {rel}")

    print("\n".join(drift_lines))
    return 0 if all("DRIFT" not in l and "missing" not in l for l in drift_lines) else 1


def _normalize(text: str) -> str:
    out = []
    for line in text.splitlines():
        line = line.rstrip()
        line = re.sub(r" +", " ", line)
        if line.strip():
            out.append(line)
    return "\n".join(out)


# ----------------------------- CLI -------------------------------------------

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="generate_vendor_content")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_val = sub.add_parser("validate", help="Validate mapping document")
    p_val.add_argument("--mapping", type=Path, required=True)

    p_emit = sub.add_parser("emit", help="Emit all declared rules")
    p_emit.add_argument("--mapping", type=Path, required=True)
    p_emit.add_argument("--pack-root", type=Path, required=True)

    p_rt = sub.add_parser("roundtrip", help="Regenerate to temp + diff vs shipped")
    p_rt.add_argument("--mapping", type=Path, required=True)
    p_rt.add_argument("--pack-root", type=Path, required=True)

    args = parser.parse_args(argv)
    doc = load_yaml(args.mapping)

    if args.cmd == "validate":
        errors = validate_mapping(doc)
        if errors:
            print("VALIDATION FAILED:")
            for e in errors:
                print(f"  - {e}")
            return 1
        print("VALIDATION OK")
        return 0

    errors = validate_mapping(doc)
    if errors:
        print("VALIDATION FAILED — refusing to emit:")
        for e in errors:
            print(f"  - {e}")
        return 1

    if args.cmd == "emit":
        for p in emit_all(doc, args.pack_root):
            print(f"  emitted: {p}")
        return 0

    if args.cmd == "roundtrip":
        return roundtrip(args.mapping, args.pack_root)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
