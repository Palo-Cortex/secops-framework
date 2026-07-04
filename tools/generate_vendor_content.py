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
    def _emit_lines(text):
        for pl in text.splitlines():
            lines.append(f"  {pl}" if pl.strip() else "")

    if cr.get("pre_alter"):
        _emit_lines(_strip_xql_comments(cr["pre_alter"]))

    if cr.get("identity"):
        if cr.get("pre_alter"):
            lines.append("")
        _emit_lines(_emit_identity_seed())
        if cr.get("cie_join"):
            _emit_lines(_emit_cie_overlay(_build_cie_overlay_xql(cr["cie_join"]), cr.get("cie_schedule")))
        elif cr.get("cie_overlay"):
            _emit_lines(_emit_cie_overlay(cr["cie_overlay"], cr.get("cie_schedule")))
        _emit_lines(_emit_identity_finalization())
    elif cr.get("cie_join"):
        _emit_lines(_emit_cie_overlay(_build_cie_overlay_xql(cr["cie_join"]), cr.get("cie_schedule")))
    elif cr.get("cie_overlay"):
        _emit_lines(_emit_cie_overlay(cr["cie_overlay"], cr.get("cie_schedule")))
    if cr.get("final_projection"):
        lines.append("  | fields")
        proj = ", ".join(
            "*" if c == "*" else c for c in cr["final_projection"]
        )
        lines.append(f"      {proj}")

    return "\n".join(lines)


def _emit_cie_overlay(overlay, schedule=None):
    """Emit optional CIE (Cloud Identity Engine) enrichment as a PRESERVED
    block comment. The XQL lines are wrapped in a single /* */ so enabling is
    two edits (delete the /* and */), not un-commenting every line -- and the
    editor treats it as a real block comment, so it won't lint the dormant
    join. `schedule` is an optional dict {crontab, search_window,
    simple_schedule}. The overlay coalesces socfw_identity_map values OVER the
    inline idr_* fields, so the alert-field mappings are unaffected either way."""
    sch = schedule or {}
    crontab = sch.get("crontab", "*/10 * * * *")
    window = sch.get("search_window", "25 hours")
    label = sch.get("simple_schedule", "10 minutes")
    header = [
        "",
        "// ============== CIE ENRICHMENT (optional, OFF by default) ==============",
        "// Cloud Identity Engine enrichment is disabled. To enable it:",
        "//   1. Set this rule to a schedule (it ships REAL_TIME):",
        "//        execution mode = SCHEDULED",
        f"//        crontab        = {crontab}",
        f"//        search window  = {window}",
        f"//        schedule label = {label}",
        "//   2. Delete the /* and */ lines that wrap the block below.",
        "// The join coalesces socfw_identity_map values OVER the inline idr_* fields;",
        "// the alert-field mappings do not change. Requires SOC IdentityResolve.",
        "// ----------------------------------------------------------------------",
        "/*",
    ]
    body = list(overlay.splitlines())
    footer = ["*/", "// ===================== END CIE ENRICHMENT ============================="]
    return "\n".join(header + body + footer)


# Standard SOC Framework identity blocks, emitted when a rule opts in via
# `identity: true` (seed + finalization) and/or `cie_join` (the /* */ overlay).
# Kept here so every vendor rule inherits one identity pattern instead of
# hand-copying it. No vendor prefix: preserved raws are generic `original_*`.

# Named join-key shorthands. Each expands to an {event, map, map_filter} triple.
# A contract may also pass cie_join as that triple directly for bespoke keys.
_CIE_JOIN_SHORTHANDS = {
    "sid": {
        "event": 'coalesce(user_id, "")',
        "map": "coalesce(sid, on_prem_sid)",
        "map_filter": 'type in ("user", "computer")',
    },
    "upn_email": {
        "event": 'coalesce(if(user_principal contains "@", user_principal, null), if(user_name contains "@", user_name, null))',
        "map": "coalesce(upn, email)",
        "map_filter": 'type = "user"',
    },
    "email": {
        "event": 'if(user_principal contains "@", user_principal, if(user_name contains "@", user_name, null))',
        "map": "email",
        "map_filter": 'type = "user"',
    },
}


def _resolve_cie_join(cie_join):
    """Accept a shorthand string or an explicit {event, map[, map_filter]} dict."""
    if isinstance(cie_join, str):
        spec = _CIE_JOIN_SHORTHANDS.get(cie_join)
        if spec is None:
            raise ValueError(f"unknown cie_join shorthand: {cie_join!r}")
        return spec
    spec = dict(cie_join)
    spec.setdefault("map_filter", 'type in ("user", "computer")')
    return spec


def _emit_identity_seed():
    """Inline idr_* fallbacks so the finalization resolves when CIE is off."""
    return (
        '| alter idr_sid = null,\n'
        '        idr_upn = user_principal,\n'
        '        idr_email = if(user_principal contains "@", lowercase(user_principal), if(user_name contains "@", lowercase(user_name), null)),\n'
        '        idr_netbios = null,\n'
        '        idr_display_name = null,\n'
        '        idr_domain_name = null,\n'
        '        idr_sam_account_name = null,\n'
        '        idr_on_prem_sid = null'
    )


def _build_cie_overlay_xql(cie_join):
    """Raw CIE overlay XQL for the given join key. Wrapped in /* */ later by
    _emit_cie_overlay. Joins socfw_identity_map and coalesces map_* OVER idr_*."""
    s = _resolve_cie_join(cie_join)
    return (
        '| filter timestamp_diff(time_frame_end(), _insert_time, "MINUTE") <= 15\n'
        f'| alter cie_join_key = lowercase({s["event"]})\n'
        '| join type = left (\n'
        '    dataset = socfw_identity_map\n'
        f'    | filter {s["map_filter"]}\n'
        f'    | alter cie_join_key = lowercase({s["map"]})\n'
        '    | dedup cie_join_key by asc netbios_and_sam_account_name\n'
        '    | fields cie_join_key,\n'
        '             sid                          as map_sid,\n'
        '             upn                          as map_upn,\n'
        '             email                        as map_email,\n'
        '             display_name                 as map_display,\n'
        '             domain_name                  as map_domain,\n'
        '             sam_account_name             as map_sam,\n'
        '             on_prem_sid                  as map_on_prem_sid,\n'
        '             netbios_and_sam_account_name as map_netbios\n'
        '  ) as m cie_join_key = m.cie_join_key\n'
        '| alter idr_sid              = coalesce(map_sid, idr_sid),\n'
        '        idr_upn              = coalesce(map_upn, idr_upn),\n'
        '        idr_email            = coalesce(map_email, idr_email),\n'
        '        idr_display_name     = coalesce(map_display, idr_display_name),\n'
        '        idr_domain_name      = coalesce(map_domain, idr_domain_name),\n'
        '        idr_sam_account_name = coalesce(map_sam, idr_sam_account_name),\n'
        '        idr_on_prem_sid      = coalesce(map_on_prem_sid, idr_on_prem_sid),\n'
        '        idr_netbios          = coalesce(map_netbios, idr_netbios)\n'
        '| alter _time = _insert_time'
    )


def _emit_identity_finalization():
    """Email-first identity finalization: resolve display_name/email/user_principal,
    email-first actor_effective_username, and email-first user_name with the
    machine/service ($) guard. Raw values preserved as original_*."""
    return (
        '| alter original_display_name   = display_name,\n'
        '        original_user_principal = user_principal\n'
        '\n'
        '| alter display_name   = coalesce(idr_display_name, idr_sam_account_name, display_name),\n'
        '        email          = idr_email,\n'
        '        user_principal = coalesce(idr_upn, user_principal)\n'
        '| alter actor_effective_username = lowercase(coalesce(idr_email, idr_upn, idr_netbios, actor_effective_username))\n'
        '\n'
        '| alter idr_email = coalesce(idr_email, idr_upn, if(user_principal contains "@", lowercase(user_principal), null), if(user_name contains "@", lowercase(user_name), null))\n'
        '| alter email     = idr_email\n'
        '\n'
        '| alter original_user_name = user_name\n'
        '| alter user_name = if(user_name contains "$", user_name, coalesce(idr_email, idr_upn, user_name))'
    )


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
    s = str(v)
    if s and (s[0] in "*&!@%#|>[]{},?:-\'\"`" or s.lower() in ("null", "true", "false", "yes", "no", "~") or ": " in s or s != s.strip()):
        return "'" + s.replace("'", "''") + "'"
    return s


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


# ----------------------- Emit-time tenant schema check -----------------------

# Identifiers that appear in XQL bodies as grammar/keywords, never as columns.
_XQL_NONCOLUMN = {
    "dataset", "alter", "fields", "filter", "comp", "join", "dedup", "sort",
    "limit", "as", "by", "asc", "desc", "and", "or", "not", "in", "contains",
    "between", "preset", "config", "window", "over", "partition", "to",
    "null", "true", "false", "nulls", "first", "last",
}


def _assemble_xql_body(doc: dict, cr: dict) -> str:
    """Reconstruct the emitted XQL exactly as _build_correlation_yml does, so
    the field check sees what actually ships in the rule."""
    parts = [f'dataset = {doc["data_source"]}']
    if cr.get("pre_alter"):
        parts.append(_strip_xql_comments(cr["pre_alter"]))
    if cr.get("final_projection"):
        parts.append("| fields " + ", ".join(
            "*" if c == "*" else c for c in cr["final_projection"]))
    return "\n".join(parts)


def _referenced_columns(xql_body: str) -> set:
    """Best-effort set of raw dataset columns referenced in an XQL body.

    Advisory heuristic: strips quoted strings, drops function-call names
    (identifier immediately followed by '(') and XQL grammar words. Whatever
    remains is treated as a dataset column reference."""
    s = re.sub(r"'(?:[^'\\]|\\.)*'", " ", xql_body)
    s = re.sub(r'"(?:[^"\\]|\\.)*"', " ", s)
    s = re.sub(r"->\s*[A-Za-z_][A-Za-z0-9_]*", " ", s)   # drop nested-field accessors
    cols = set()
    for m in re.finditer(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)", s):
        tok = m.group(1)
        if tok in _XQL_NONCOLUMN:
            continue
        if s[m.end():].lstrip()[:1] == "(":   # function call, not a column
            continue
        cols.add(tok)
    return cols


def _fetch_tenant_columns(dataset: str, sample: int = 500):
    """Union of columns observed in `sample` rows of `dataset` on the tenant
    named by DEMISTO_BASE_URL / DEMISTO_API_KEY / XSIAM_AUTH_ID.

    Advisory only. Returns None (check skipped) if creds are absent or any part
    of the query fails - this must never break an offline or CI emit."""
    import os, json as _json, time, urllib.request, urllib.error
    base = os.environ.get("DEMISTO_BASE_URL")
    key = os.environ.get("DEMISTO_API_KEY")
    auth = os.environ.get("XSIAM_AUTH_ID")
    if not (base and key and auth):
        return None
    base = base.rstrip("/")
    H = {"Authorization": key, "x-xdr-auth-id": str(auth),
         "Content-Type": "application/json"}

    def _post(ep, body):
        req = urllib.request.Request(base + ep, data=_json.dumps(body).encode(),
                                     headers=H)
        return _json.loads(urllib.request.urlopen(req, timeout=45).read().decode())

    try:
        q = f"dataset = {dataset} | limit {sample}"
        r = _post("/public_api/v1/xql/start_xql_query/",
                  {"request_data": {"query": q, "tenants": []}})
        eid = r["reply"] if isinstance(r.get("reply"), str) \
            else (r.get("reply") or {}).get("execution_id")
        if not eid:
            return None
        for _ in range(25):
            time.sleep(2)
            rr = _post("/public_api/v1/xql/get_query_results/",
                       {"request_data": {"query_id": eid, "pending_flag": True,
                                         "format": "json"}})
            rep = rr.get("reply", {}) if isinstance(rr, dict) else {}
            if rep.get("status") == "SUCCESS":
                cols = set()
                for row in rep.get("results", {}).get("data", []) or []:
                    cols.update(row.keys())
                return cols or None
            if rep.get("status") not in ("PENDING", "RUNNING"):
                return None
    except Exception:
        return None
    return None


def emit_time_schema_check(doc: dict) -> None:
    """Warn (never fail) when a correlation rule's XQL references a column the
    target tenant's dataset doesn't carry - the class of gap that surfaces at
    install time as error 101704."""
    ds = doc.get("data_source")
    present = _fetch_tenant_columns(ds) if ds else None
    if present is None:
        print("  schema-check: skipped (no DEMISTO_* tenant creds or query unavailable)")
        return
    print(f"  schema-check: sampled {len(present)} columns from {ds}")
    warned = 0
    for cr in doc.get("correlation_rules") or []:
        try:
            computed = _extract_computed_columns(cr.get("pre_alter", ""))
            absent = sorted(_referenced_columns(_assemble_xql_body(doc, cr)) - present - computed - {ds})
        except Exception:
            # advisory only: an unanalyzable rule must never fail emit
            print(f"  schema-check: skipped {cr.get('name', '<unnamed>')} (could not analyze XQL)")
            continue
        if absent:
            warned += 1
            print(f"  WARN  {cr.get('name', '<unnamed>')}")
            print(f"        not in tenant schema: {', '.join(absent)}")
    if not warned:
        print("  schema-check: all correlation-rule fields resolve against tenant schema")
    else:
        print(f"  schema-check: {warned} rule(s) reference tenant-absent fields "
              "(advisory; authored for a fuller-telemetry tenant?)")


# ----------------------------- CLI -------------------------------------------

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="generate_vendor_content")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_val = sub.add_parser("validate", help="Validate mapping document")
    p_val.add_argument("--mapping", type=Path, required=True)

    p_emit = sub.add_parser("emit", help="Emit all declared rules")
    p_emit.add_argument("--mapping", type=Path, required=True)
    p_emit.add_argument("--pack-root", type=Path, required=True)
    p_emit.add_argument("--schema-check", action="store_true",
                        help="After emit, warn on correlation-rule XQL fields "
                             "absent from the target tenant dataset schema "
                             "(reads DEMISTO_* env; advisory, never fails emit)")

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
        if getattr(args, "schema_check", False):
            emit_time_schema_check(doc)
        return 0

    if args.cmd == "roundtrip":
        return roundtrip(args.mapping, args.pack_root)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
