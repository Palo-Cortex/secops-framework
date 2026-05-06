#!/usr/bin/env python3
"""Generate Swagger-style markdown documentation for SOC Framework schemas.

Walks ``schemas/`` and emits one ``.md`` file per YAML schema into the
appropriate ``docs/<pack>/`` directory. Two schema families are recognized:

* **vendor**   — ``schemas/vendors/<vendor>/*.yaml`` (vendor / product / raw_schema /
                 modeling_rule / correlation_rules)
* **contract** — ``schemas/soc-framework/<pack>/*.yaml`` (pack / list_name /
                 validation / mappings / stamps / mirrors / phases / routing / writes / ...)

Usage::

    python tools/generate_schema_docs.py                    # generate all
    python tools/generate_schema_docs.py --check            # CI: fail on drift
    python tools/generate_schema_docs.py --schema PATH      # one file
    python tools/generate_schema_docs.py --out-dir docs     # override docs root
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Repo layout & docs-pack aliases
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMAS_DIR = REPO_ROOT / "schemas"
DOCS_DIR = REPO_ROOT / "docs"
CATALOG_PATH = REPO_ROOT / "pack_catalog.json"

# Source links point at the file in GitHub rather than at a relative path —
# the schemas/ tree isn't part of the rendered docs site, so relative links
# fail under mkdocs --strict.
GITHUB_BLOB_BASE = "https://github.com/Palo-Cortex/secops-framework/blob/main"

# Banner stamped into every generated file. Pruning matches against this exact
# string when sweeping orphans — never touches files without it.
GENERATED_BANNER = (
    "<!-- GENERATED FILE — do not edit by hand. "
    "Run `python tools/generate_schema_docs.py` to regenerate. -->"
)


# ---------------------------------------------------------------------------
# Schema loading & dispatch
# ---------------------------------------------------------------------------

def load_yaml(path: Path) -> dict[str, Any]:
    with path.open() as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level must be a mapping")
    return data


def detect_family(schema: dict[str, Any]) -> str:
    if "vendor" in schema and "correlation_rules" in schema:
        return "vendor"
    if "pack" in schema and "list_name" in schema:
        return "contract"
    return "unknown"


def schema_pack_id(schema: dict[str, Any]) -> str | None:
    """Both schema families now declare ``pack: <catalog-id>`` near the top.

    Framework schemas always have it; vendor schemas adopted it as part of the
    catalog-driven docs migration. Returns None if absent — caller errors.
    """
    pack = schema.get("pack")
    return pack if isinstance(pack, str) and pack else None


def load_catalog(catalog_path: Path) -> dict[str, dict]:
    """Return ``{pack_id: catalog_entry}`` for ALL packs.

    Visibility filtering happens per-schema in ``process_one`` so that
    invisible packs produce a SKIP, not a FAIL. The distinction matters: a
    schema referencing a pack that genuinely doesn't exist is a bug; a schema
    referencing a pack that's deliberately ``visible: false`` is a config.
    """
    if not catalog_path.exists():
        raise FileNotFoundError(f"pack_catalog.json not found at {catalog_path}")
    data = json.loads(catalog_path.read_text())
    packs = data.get("packs") if isinstance(data, dict) else data
    if not isinstance(packs, list):
        raise ValueError(f"{catalog_path}: expected list of packs")
    out: dict[str, dict] = {}
    for entry in packs:
        if not isinstance(entry, dict):
            continue
        pid = entry.get("id")
        if isinstance(pid, str):
            out[pid] = entry
    return out


def resolve_docs_dir(catalog_entry: dict, repo_root: Path) -> Path:
    declared = catalog_entry.get("docs_path") or f"docs/{catalog_entry.get('id')}"
    return (repo_root / declared).resolve()


# ---------------------------------------------------------------------------
# Markdown helpers
# ---------------------------------------------------------------------------

def md_escape_cell(value: Any, max_len: int = 80) -> str:
    """Render a value for a single markdown table cell."""
    if value is None or value == "":
        return ""
    if isinstance(value, list):
        s = ", ".join(str(x) for x in value)
    elif isinstance(value, dict):
        s = ", ".join(f"{k}={v}" for k, v in value.items())
    elif isinstance(value, bool):
        return "✓" if value else ""
    else:
        s = str(value)
    s = s.replace("|", "\\|").replace("\n", " ").strip()
    if len(s) > max_len:
        s = s[: max_len - 3] + "..."
    return s


def md_code(value: Any) -> str:
    """Wrap a value as inline code, blank-safe."""
    cell = md_escape_cell(value)
    return f"`{cell}`" if cell else ""


def md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    out = []
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join("---" for _ in headers) + "|")
    for row in rows:
        out.append("| " + " | ".join(row) + " |")
    out.append("")
    return out


def render_record_list(title: str, records: list[Any], level: int = 2) -> list[str]:
    """Render a list of dict records as a labeled markdown table.

    Column headers are the union of keys preserved in first-seen order.
    Keys named ``description`` / ``notes`` / ``purpose`` render as prose
    (not wrapped in code formatting) since they hold human commentary
    rather than identifiers.
    """
    if not records:
        return []
    hashes = "#" * max(1, min(level, 6))
    out = [f"{hashes} {title}", ""]

    cols: list[str] = []
    seen: set[str] = set()
    for r in records:
        if not isinstance(r, dict):
            continue
        for k in r:
            if k not in seen:
                cols.append(k)
                seen.add(k)
    if not cols:
        return []

    prose_cols = {"description", "notes", "purpose"}

    rows = []
    for r in records:
        if not isinstance(r, dict):
            continue
        row = []
        for c in cols:
            v = r.get(c)
            if c in prose_cols:
                row.append(md_escape_cell(v, max_len=400))
            else:
                row.append(md_code(v))
        rows.append(row)
    out.extend(md_table(cols, rows))
    return out


# ---------------------------------------------------------------------------
# Vendor schema renderer
# ---------------------------------------------------------------------------

def render_vendor(schema: dict[str, Any], source_rel: str) -> str:
    out: list[str] = []
    vendor = schema.get("vendor", "")
    product = schema.get("product", "")
    if vendor and product:
        title = f"{product} ({vendor})"
    else:
        title = product or vendor or "Vendor"
    out.append(f"# {title} — Vendor Schema")
    out.append("")
    out.append(GENERATED_BANNER)
    out.append("")
    out.append(f"> **Source:** [`{source_rel}`]({GITHUB_BLOB_BASE}/{source_rel})")
    out.append("")

    # Identity
    out.append("## Identity")
    out.append("")
    rows = []
    for k in ("vendor", "product", "data_source", "category"):
        if k in schema:
            rows.append([k, md_code(schema[k])])
    out.extend(md_table(["Field", "Value"], rows))

    # Raw schema
    if "raw_schema" in schema:
        out.extend(_render_raw_schema(schema["raw_schema"]))

    # Modeling rule
    if "modeling_rule" in schema:
        out.extend(_render_modeling_rule(schema["modeling_rule"]))

    # Correlation rules
    cr = schema.get("correlation_rules") or []
    if cr:
        out.append("## Correlation Rules")
        out.append("")
        for rule in cr:
            out.extend(_render_correlation_rule(rule))

    return "\n".join(out)


def _render_raw_schema(raw: dict[str, Any]) -> list[str]:
    out = ["## Raw Schema", ""]
    out.append("Fields available in the raw ingest dataset.")
    out.append("")
    rows = []
    for fname, fdef in raw.items():
        if not isinstance(fdef, dict):
            rows.append([md_code(fname), "", "", "", ""])
            continue
        rows.append([
            md_code(fname),
            md_code(fdef.get("type")),
            md_escape_cell(fdef.get("is_array", False)),
            md_escape_cell(fdef.get("status", "declared")),
            md_escape_cell(", ".join(fdef.get("json_subfields", []))),
        ])
    out.extend(md_table(["Field", "Type", "Array", "Status", "JSON Subfields"], rows))
    return out


def _render_modeling_rule(mr: dict[str, Any]) -> list[str]:
    name = mr.get("modeling_rule_name") or mr.get("modeling_rule_id") or "Modeling Rule"
    out = [f"## Modeling Rule — {name}", ""]
    rows = []
    for k in ("modeling_rule_id", "modeling_rule_name", "directory_name", "fromversion"):
        if k in mr:
            rows.append([k, md_code(mr[k])])
    out.extend(md_table(["Field", "Value"], rows))

    fields = mr.get("fields") or []
    if fields:
        out.append("### Field Mappings")
        out.append("")
        out.append(
            "What each XDM field is, where it sources from, what issue field "
            "it surfaces on, and why the mapping is shaped the way it is."
        )
        out.append("")
        rows = []
        for f in fields:
            if not isinstance(f, dict):
                continue
            rows.append([
                md_code(f.get("xdm_path")),
                md_code(f.get("expression")),
                md_code(", ".join(f.get("sources", []))),
                md_code(f.get("issue_field")),
                md_escape_cell(f.get("notes"), max_len=400),
            ])
        out.extend(md_table(
            ["XDM Path", "Expression", "Sources", "Issue Field", "Description"],
            rows,
        ))

    contributes = mr.get("contributes") or []
    if contributes:
        out.append("### Contributes (Artifacts.*)")
        out.append("")
        out.append("Fields populated for downstream lifecycle Artifacts schemas:")
        out.append("")
        for c in contributes:
            out.append(f"- `{c}`")
        out.append("")

    return out


def _render_correlation_rule(rule: dict[str, Any]) -> list[str]:
    name = rule.get("name") or rule.get("global_rule_id") or "Unnamed Rule"
    out = [f"### {name}", ""]

    rows = []
    for k in ("global_rule_id", "subtype", "fromversion"):
        if k in rule:
            rows.append([k, md_code(rule[k])])
    if rows:
        out.extend(md_table(["Field", "Value"], rows))

    if rule.get("description"):
        out.append(str(rule["description"]).strip())
        out.append("")

    if rule.get("tags"):
        out.append("**Tags:** " + ", ".join(f"`{t}`" for t in rule["tags"]))
        out.append("")

    if rule.get("schema_constants"):
        out.append("#### Schema Constants")
        out.append("")
        rows = [[k, md_code(v)] for k, v in rule["schema_constants"].items()]
        out.extend(md_table(["Field", "Value"], rows))

    if rule.get("suppression"):
        s = rule["suppression"]
        out.append("#### Suppression")
        out.append("")
        rows = [
            ["enabled",  md_code(s.get("enabled"))],
            ["duration", md_code(s.get("duration"))],
            ["fields",   md_code(", ".join(s.get("fields", [])))],
        ]
        out.extend(md_table(["Field", "Value"], rows))
        if s.get("notes"):
            out.append(str(s["notes"]).strip())
            out.append("")

    if rule.get("alert_fields"):
        out.append("#### Alert Fields")
        out.append("")
        out.append(
            "Issue-field assignments emitted by the correlation rule. The "
            "Description column captures intent — when present, this is what "
            "downstream playbooks rely on the field meaning."
        )
        out.append("")
        rows = []
        for af in rule["alert_fields"]:
            if not isinstance(af, dict):
                continue
            rows.append([
                md_code(af.get("issue_field")),
                md_code(af.get("source")),
                md_code(af.get("bucket")),
                md_escape_cell(af.get("notes"), max_len=400),
            ])
        out.extend(md_table(
            ["Issue Field", "Source", "Bucket", "Description"],
            rows,
        ))

    if rule.get("pre_alter"):
        out.append("#### Pre-Alter XQL")
        out.append("")
        out.append("```xql")
        out.append(str(rule["pre_alter"]).rstrip())
        out.append("```")
        out.append("")

    return out


# ---------------------------------------------------------------------------
# Contract schema renderer
# ---------------------------------------------------------------------------

# Order matters — these sections render in this order if present.
CONTRACT_RECORD_BLOCKS: list[tuple[str, str]] = [
    ("phases",               "Phases"),
    ("routing",              "Routing"),
    ("reads_from_framework", "Reads from Framework Namespace (`SOCFramework.*`)"),
    ("reads_from_phases",    "Reads from Upstream Phases"),
    ("writes",               "Writes (Top-Level)"),
    ("writes_by_category",   "Writes by Category"),
    ("mappings",             "Mappings — `issue.*` → `SOCFramework.*`"),
    ("stamps",               "Stamps — literal value → `SOCFramework.*`"),
    ("mirrors",              "Mirrors — `SOCFramework.*` → `SOCFramework.*`"),
]


def render_contract(schema: dict[str, Any], source_rel: str) -> str:
    out: list[str] = []
    list_name = schema.get("list_name", "Contract")
    pack = schema.get("pack", "")
    out.append(f"# {list_name}")
    out.append("")
    out.append(GENERATED_BANNER)
    out.append("")
    rows = [
        ["Pack",       md_code(pack)],
        ["List Name",  md_code(list_name)],
        ["Source",     f"[`{source_rel}`]({GITHUB_BLOB_BASE}/{source_rel})"],
    ]
    out.extend(md_table(["Field", "Value"], rows))

    if schema.get("description"):
        out.append(str(schema["description"]).strip())
        out.append("")

    if "validation" in schema:
        out.extend(_render_validation(schema["validation"]))

    if "emit" in schema:
        out.extend(_render_emit(schema["emit"]))

    if "categories" in schema:
        out.extend(_render_categories(schema["categories"]))

    # Phases is a mapping, not a list — render specially
    if isinstance(schema.get("phases"), dict):
        out.extend(_render_phases_mapping(schema["phases"]))

    for key, title in CONTRACT_RECORD_BLOCKS:
        if key == "phases":
            continue  # handled above for the mapping case
        block = schema.get(key)
        if isinstance(block, list):
            out.extend(render_record_list(title, block))

    return "\n".join(out)


def _render_validation(v: dict[str, Any]) -> list[str]:
    out = ["## Validation", ""]
    if v.get("required_blocks"):
        out.append("**Required blocks:** " +
                   ", ".join(f"`{b}`" for b in v["required_blocks"]))
        out.append("")
    if isinstance(v.get("blocks"), dict):
        out.append("### Block Rules")
        out.append("")
        rows = []
        for bname, bdef in v["blocks"].items():
            if isinstance(bdef, dict):
                rows.append([
                    md_code(bname),
                    md_escape_cell(bdef.get("type", "")),
                    md_escape_cell(", ".join(bdef.get("item_required", []))),
                ])
        out.extend(md_table(["Block", "Type", "Item-Required Fields"], rows))
    if v.get("drift_gates"):
        out.append("### Drift Gates")
        out.append("")
        for g in v["drift_gates"]:
            if not isinstance(g, dict):
                continue
            kind = g.get("kind", "")
            params = ", ".join(f"`{k}={vv}`" for k, vv in g.items() if k != "kind")
            out.append(f"- **{kind}** — {params}" if params else f"- **{kind}**")
        out.append("")
    return out


def _render_emit(e: Any) -> list[str]:
    if not e:
        return []
    out = ["## Emit", ""]
    if not isinstance(e, dict):
        out.append(f"`{e}`")
        out.append("")
        return out

    flat_rows: list[list[str]] = []
    for key, value in e.items():
        if isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
            # List of records — render as its own sub-section
            out.extend(render_record_list(f"`{key}`", value, level=3))
        elif isinstance(value, list):
            out.append(f"### `{key}`")
            out.append("")
            for v in value:
                out.append(f"- {md_code(v)}")
            out.append("")
        elif isinstance(value, dict):
            out.append(f"### `{key}`")
            out.append("")
            rows = [[k, md_code(v)] for k, v in value.items()]
            out.extend(md_table(["Field", "Value"], rows))
        else:
            flat_rows.append([key, md_code(value)])
    if flat_rows:
        # Flat scalar entries grouped at top
        out_flat = ["### Flat Settings", ""]
        out_flat.extend(md_table(["Field", "Value"], flat_rows))
        # insert flat block after the "## Emit" header
        out = out[:2] + out_flat + out[2:]
    return out


def _render_categories(cats: Any) -> list[str]:
    out = ["## Categories", ""]
    if isinstance(cats, dict):
        rows = []
        for cname, cdef in cats.items():
            if isinstance(cdef, dict):
                rows.append([
                    md_code(cname),
                    md_escape_cell(cdef.get("status", "")),
                    md_escape_cell(cdef.get("shape", "")),
                    md_code(cdef.get("source_playbook", "")),
                ])
            else:
                rows.append([md_code(cname), "", "", ""])
        out.extend(md_table(["Category", "Status", "Shape", "Source Playbook"], rows))
    elif isinstance(cats, list):
        for c in cats:
            out.append(f"- `{c}`")
        out.append("")
    return out


def _render_phases_mapping(phases: dict[str, Any]) -> list[str]:
    out = ["## Phases", ""]
    rows = []
    for pname, pdef in phases.items():
        if isinstance(pdef, dict):
            rows.append([
                md_code(pname),
                md_code(pdef.get("orchestrator", "")),
                md_escape_cell(pdef.get("purpose", ""), max_len=120),
            ])
        else:
            rows.append([md_code(pname), "", ""])
    out.extend(md_table(["Phase", "Orchestrator", "Purpose"], rows))
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def process_one(schema_path: Path, *, catalog: dict[str, dict], schemas_root: Path,
                docs_root: Path, repo_root: Path,
                check: bool) -> tuple[bool, str, Path | None]:
    """Render one schema. Returns ``(changed, log_message, output_path)``.

    ``output_path`` is None when nothing was written (skipped/failed).
    """
    rel_in = _safe_rel(schema_path, repo_root)
    try:
        schema = load_yaml(schema_path)
    except Exception as exc:
        return (False, f"FAIL  {rel_in}: {exc}", None)

    family = detect_family(schema)
    if family == "unknown":
        return (False, f"SKIP  {rel_in}: unknown schema family", None)

    pack_id = schema_pack_id(schema)
    if not pack_id:
        return (False,
                f"FAIL  {rel_in}: missing required `pack:` field "
                f"(must match a catalog id in pack_catalog.json)",
                None)

    catalog_entry = catalog.get(pack_id)
    if catalog_entry is None:
        return (False,
                f"FAIL  {rel_in}: pack `{pack_id}` not found in catalog",
                None)

    # Visibility is intentionally NOT checked here. Schema docs are content,
    # generated for every pack in the catalog regardless of `visible`. The
    # mkdocs nav generator filters by `visible` so invisible packs simply
    # don't appear in nav — their pages still build and remain reachable by
    # direct URL. Flipping a pack visible later is a no-op for content.

    docs_dir = resolve_docs_dir(catalog_entry, repo_root)
    out_path = docs_dir / (schema_path.stem + ".md")
    rel_out = _safe_rel(out_path, repo_root)

    source_rel = _safe_rel(schema_path, repo_root)
    if family == "vendor":
        rendered = render_vendor(schema, source_rel)
    else:
        rendered = render_contract(schema, source_rel)
    if not rendered.endswith("\n"):
        rendered += "\n"

    existing = out_path.read_text() if out_path.exists() else ""
    changed = existing != rendered

    if check:
        if changed:
            return (True, f"DRIFT {rel_out}", out_path)
        return (False, f"OK    {rel_out}", out_path)

    if changed:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered)
        return (True, f"WROTE {rel_out}", out_path)
    return (False, f"OK    {rel_out}", out_path)


def prune_orphans(current_outputs: set[Path], docs_root: Path,
                  *, check: bool) -> tuple[int, list[str]]:
    """Delete generated-banner files that aren't in the current generation set.

    Only touches files containing this script's exact ``GENERATED_BANNER`` —
    hand-authored prose stays untouched even when it lives in the same folder.
    Returns ``(count, log_lines)``.
    """
    if not docs_root.exists():
        return (0, [])
    log: list[str] = []
    count = 0
    for md_path in docs_root.rglob("*.md"):
        try:
            head = md_path.read_text()[:600]
        except OSError:
            continue
        if GENERATED_BANNER not in head:
            continue
        if md_path.resolve() in current_outputs:
            continue
        rel = _safe_rel(md_path, docs_root.parent)
        if check:
            log.append(f"PRUNE {rel} (would delete)")
        else:
            md_path.unlink()
            log.append(f"PRUNE {rel}")
        count += 1
    return (count, log)


def _safe_rel(p: Path, base: Path) -> str:
    try:
        return str(p.resolve().relative_to(base.resolve()))
    except ValueError:
        return str(p)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Generate Swagger-style markdown docs for SOC Framework schemas."
    )
    p.add_argument("--schema", help="Render a single schema file (default: all)")
    p.add_argument("--check",  action="store_true",
                   help="CI mode — exit 1 if any docs would change")
    p.add_argument("--no-prune", action="store_true",
                   help="Skip orphan cleanup (default: prune is on)")
    p.add_argument("--catalog", default=str(CATALOG_PATH),
                   help=f"Default: {CATALOG_PATH}")
    p.add_argument("--schemas-root", default=str(SCHEMAS_DIR),
                   help=f"Default: {SCHEMAS_DIR}")
    p.add_argument("--docs-root",    default=str(DOCS_DIR),
                   help=f"Default: {DOCS_DIR}")
    p.add_argument("--repo-root",    default=str(REPO_ROOT),
                   help=f"Default: {REPO_ROOT}")
    args = p.parse_args(argv)

    schemas_root = Path(args.schemas_root).resolve()
    docs_root    = Path(args.docs_root).resolve()
    repo_root    = Path(args.repo_root).resolve()
    catalog_path = Path(args.catalog).resolve()

    try:
        catalog = load_catalog(catalog_path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.schema:
        targets = [Path(args.schema).resolve()]
    else:
        targets = sorted(schemas_root.rglob("*.yaml"))

    if not targets:
        print(f"No schemas found under {schemas_root}", file=sys.stderr)
        return 0

    drifts = 0
    failures = 0
    current_outputs: set[Path] = set()

    for t in targets:
        changed, msg, out_path = process_one(
            t,
            catalog=catalog,
            schemas_root=schemas_root,
            docs_root=docs_root,
            repo_root=repo_root,
            check=args.check,
        )
        print(msg)
        if msg.startswith("FAIL"):
            failures += 1
            continue
        if out_path is not None:
            current_outputs.add(out_path.resolve())
        if args.check and changed:
            drifts += 1

    pruned_count = 0
    if not args.no_prune and not args.schema:
        # Only prune on full-tree runs. Single-schema runs leave orphans alone
        # since they only know about one file.
        pruned_count, prune_log = prune_orphans(current_outputs, docs_root,
                                                check=args.check)
        for line in prune_log:
            print(line)

    if failures:
        print(f"\n{failures} schema(s) failed — see errors above.", file=sys.stderr)
        return 2

    if args.check and (drifts or pruned_count):
        print(
            f"\n{drifts} doc(s) drifted, {pruned_count} orphan(s) need pruning — "
            f"run `python tools/generate_schema_docs.py` to regenerate.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
