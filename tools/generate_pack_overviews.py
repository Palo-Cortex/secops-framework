#!/usr/bin/env python3
"""Generate per-pack overview docs from xsoar_config.json.

Driven by ``pack_catalog.json`` at repo root: for each pack entry, locate
``Packs/<dir>/xsoar_config.json`` and render a markdown overview into
``docs/<docs-folder>/overview.md``.

The overview surfaces what gets installed / configured when a pack is loaded
by the package manager or xsiam-pov-automation:

  * post_config_docs       — manual steps (links to GitHub blobs)
  * custom_packs           — other custom packs pulled in by this install
  * marketplace_packs      — Marketplace dependencies
  * lookup_datasets        — lookup datasets created
  * integration_instances  — integration brand instances configured
  * jobs                   — scheduled / triggered jobs created
  * exported_playbooks     — playbooks this pack exposes

Usage::

    python tools/generate_pack_overviews.py                # generate all
    python tools/generate_pack_overviews.py --check        # CI: fail on drift
    python tools/generate_pack_overviews.py --pack ID      # one pack
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "pack_catalog.json"
DOCS_DIR = REPO_ROOT / "docs"

GENERATED_BANNER = (
    "<!-- GENERATED FILE — do not edit by hand. "
    "Run `python tools/generate_pack_overviews.py` to regenerate. -->"
)


# ---------------------------------------------------------------------------
# Markdown helpers (kept local; refactor to shared module if a third tool grows)
# ---------------------------------------------------------------------------

def md_escape_cell(value: Any, max_len: int = 80) -> str:
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
    cell = md_escape_cell(value)
    return f"`{cell}`" if cell else ""


def md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    out.extend("| " + " | ".join(r) + " |" for r in rows)
    out.append("")
    return out


# ---------------------------------------------------------------------------
# Section renderers — each takes the section's value and returns markdown lines
# ---------------------------------------------------------------------------

def _render_post_config_docs(items: list[dict]) -> list[str]:
    if not items:
        return []
    out = ["## Manual Steps", "",
           "Documented post-install steps required to finish configuration.",
           ""]
    for it in items:
        name = it.get("name") or "(unnamed)"
        url = it.get("url") or ""
        if url:
            out.append(f"- [{name}]({url})")
        else:
            out.append(f"- {name}")
    out.append("")
    return out


def _render_custom_packs(items: list[dict]) -> list[str]:
    if not items:
        return []
    out = ["## Custom Packs Installed", "",
           "Additional custom packs the installer pulls in alongside this pack.",
           ""]
    rows = []
    for p in items:
        rows.append([
            md_code(p.get("id")),
            md_code(p.get("system")),
            f"[release]({p['url']})" if p.get("url") else "",
        ])
    out.extend(md_table(["Pack", "System", "Source"], rows))
    return out


def _render_marketplace_packs(items: list[dict]) -> list[str]:
    if not items:
        return []
    out = ["## Marketplace Dependencies", "",
           "Marketplace packs the installer ensures are present on the tenant.",
           ""]
    rows = [[md_code(p.get("id")), md_escape_cell(p.get("name")),
             md_code(p.get("version"))] for p in items]
    out.extend(md_table(["ID", "Name", "Version"], rows))
    return out


def _render_lookup_datasets(items: list[dict]) -> list[str]:
    if not items:
        return []
    out = ["## Lookup Datasets", ""]
    for ds in items:
        name = ds.get("dataset_name") or "(unnamed)"
        out.append(f"### `{name}`")
        out.append("")
        rows = [
            ["Type", md_code(ds.get("dataset_type"))],
            ["Source", f"[file]({ds['url']})" if ds.get("url") else ""],
        ]
        out.extend(md_table(["Field", "Value"], rows))
        schema = ds.get("dataset_schema") or {}
        if schema:
            out.append("**Schema:**")
            out.append("")
            schema_rows = [[md_code(k), md_code(v)] for k, v in schema.items()
                           if not k.startswith("_")]
            if schema_rows:
                out.extend(md_table(["Column", "Type"], schema_rows))
    return out


def _render_integration_instances(items: list[dict]) -> list[str]:
    if not items:
        return []
    out = ["## Integration Instances", "",
           "Integration brand instances the installer configures. Credentials "
           "and propagation labels are always tenant-specific — only the "
           "scaffolding ships in the pack.",
           ""]
    rows = []
    for inst in items:
        rows.append([
            md_code(inst.get("name")),
            md_code(inst.get("brand")),
            md_escape_cell(inst.get("category")),
            md_escape_cell(inst.get("enabled")),
        ])
    out.extend(md_table(["Instance Name", "Brand", "Category", "Enabled"], rows))
    return out


def _render_jobs(items: list[dict]) -> list[str]:
    if not items:
        return []
    out = ["## Jobs", "",
           "Scheduled or triggered jobs the installer creates on the tenant.",
           ""]
    for j in items:
        name = j.get("name") or "(unnamed)"
        out.append(f"### {name}")
        out.append("")
        details = j.get("details")
        if details:
            out.append(str(details).strip())
            out.append("")
        rows = [
            ["Playbook",  md_code(j.get("playbookId"))],
            ["Recurrent", md_escape_cell(j.get("recurrent"))],
            ["Schedule",  _summarize_schedule(j)],
            ["Owner",     md_code(j.get("owner"))],
        ]
        rows = [r for r in rows if r[1]]
        out.extend(md_table(["Field", "Value"], rows))
    return out


def _summarize_schedule(job: dict) -> str:
    """Human-readable schedule summary from humanCron / scheduled fields."""
    hc = job.get("humanCron") or {}
    if hc:
        period = hc.get("timePeriod")
        unit = hc.get("timePeriodType", "")
        days = hc.get("days") or []
        bits = []
        if period and unit:
            bits.append(f"every {period} {unit}")
        if days and len(days) < 7:
            bits.append(f"on {', '.join(days)}")
        elif days and len(days) == 7:
            bits.append("daily")
        if bits:
            return " ".join(bits)
    if job.get("scheduled") is False:
        return "on-demand"
    return ""


def _render_exported_playbooks(items: list[Any]) -> list[str]:
    if not items:
        return []
    out = ["## Exported Playbooks", "",
           "Playbooks this pack exposes for use by other packs or directly "
           "from the tenant.",
           ""]
    for pb in items:
        out.append(f"- `{pb}`")
    out.append("")
    return out


# Marker fragment that schema docs carry in their generated banner. Used
# to scan a pack's docs folder for sibling schema pages without coupling
# to file naming. Must stay in sync with generate_schema_docs.py's banner.
SCHEMA_BANNER_FRAGMENT = "tools/generate_schema_docs.py"


def _discover_schemas_for_pack(docs_dir: Path) -> list[tuple[str, str]]:
    """Find sibling schema docs in this pack's docs folder.

    Returns ``[(label, filename), ...]`` sorted alphabetically by label.
    Only matches files containing the schema generator's banner — overview.md
    and any hand-authored Markdown are skipped.
    """
    if not docs_dir.exists():
        return []
    found: list[tuple[str, str]] = []
    for md in sorted(docs_dir.glob("*.md")):
        if md.name == "overview.md":
            continue
        try:
            text = md.read_text()
        except OSError:
            continue
        if SCHEMA_BANNER_FRAGMENT not in text[:600]:
            continue
        # Use the file's first H1 heading as the label
        title = md.stem
        for line in text.splitlines():
            if line.startswith("# "):
                title = line[2:].strip()
                break
        # Strip render suffixes ("— Vendor Schema", "— Phase Contract", etc.)
        title = re.sub(r"\s+—\s+(Vendor Schema|.*Contract.*)\s*$", "", title).strip()
        found.append((title, md.name))
    return sorted(found, key=lambda x: x[0].lower())


def _render_schemas_section(schemas: list[tuple[str, str]]) -> list[str]:
    """Render the Schemas section linking each sibling schema doc."""
    if not schemas:
        return []
    out = ["## Schemas", "",
           "Reference documentation for the schemas this pack defines.",
           ""]
    for label, filename in schemas:
        out.append(f"- [{label}]({filename})")
    out.append("")
    return out


# Section render order for the overview page
SECTION_ORDER: list[tuple[str, Any]] = [
    ("post_config_docs",      _render_post_config_docs),
    ("custom_packs",          _render_custom_packs),
    ("marketplace_packs",     _render_marketplace_packs),
    ("lookup_datasets",       _render_lookup_datasets),
    ("integration_instances", _render_integration_instances),
    ("jobs",                  _render_jobs),
    ("exported_playbooks",    _render_exported_playbooks),
]


# ---------------------------------------------------------------------------
# Per-pack overview rendering
# ---------------------------------------------------------------------------

def render_overview(pack_entry: dict, xsoar_config: dict, source_rel: str,
                    schemas: list[tuple[str, str]] | None = None) -> str:
    out: list[str] = []

    title = pack_entry.get("display_name") or pack_entry.get("id", "Pack")
    out.append(f"# {title} — Overview")
    out.append("")
    out.append(GENERATED_BANNER)
    out.append("")

    rows = [
        ["ID",            md_code(pack_entry.get("id"))],
        ["Version",       md_code(pack_entry.get("version"))],
        ["Category",      md_escape_cell(pack_entry.get("category"))],
        ["Pack Path",     md_code(pack_entry.get("path"))],
        ["Manifest",      f"[`{source_rel}`](https://github.com/Palo-Cortex/secops-framework/blob/main/{source_rel})"],
    ]
    rows = [r for r in rows if r[1]]
    out.extend(md_table(["Field", "Value"], rows))

    # Schemas section right after identity — puts schemas as the second
    # entry in the right-rail TOC so they're immediately discoverable.
    if schemas:
        out.extend(_render_schemas_section(schemas))

    # If there are post_config_docs, surface them prominently
    if xsoar_config.get("post_config_docs"):
        out.append(
            "> ⚠️ This pack requires manual post-install steps. "
            "See [Manual Steps](#manual-steps) below."
        )
        out.append("")

    rendered_any = False
    for key, renderer in SECTION_ORDER:
        section_lines = renderer(xsoar_config.get(key) or [])
        if section_lines:
            out.extend(section_lines)
            rendered_any = True

    if not rendered_any:
        out.append("_This pack's `xsoar_config.json` declares no installable items._")
        out.append("")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Path resolution & I/O
# ---------------------------------------------------------------------------

def resolve_docs_path(pack_entry: dict, docs_root: Path, repo_root: Path) -> Path:
    """Catalog's ``docs_path`` is authoritative; fall back to ``docs/<id>``."""
    declared = pack_entry.get("docs_path")
    if declared:
        # Catalog stores paths relative to repo root (e.g. "docs/soc-proofpoint-tap").
        p = (repo_root / declared).resolve()
        return p
    pack_id = pack_entry.get("id") or "unknown"
    return docs_root / pack_id


def load_catalog(catalog_path: Path) -> list[dict]:
    """Return ALL pack entries from the catalog.

    Visibility is intentionally NOT filtered here. Pack overviews are content,
    generated for every pack regardless of `visible`. The mkdocs nav generator
    filters by `visible` so invisible packs don't appear in nav — their pages
    still build and remain reachable by direct URL.

    Pruning still removes overview.md files for packs that are genuinely gone
    from the catalog (or whose xsoar_config.json was deleted) — that's
    orthogonal to visibility.
    """
    if not catalog_path.exists():
        raise FileNotFoundError(f"pack_catalog.json not found at {catalog_path}")
    data = json.loads(catalog_path.read_text())
    if isinstance(data, dict) and "packs" in data:
        packs = data["packs"]
    elif isinstance(data, list):
        packs = data
    else:
        raise ValueError(f"{catalog_path}: expected list of packs or {{packs: [...]}}")
    return [p for p in packs if isinstance(p, dict)]


def _safe_rel(p: Path, base: Path) -> str:
    try:
        return str(p.resolve().relative_to(base.resolve()))
    except ValueError:
        return str(p)


def process_pack(pack_entry: dict, *, repo_root: Path, docs_root: Path,
                 check: bool) -> tuple[str, bool, str, Path | None]:
    """Returns ``(pack_id, changed, log_message, output_path)``."""
    pack_id = pack_entry.get("id") or "(unknown)"
    pack_path_str = pack_entry.get("path")
    if not pack_path_str:
        return (pack_id, False, f"SKIP  {pack_id}: no path field in catalog", None)

    pack_dir = (repo_root / pack_path_str).resolve()
    cfg_path = pack_dir / "xsoar_config.json"
    if not cfg_path.exists():
        return (pack_id, False,
                f"SKIP  {pack_id}: no xsoar_config.json at {pack_path_str}",
                None)

    try:
        xsoar_config = json.loads(cfg_path.read_text())
    except json.JSONDecodeError as exc:
        return (pack_id, False, f"FAIL  {pack_id}: invalid JSON — {exc}", None)

    docs_dir = resolve_docs_path(pack_entry, docs_root, repo_root)
    out_path = docs_dir / "overview.md"
    rel_in = _safe_rel(cfg_path, repo_root)
    rel_out = _safe_rel(out_path, repo_root)

    rendered = render_overview(pack_entry, xsoar_config, rel_in,
                                schemas=_discover_schemas_for_pack(docs_dir))
    if not rendered.endswith("\n"):
        rendered += "\n"

    existing = out_path.read_text() if out_path.exists() else ""
    changed = existing != rendered

    if check:
        if changed:
            return (pack_id, True, f"DRIFT {rel_out}", out_path)
        return (pack_id, False, f"OK    {rel_out}", out_path)

    if changed:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered)
        return (pack_id, True, f"WROTE {rel_out}", out_path)
    return (pack_id, False, f"OK    {rel_out}", out_path)


def prune_orphans(current_outputs: set[Path], docs_root: Path,
                  *, check: bool) -> tuple[int, list[str]]:
    """Delete generated-banner overview.md files not in the current set.

    Only matches this script's exact ``GENERATED_BANNER`` — never touches
    hand-authored prose, even when it lives in the same folder.
    """
    if not docs_root.exists():
        return (0, [])
    log: list[str] = []
    count = 0
    for md_path in docs_root.rglob("overview.md"):
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


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Generate per-pack overview docs from xsoar_config.json."
    )
    p.add_argument("--pack", help="Single pack id from pack_catalog.json")
    p.add_argument("--check", action="store_true",
                   help="CI mode — exit 1 if any docs would change")
    p.add_argument("--no-prune", action="store_true",
                   help="Skip orphan cleanup (default: prune is on)")
    p.add_argument("--catalog",   default=str(CATALOG_PATH),
                   help=f"Default: {CATALOG_PATH}")
    p.add_argument("--docs-root", default=str(DOCS_DIR),
                   help=f"Default: {DOCS_DIR}")
    p.add_argument("--repo-root", default=str(REPO_ROOT),
                   help=f"Default: {REPO_ROOT}")
    args = p.parse_args(argv)

    catalog_path = Path(args.catalog).resolve()
    docs_root    = Path(args.docs_root).resolve()
    repo_root    = Path(args.repo_root).resolve()

    try:
        packs = load_catalog(catalog_path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.pack:
        packs = [p for p in packs if p.get("id") == args.pack]
        if not packs:
            print(f"No pack with id={args.pack} in {catalog_path}",
                  file=sys.stderr)
            return 2

    drifts = 0
    failures = 0
    current_outputs: set[Path] = set()
    for pack_entry in packs:
        _, changed, msg, out_path = process_pack(
            pack_entry,
            repo_root=repo_root,
            docs_root=docs_root,
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
    if not args.no_prune and not args.pack:
        pruned_count, prune_log = prune_orphans(current_outputs, docs_root,
                                                check=args.check)
        for line in prune_log:
            print(line)

    if failures:
        print(f"\n{failures} pack(s) failed — see errors above.", file=sys.stderr)
        return 2

    if args.check and (drifts or pruned_count):
        print(
            f"\n{drifts} overview(s) drifted, {pruned_count} orphan(s) need pruning — "
            f"run `python tools/generate_pack_overviews.py` to regenerate.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
