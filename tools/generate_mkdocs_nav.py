#!/usr/bin/env python3
"""Generate mkdocs.yml from mkdocs.yml.template by injecting auto-generated
``Foundation`` and ``Packs`` nav sections.

For every visible pack in ``pack_catalog.json``:
  - looks at the pack's ``docs_path`` for an ``overview.md``
  - looks for any other ``*.md`` files with the schema-doc generated banner
  - builds a sub-nav: Overview first, schema docs alphabetical

Packs are bucketed by their ``tier`` field:
  - ``tier: foundation``  →  Foundation section (framework-tier packs)
  - anything else / unset →  Packs section (vendor / data-source packs)

The template carries two markers that get substituted:
  ``# {{AUTO_FOUNDATION}}``  and  ``# {{AUTO_PACKS}}``

Usage::

    python tools/generate_mkdocs_nav.py             # write mkdocs.yml
    python tools/generate_mkdocs_nav.py --check     # CI: fail on drift
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "pack_catalog.json"
DOCS_DIR     = REPO_ROOT / "docs"
TEMPLATE     = REPO_ROOT / "mkdocs.yml.template"
OUTPUT       = REPO_ROOT / "mkdocs.yml"

MARKER_FOUNDATION = "# {{AUTO_FOUNDATION}}"
MARKER_PACKS      = "# {{AUTO_PACKS}}"

# Banner fragments stamped by the schema generator. We use these to discover
# what each generator produced — anything else under a pack's docs_path is
# hand-authored and gets ignored by the nav generator.
SCHEMA_BANNER  = "tools/generate_schema_docs.py"
OVERVIEW_NAME  = "overview.md"


def load_visible_packs(catalog_path: Path) -> list[dict]:
    if not catalog_path.exists():
        raise FileNotFoundError(f"pack_catalog.json not found at {catalog_path}")
    data = json.loads(catalog_path.read_text())
    packs = data.get("packs") if isinstance(data, dict) else data
    if not isinstance(packs, list):
        raise ValueError(f"{catalog_path}: expected list of packs")
    return [p for p in packs if isinstance(p, dict) and p.get("visible") is True]


def first_h1_title(md_path: Path) -> str:
    """Use the file's first ``# Heading`` as its nav label."""
    try:
        for line in md_path.read_text().splitlines():
            if line.startswith("# "):
                return line[2:].strip()
    except OSError:
        pass
    return md_path.stem


def discover_pack_pages(docs_path: Path, repo_root: Path) -> list[tuple[str, str]]:
    """Return ``[(label, mkdocs-relative-path), ...]`` for one pack.

    Overview always first; schema docs alphabetical by their first H1 label.
    Hand-authored .md files in the same folder are NOT included — only
    generator output appears in the auto Packs section.
    """
    if not docs_path.exists():
        return []

    pages: list[tuple[str, str, Path]] = []  # (sort_key, label, path)

    overview = docs_path / OVERVIEW_NAME
    if overview.is_file():
        pages.append(("0", "Overview", overview))

    for md in sorted(docs_path.glob("*.md")):
        if md.name == OVERVIEW_NAME:
            continue
        try:
            head = md.read_text()[:600]
        except OSError:
            continue
        if SCHEMA_BANNER not in head:
            continue
        title = first_h1_title(md)
        # Strip any trailing " — Vendor Schema" / similar render suffix
        title = re.sub(r"\s+—\s+(Vendor Schema|.*Contract.*)$", "", title).strip()
        pages.append(("1:" + title.lower(), title, md))

    pages.sort(key=lambda x: x[0])

    # Convert to mkdocs-relative paths (relative to docs_dir, which is docs/)
    out: list[tuple[str, str]] = []
    for _, label, path in pages:
        rel_to_docs = path.resolve().relative_to((repo_root / "docs").resolve())
        out.append((label, rel_to_docs.as_posix()))
    return out


def render_packs_section(packs: list[dict], repo_root: Path,
                         indent: str) -> str:
    """Render YAML lines for one nav section's pack list.

    Lines are emitted at the supplied indent (no parent header). The
    caller wraps these inside a parent tab in the template — the nav
    generator just produces the pack-list children.

    Returns a multi-line string with no leading or trailing newline.
    Returns an empty string if there are no packs to render so the section
    cleanly degrades to just its index.md.
    """
    enriched: list[tuple[str, dict, list[tuple[str, str]]]] = []
    for entry in packs:
        docs_path_str = entry.get("docs_path") or f"docs/{entry.get('id')}"
        docs_path = (repo_root / docs_path_str).resolve()
        pages = discover_pack_pages(docs_path, repo_root)
        if not pages:
            continue
        # Use pack id (slug) for nav label — display_name from pack_metadata
        # is often verbose ("SOC CrowdStrike Falcon Integration Enhancement
        # for Cortex XSIAM2") and wraps badly in the left rail. The id is
        # short, stable, and matches what authors recognize.
        display = entry.get("id") or entry.get("display_name") or "(unnamed)"
        enriched.append((display, entry, pages))

    enriched.sort(key=lambda x: x[0].lower())

    if not enriched:
        return ""

    lines: list[str] = []
    for display, _entry, pages in enriched:
        lines.append(f'{indent}- "{display}":')
        for label, rel in pages:
            safe_label = f'"{label}"' if any(c in label for c in ":#&*?!|>%@") else label
            lines.append(f'{indent}    - {safe_label}: {rel}')
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate mkdocs.yml from template + catalog.")
    p.add_argument("--check", action="store_true",
                   help="CI mode — exit 1 if mkdocs.yml would change")
    p.add_argument("--catalog",   default=str(CATALOG_PATH))
    p.add_argument("--template",  default=str(TEMPLATE))
    p.add_argument("--output",    default=str(OUTPUT))
    p.add_argument("--repo-root", default=str(REPO_ROOT))
    args = p.parse_args(argv)

    template_path = Path(args.template).resolve()
    output_path   = Path(args.output).resolve()
    repo_root     = Path(args.repo_root).resolve()
    catalog_path  = Path(args.catalog).resolve()

    if not template_path.exists():
        print(f"ERROR: template not found at {template_path}", file=sys.stderr)
        return 2

    try:
        packs = load_visible_packs(catalog_path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    template_text = template_path.read_text()

    # Bucket visible packs by tier
    foundation_packs = [p for p in packs if (p.get("tier") or "").lower() == "foundation"]
    vendor_packs     = [p for p in packs if (p.get("tier") or "").lower() != "foundation"]

    # Substitute each marker, preserving whatever indent the template carries.
    # If a bucket is empty, the marker line is simply removed — the section's
    # index.md still appears in nav but no pack children are listed.
    rendered = template_text
    for marker, bucket in [
        (MARKER_FOUNDATION, foundation_packs),
        (MARKER_PACKS,      vendor_packs),
    ]:
        pattern = re.compile(r"^(\s*)" + re.escape(marker) + r"\s*\n",
                             re.MULTILINE)
        match = pattern.search(rendered)
        if not match:
            print(f"ERROR: template is missing the '{marker}' marker.",
                  file=sys.stderr)
            return 2
        indent = match.group(1)
        block = render_packs_section(bucket, repo_root, indent)
        replacement = (block + "\n") if block else ""
        rendered = pattern.sub(lambda m: replacement, rendered, count=1)

    if not rendered.endswith("\n"):
        rendered += "\n"

    existing = output_path.read_text() if output_path.exists() else ""
    changed = existing != rendered

    rel = output_path.name
    if args.check:
        if changed:
            print(f"DRIFT {rel}")
            print(
                f"\nmkdocs.yml is out of date — "
                f"run `python tools/generate_mkdocs_nav.py` to regenerate.",
                file=sys.stderr,
            )
            return 1
        print(f"OK    {rel}")
        return 0

    if changed:
        output_path.write_text(rendered)
        print(f"WROTE {rel}")
    else:
        print(f"OK    {rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
