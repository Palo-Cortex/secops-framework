#!/usr/bin/env python3
"""Generate mkdocs.yml from mkdocs.yml.template and docs/nav.yml.

``docs/nav.yml`` is the hand-curated site map: the five tabs and every
hand-authored page, in order. It carries placeholders that this script
expands from ``pack_catalog.json``:

  ``"{{PACK:<id>}}"``        the generated pages of one pack (Overview first,
                             then schema docs alphabetical), inlined where
                             the placeholder sits.
  ``"{{PACKS:vendor}}"``     every visible pack without ``tier: foundation``
                             that no ``{{PACK:...}}`` placed, one group each.
  ``"{{PACKS:foundation}}"`` every visible ``tier: foundation`` pack that no
                             ``{{PACK:...}}`` placed, one group each.

For every pack the script looks at the catalog's ``docs_path`` for an
``overview.md`` and for ``*.md`` files carrying the schema-doc generated
banner. Hand-authored files under a pack's docs folder are ignored here;
list them in ``docs/nav.yml`` instead.

The expanded nav replaces the ``# {{AUTO_NAV}}`` marker in the template.

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

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "pack_catalog.json"
DOCS_DIR     = REPO_ROOT / "docs"
NAV_PATH     = DOCS_DIR / "nav.yml"
TEMPLATE     = REPO_ROOT / "mkdocs.yml.template"
OUTPUT       = REPO_ROOT / "mkdocs.yml"

MARKER_NAV = "# {{AUTO_NAV}}"

PACK_RE  = re.compile(r"^\{\{PACK:([A-Za-z0-9._-]+)\}\}$")
PACKS_RE = re.compile(r"^\{\{PACKS:(vendor|foundation)\}\}$")

# Banner fragment stamped by the schema generator. We use it to discover
# what the generator produced — anything else under a pack's docs_path is
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

    out: list[tuple[str, str]] = []
    for _, label, path in pages:
        rel_to_docs = path.resolve().relative_to((repo_root / "docs").resolve())
        out.append((label, rel_to_docs.as_posix()))
    return out


def pack_docs_path(entry: dict, repo_root: Path) -> Path:
    docs_path_str = entry.get("docs_path") or f"docs/{entry.get('id')}"
    return (repo_root / docs_path_str).resolve()


def pack_items(entry: dict, repo_root: Path) -> list[dict]:
    """Nav items for one pack: ``[{label: path}, ...]``."""
    return [{label: rel}
            for label, rel in discover_pack_pages(pack_docs_path(entry, repo_root), repo_root)]


def pack_groups(packs: list[dict], repo_root: Path) -> list[dict]:
    """One nav group per pack, labelled by pack id, sorted by id.

    Packs with no generated pages are skipped so the section degrades
    cleanly to whatever hand-authored pages sit beside the placeholder.
    """
    groups: list[tuple[str, list[dict]]] = []
    for entry in packs:
        items = pack_items(entry, repo_root)
        if not items:
            continue
        # The pack id is short, stable, and what authors recognise; the
        # catalog's display_name is often verbose and wraps in the rail.
        groups.append((entry.get("id") or entry.get("display_name") or "(unnamed)", items))
    groups.sort(key=lambda g: g[0].lower())
    return [{name: items} for name, items in groups]


class NavExpander:
    def __init__(self, packs: list[dict], repo_root: Path) -> None:
        self.by_id = {p.get("id"): p for p in packs}
        self.repo_root = repo_root
        self.placed: set[str] = set()
        self.errors: list[str] = []

    def _scan_placed(self, node) -> None:
        """First pass: record every {{PACK:id}} so bucket placeholders skip them."""
        if isinstance(node, str):
            m = PACK_RE.match(node)
            if m:
                self.placed.add(m.group(1))
        elif isinstance(node, list):
            for item in node:
                self._scan_placed(item)
        elif isinstance(node, dict):
            for value in node.values():
                self._scan_placed(value)

    def _bucket(self, kind: str) -> list[dict]:
        want_foundation = kind == "foundation"
        packs = [
            p for pid, p in self.by_id.items()
            if pid not in self.placed
            and ((p.get("tier") or "").lower() == "foundation") is want_foundation
        ]
        return pack_groups(packs, self.repo_root)

    def expand_list(self, items: list) -> list:
        out: list = []
        for item in items:
            if isinstance(item, str):
                m = PACK_RE.match(item)
                if m:
                    pid = m.group(1)
                    entry = self.by_id.get(pid)
                    if entry is None:
                        self.errors.append(
                            f"{{{{PACK:{pid}}}}}: no visible pack with that id in pack_catalog.json")
                        continue
                    out.extend(pack_items(entry, self.repo_root))
                    continue
                m = PACKS_RE.match(item)
                if m:
                    out.extend(self._bucket(m.group(1)))
                    continue
                out.append(item)          # a bare page path
            elif isinstance(item, dict):
                out.append({k: self.expand(v) for k, v in item.items()})
            else:
                out.append(item)
        return out

    def expand(self, node):
        if isinstance(node, list):
            return self.expand_list(node)
        return node

    def run(self, nav: list) -> list:
        self._scan_placed(nav)
        return self.expand(nav)


def render_nav(nav: list) -> str:
    text = yaml.safe_dump(nav, sort_keys=False, allow_unicode=True,
                          default_flow_style=False, width=1000)
    return text.rstrip("\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate mkdocs.yml from template + docs/nav.yml + catalog.")
    p.add_argument("--check", action="store_true",
                   help="CI mode — exit 1 if mkdocs.yml would change")
    p.add_argument("--catalog",   default=str(CATALOG_PATH))
    p.add_argument("--nav",       default=str(NAV_PATH))
    p.add_argument("--template",  default=str(TEMPLATE))
    p.add_argument("--output",    default=str(OUTPUT))
    p.add_argument("--repo-root", default=str(REPO_ROOT))
    args = p.parse_args(argv)

    template_path = Path(args.template).resolve()
    nav_path      = Path(args.nav).resolve()
    output_path   = Path(args.output).resolve()
    repo_root     = Path(args.repo_root).resolve()
    catalog_path  = Path(args.catalog).resolve()

    for label, path in (("template", template_path), ("nav", nav_path)):
        if not path.exists():
            print(f"ERROR: {label} not found at {path}", file=sys.stderr)
            return 2

    try:
        packs = load_visible_packs(catalog_path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        nav = yaml.safe_load(nav_path.read_text())
    except yaml.YAMLError as exc:
        print(f"ERROR: {nav_path} is not valid YAML: {exc}", file=sys.stderr)
        return 2
    if not isinstance(nav, list):
        print(f"ERROR: {nav_path} must be a YAML list (the mkdocs nav shape).", file=sys.stderr)
        return 2

    expander = NavExpander(packs, repo_root)
    expanded = expander.run(nav)
    if expander.errors:
        for err in expander.errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 2

    template_text = template_path.read_text()
    pattern = re.compile(r"^(\s*)" + re.escape(MARKER_NAV) + r"\s*\n", re.MULTILINE)
    match = pattern.search(template_text)
    if not match:
        print(f"ERROR: template is missing the '{MARKER_NAV}' marker.", file=sys.stderr)
        return 2
    indent = match.group(1)
    block = "\n".join(indent + line if line else line
                      for line in render_nav(expanded).splitlines())
    rendered = pattern.sub(lambda m: block + "\n", template_text, count=1)
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
