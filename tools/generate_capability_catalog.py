#!/usr/bin/env python3
"""Render the capability catalog from ``docs/capabilities.yml``.

One source, two targets, so the catalog is never hand-maintained twice:

  * ``docs/reference/index.md`` — one table per pack under the landing page's
    cards, with links relative to ``docs/``.
  * ``Packs/<pack>/README.md`` — the same table with absolute site links,
    because the README is read on GitHub and in the Marketplace.

Each target carries a marker pair; everything between the markers is
replaced, everything outside is left alone::

    <!-- capabilities:begin -->
    ...
    <!-- capabilities:end -->

A README without the markers is skipped (not every pack has joined the
catalog shape yet).

Usage::

    python tools/generate_capability_catalog.py           # write
    python tools/generate_capability_catalog.py --check   # CI: fail on drift
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = REPO_ROOT / "docs"
CATALOG = DOCS_DIR / "capabilities.yml"
REFERENCE_INDEX = DOCS_DIR / "reference" / "index.md"
SITE_URL = "https://palo-cortex.github.io/secops-framework/"

BEGIN = "<!-- capabilities:begin -->"
END = "<!-- capabilities:end -->"
BLOCK_RE = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.S)
GENERATED_NOTE = "<!-- generated from docs/capabilities.yml by tools/generate_capability_catalog.py; edit the yml -->"


def site_url(page: str) -> str:
    """``docs/`` path -> published URL (``index.md`` and ``.md`` folded away)."""
    if page.endswith("index.md"):
        page = page[: -len("index.md")]
    elif page.endswith(".md"):
        page = page[:-3] + "/"
    return SITE_URL + page


def cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def render_table(rows: list[dict], link_for) -> list[str]:
    out = ["| Capability | What it does | Page |", "|---|---|---|"]
    for row in rows:
        name = cell(row["name"])
        page = row.get("page")
        link = f"[{name}]({link_for(page)})" if page else "page pending"
        out.append(f"| {name} | {cell(row['does'])} | {link} |")
    return out


def render_block(packs: dict, *, for_pack: str | None, link_for) -> str:
    lines = [BEGIN, GENERATED_NOTE, ""]
    for pack_id, entry in packs.items():
        if for_pack and pack_id != for_pack:
            continue
        if not for_pack:
            lines += [f"### {entry['title']}", ""]
        lines += render_table(entry["capabilities"], link_for)
        lines.append("")
    lines.append(END)
    return "\n".join(lines)


def splice(path: Path, block: str, check: bool) -> tuple[bool, str]:
    """Replace the marker block in ``path``. Returns (changed, log line)."""
    rel = path.relative_to(REPO_ROOT)
    if not path.exists():
        return False, f"SKIP  {rel}: not found"
    text = path.read_text()
    if not BLOCK_RE.search(text):
        return False, f"SKIP  {rel}: no {BEGIN} / {END} markers"
    rendered = BLOCK_RE.sub(lambda m: block, text, count=1)
    if rendered == text:
        return False, f"OK    {rel}"
    if check:
        return True, f"DRIFT {rel}"
    path.write_text(rendered)
    return True, f"WROTE {rel}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Render the capability catalog into docs and READMEs.")
    p.add_argument("--check", action="store_true", help="CI mode — exit 1 if anything would change")
    args = p.parse_args(argv)

    if not CATALOG.exists():
        print(f"ERROR: {CATALOG} not found", file=sys.stderr)
        return 2
    packs = yaml.safe_load(CATALOG.read_text()) or {}
    for pack_id, entry in packs.items():
        for row in entry.get("capabilities") or []:
            page = row.get("page")
            if page and not (DOCS_DIR / page).is_file():
                print(f"ERROR: {pack_id} / {row.get('name')}: page {page} does not exist under docs/",
                      file=sys.stderr)
                return 2

    drift = 0
    ref_dir = REFERENCE_INDEX.parent
    changed, msg = splice(
        REFERENCE_INDEX,
        render_block(packs, for_pack=None,
                     link_for=lambda page: os.path.relpath(DOCS_DIR / page, ref_dir)),
        args.check,
    )
    print(msg)
    drift += changed

    for pack_id in packs:
        changed, msg = splice(
            REPO_ROOT / "Packs" / pack_id / "README.md",
            render_block(packs, for_pack=pack_id, link_for=site_url),
            args.check,
        )
        print(msg)
        drift += changed

    if args.check and drift:
        print("\ncapability catalog is out of date — run `python tools/generate_capability_catalog.py`.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
