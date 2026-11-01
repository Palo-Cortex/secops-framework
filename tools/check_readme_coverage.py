#!/usr/bin/env python3
"""Docs gate: anything a pack PR adds must be mentioned in that pack's docs.

Compares the branch against ``origin/main`` (or a ``--base`` ref) and collects
the names the PR adds to a pack:

  * a new ``Scripts/<Name>/``        -> the script name
  * a new ``Lists/<Name>/``          -> the list name
  * a new top-level key in a list's ``_data.json`` -> the key
    (an action in ``SOCFrameworkActions_V3``, a flag in ``SOCFWFeatureFlags``,
    a data source in ``SOCProductCategoryMap_V3``, a mode, ...)

Each name must appear in the pack's ``README.md``, in ``docs/capabilities.yml``,
or in a hand-authored page under the pack's ``docs/`` folder (generated pages
carry a banner and do not count — they would mention everything).

Only packs whose README has joined the catalog shape are gated; the marker
``<!-- capabilities:begin -->`` is the opt-in. Other packs are skipped.

Usage::

    python tools/check_readme_coverage.py Packs/soc-optimization-unified
    python tools/check_readme_coverage.py Packs/<pack> --base origin/main
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OPT_IN_MARKER = "<!-- capabilities:begin -->"
GENERATED_MARKER = "GENERATED FILE"
LIST_META_KEYS = {"id", "name", "version", "description", "note", "_note"}


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True,
                          text=True, check=False).stdout


def resolve_base(base: str | None) -> str | None:
    """The merge base with origin/main, so the diff is what this branch adds
    (committed or not), never what main moved on to."""
    for candidate in ([base] if base else []) + ["origin/main", "main"]:
        if git("rev-parse", "--verify", "--quiet", candidate).strip():
            merge_base = git("merge-base", candidate, "HEAD").strip()
            return merge_base or candidate
    return None


def added_names(pack: Path, base: str) -> list[tuple[str, str]]:
    """``[(name, where), ...]`` for everything the branch adds to the pack."""
    rel_pack = pack.relative_to(REPO_ROOT).as_posix()
    # Working tree against the base: the local gate runs before the commit.
    status = git("diff", "--name-status", "--diff-filter=AM", base, "--", rel_pack)
    # Untracked files are invisible to git diff; a brand-new script or list
    # before its first `git add` is exactly the case the local gate exists for.
    untracked = git("ls-files", "--others", "--exclude-standard", "--", rel_pack)
    entries = [line.split("\t") for line in status.splitlines()]
    entries += [["A", path] for path in untracked.splitlines() if path]
    found: list[tuple[str, str]] = []
    seen_dirs: set[str] = set()
    for parts in entries:
        if len(parts) < 2:
            continue
        kind, path = parts[0], parts[-1]
        rel = Path(path).relative_to(rel_pack)
        if len(rel.parts) >= 2 and rel.parts[0] in ("Scripts", "Lists"):
            item_dir = rel.parts[1]
            dir_rel = f"{rel_pack}/{rel.parts[0]}/{item_dir}"
            if kind == "A" and dir_rel not in seen_dirs:
                seen_dirs.add(dir_rel)
                # New directory: nothing under it exists on the base ref.
                if not git("ls-tree", "--name-only", base, "--", dir_rel + "/").strip():
                    found.append((item_dir, f"new {rel.parts[0][:-1].lower()} {dir_rel}/"))
        if rel.parts[0] == "Lists" and path.endswith("_data.json"):
            try:
                new = json.loads((REPO_ROOT / path).read_text())
            except (OSError, json.JSONDecodeError):
                continue
            old_text = git("show", f"{base}:{path}") if kind == "M" else ""
            try:
                old = json.loads(old_text) if old_text else {}
            except json.JSONDecodeError:
                old = {}
            if isinstance(new, dict):
                old_keys = set(old) if isinstance(old, dict) else set()
                for key in new:
                    if key in LIST_META_KEYS or key in old_keys:
                        continue
                    found.append((key, f"new key in {path}"))
    return found


def mention_corpus(pack: Path) -> str:
    texts = []
    readme = pack / "README.md"
    if readme.is_file():
        texts.append(readme.read_text())
    catalog = REPO_ROOT / "docs" / "capabilities.yml"
    if catalog.is_file():
        texts.append(catalog.read_text())
    docs_dir = REPO_ROOT / "docs" / pack.name
    if docs_dir.is_dir():
        for md in docs_dir.glob("*.md"):
            text = md.read_text()
            if GENERATED_MARKER in text[:600]:
                continue
            texts.append(text)
    return "\n".join(texts)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Fail when a pack PR adds names its docs never mention.")
    p.add_argument("pack", help="Pack directory, e.g. Packs/soc-optimization-unified")
    p.add_argument("--base", help="Git ref to diff against (default: origin/main, then main)")
    args = p.parse_args(argv)

    pack = (REPO_ROOT / args.pack).resolve()
    if not pack.is_dir():
        print(f"ERROR: {args.pack} is not a directory", file=sys.stderr)
        return 2
    readme = pack / "README.md"
    if not readme.is_file() or OPT_IN_MARKER not in readme.read_text():
        print(f"SKIP  {pack.name}: README has not joined the catalog shape (no {OPT_IN_MARKER})")
        return 0

    base = resolve_base(args.base)
    if base is None:
        print("SKIP  no base ref (origin/main) to diff against")
        return 0

    names = added_names(pack, base)
    if not names:
        print(f"OK    {pack.name}: nothing added since the merge base with main")
        return 0

    corpus = mention_corpus(pack)
    missing = [(n, where) for n, where in names if n not in corpus]
    for n, where in names:
        print(f"{'MISSING' if n not in corpus else 'OK     '} {n}  ({where})")
    if missing:
        print(
            f"\n{len(missing)} name(s) added to {pack.name} are not mentioned in its README.md, "
            f"docs/capabilities.yml, or a hand-authored page under docs/{pack.name}/.\n"
            "Document what you added (the capability page it belongs to, or a README row) "
            "and re-run.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
