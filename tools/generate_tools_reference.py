#!/usr/bin/env python3
"""Generate docs/contributing/tools.md from the docstrings in tools/*.py and tools/*.sh.

One row per tool: name, what it does (the first sentence of its module
docstring, or the first comment block of a shell script), and its usage
block when the docstring carries one (a ``Usage::`` or ``USAGE`` section,
or lines beginning with ``python3 tools/``). A tool without a docstring is
listed as ``UNVERIFIED`` so the gap is visible instead of silently absent.

The table is generated so it cannot drift from the tools it describes;
to change a row, change the tool's docstring.

Usage::

    python tools/generate_tools_reference.py           # write
    python tools/generate_tools_reference.py --check   # CI: fail on drift
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"
OUTPUT = REPO_ROOT / "docs" / "contributing" / "tools.md"

GENERATED_BANNER = (
    "<!-- GENERATED FILE — do not edit by hand. "
    "Run `python tools/generate_tools_reference.py` to regenerate; "
    "the rows come from each tool's docstring. -->"
)

# Scripts that are fixtures or one-off tests rather than tools an author runs.
SKIP = {"__init__.py"}
TEST_PREFIXES = ("test_", "SOCCommandWrapper_test_")


def first_sentence(text: str, name: str) -> str:
    lines = [l.strip() for l in text.strip().splitlines()]
    # Many docstrings open with the file name on its own line; skip it.
    lines = [l for l in lines if l and l.rstrip(":") not in (name, name.replace(".py", ""))
             and not re.fullmatch(r"[─━=\-#*_ ]+", l)
             and not l.lower().startswith(("usage", "python", "bash ", "./tools", "tools/", "$ "))]
    if not lines:
        return ""
    para = []
    for l in lines:
        if not l:
            break
        para.append(l)
        if l.endswith((".", "!", "?")):
            break
    text = " ".join(para)
    # Strip a leading "name — " / "name -- " prefix.
    text = re.sub(r"^" + re.escape(name) + r"\s*[—–-]+\s*", "", text)
    text = re.sub(r"^" + re.escape(name.replace('.py', '')) + r"\s*[—–-]+\s*", "", text)
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    return (m.group(1) if m else text).replace("|", "\\|")


def usage_lines(text: str, name: str) -> list[str]:
    out: list[str] = []
    for l in text.splitlines():
        s = l.strip()
        s = s.lstrip("$ ")
        if re.match(r"^(python3?|bash)\s+(\./)?(tools/)?" + re.escape(name) + r"(\s|$)", s):
            s = re.sub(r"^(python3?|bash)\s+(\./)?(tools/)?", lambda m: m.group(1) + " tools/", s)
            out.append(s.split("  #")[0].strip())
        if len(out) == 3:
            break
    return out


def py_doc(path: Path) -> str | None:
    try:
        return ast.get_docstring(ast.parse(path.read_text()))
    except (SyntaxError, UnicodeDecodeError):
        return None


def sh_doc(path: Path) -> str | None:
    lines = []
    for l in path.read_text(errors="ignore").splitlines()[1:]:
        if l.startswith("#"):
            lines.append(l.lstrip("#").strip())
        elif lines:
            break
    text = "\n".join(lines).strip()
    return text or None


def render() -> str:
    rows: list[tuple[str, str, list[str]]] = []
    unverified: list[str] = []
    for path in sorted(TOOLS_DIR.iterdir()):
        if not path.is_file() or path.suffix not in (".py", ".sh") or path.name in SKIP:
            continue
        if path.name.startswith(TEST_PREFIXES):
            continue
        doc = py_doc(path) if path.suffix == ".py" else sh_doc(path)
        if not doc:
            unverified.append(path.name)
            rows.append((path.name, "UNVERIFIED — no docstring", []))
            continue
        rows.append((path.name, first_sentence(doc, path.name) or "UNVERIFIED — docstring has no summary line",
                     usage_lines(doc, path.name)))

    out = ["# Tools reference", "", GENERATED_BANNER, "",
           "Every script under `tools/`, with what it does in its own words. "
           "`check_contribution.py` is the gate that runs before every commit; the rest are what it calls, "
           "the generators behind `prep_docs.py`, and the authoring and replay tools. "
           "Run any of them with `--help` for its arguments.", "",
           "| Tool | What it does | Usage |", "|---|---|---|"]
    for name, summary, usage in rows:
        use = "<br>".join(f"`{u}`" for u in usage) if usage else ""
        out.append(f"| `{name}` | {summary} | {use} |")
    out.append("")
    if unverified:
        out += ["## Without a docstring", "",
                "These need a module docstring before they can be described here:", ""]
        out += [f"- `{n}`" for n in unverified]
        out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate the tools reference page from docstrings.")
    p.add_argument("--check", action="store_true", help="CI mode — exit 1 if the page would change")
    args = p.parse_args(argv)
    rendered = render()
    existing = OUTPUT.read_text() if OUTPUT.exists() else ""
    rel = OUTPUT.relative_to(REPO_ROOT)
    if rendered == existing:
        print(f"OK    {rel}")
        return 0
    if args.check:
        print(f"DRIFT {rel}")
        print("\nrun `python tools/generate_tools_reference.py` to regenerate.", file=sys.stderr)
        return 1
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered)
    print(f"WROTE {rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
