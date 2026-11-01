#!/usr/bin/env python3
"""Generate docs/index.md from docs/index.md.template.

The home page surfaces the framework's install link, which is owned by
``Packs/soc-optimization-unified/xsoar_config.json`` (specifically the
first ``post_config_docs`` entry). Hard-coding the URL on the home page
would create two sources of truth; pulling from the JSON keeps it as one.

The template carries a ``# {{INSTALL_LINK}}`` marker that this script
substitutes with a properly-formatted Markdown link.

Usage::

    python tools/generate_home_page.py             # write docs/index.md
    python tools/generate_home_page.py --check     # CI: fail on drift
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE  = REPO_ROOT / "docs" / "index.md.template"
OUTPUT    = REPO_ROOT / "docs" / "index.md"

# Pack that owns the canonical install README. Hard-coded because it's the
# *only* pack that holds the framework-level install steps; not configurable.
INSTALL_PACK = "soc-optimization-unified"
INSTALL_PACK_PATH = REPO_ROOT / "Packs" / INSTALL_PACK / "xsoar_config.json"

MARKER = "# {{INSTALL_LINK}}"


def load_install_doc(pack_config_path: Path) -> dict:
    """Return the first ``post_config_docs`` entry from the pack's xsoar_config.

    Errors if the file is missing, malformed, or has no post_config_docs —
    those are all "the home page can't be generated correctly" conditions
    that should fail loudly rather than silently produce a broken link.
    """
    if not pack_config_path.exists():
        raise FileNotFoundError(
            f"{pack_config_path} not found — the home page generator depends "
            f"on this file for the install link URL."
        )
    data = json.loads(pack_config_path.read_text())
    docs = data.get("post_config_docs") or []
    if not docs:
        raise ValueError(
            f"{pack_config_path} has no `post_config_docs` entries — "
            f"the home page generator needs at least one to link to."
        )
    first = docs[0]
    if not isinstance(first, dict) or not first.get("url"):
        raise ValueError(
            f"{pack_config_path}: first post_config_docs entry has no `url` "
            f"field. Each entry must be {{name, url}}."
        )
    return first


INSTALL_PAGE = "evaluate/install.md"


def render_install_block(install_doc: dict) -> str:
    """Render the install link as a single-line Markdown link.

    The link goes to the site's own install page, which includes the pack's
    ``POST_CONFIG_README.md`` by snippet — the same file the manifest's
    ``post_config_docs`` entry points at on GitHub. ``install_doc`` is only
    checked, not rendered: if the pack stops declaring it, the home page
    generator fails rather than quietly linking to an install page whose
    source is gone.
    """
    if "POST_CONFIG_README.md" not in install_doc["url"]:
        raise ValueError(
            f"first post_config_docs entry is not POST_CONFIG_README.md "
            f"({install_doc['url']}); {INSTALL_PAGE} includes that file."
        )
    return f"**[→ Install the SOC Framework]({INSTALL_PAGE})** · about 30 minutes\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Generate docs/index.md from index.md.template + xsoar_config."
    )
    p.add_argument("--check", action="store_true",
                   help="CI mode — exit 1 if docs/index.md would change")
    p.add_argument("--template",       default=str(TEMPLATE))
    p.add_argument("--output",         default=str(OUTPUT))
    p.add_argument("--install-config", default=str(INSTALL_PACK_PATH),
                   help=f"Default: {INSTALL_PACK_PATH}")
    args = p.parse_args(argv)

    template_path = Path(args.template).resolve()
    output_path   = Path(args.output).resolve()
    config_path   = Path(args.install_config).resolve()

    if not template_path.exists():
        print(f"ERROR: template not found at {template_path}", file=sys.stderr)
        return 2

    try:
        install_block = render_install_block(load_install_doc(config_path))
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    template_text = template_path.read_text()
    if MARKER not in template_text:
        print(f"ERROR: template is missing the '{MARKER}' marker.",
              file=sys.stderr)
        return 2

    # Match the marker line preserving its leading whitespace, replace with
    # the install block at the same indent.
    pattern = re.compile(r"^(\s*)" + re.escape(MARKER) + r"\s*$", re.MULTILINE)
    rendered = pattern.sub(
        lambda m: m.group(1) + install_block,
        template_text,
        count=1,
    )

    if not rendered.endswith("\n"):
        rendered += "\n"

    existing = output_path.read_text() if output_path.exists() else ""
    changed = existing != rendered
    rel = output_path.relative_to(REPO_ROOT) if output_path.is_relative_to(REPO_ROOT) else output_path

    if args.check:
        if changed:
            print(f"DRIFT {rel}")
            print(
                f"\ndocs/index.md is out of date — "
                f"run `python tools/generate_home_page.py` to regenerate.",
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
