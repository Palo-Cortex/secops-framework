#!/usr/bin/env python3
"""
check_dependency_versions.py

Compares version strings embedded in each pack's xsoar_config.json URLs
against the current versions in pack_catalog.json.

No pack content is read. This is purely a version string comparison.

Pinned dependencies (intentional version locks) are read from
dependency_pins.json in the pack directory and silently skipped.

Usage:
  python tools/check_dependency_versions.py                         # check all packs, warn only
  python tools/check_dependency_versions.py --pack my-pack         # check one pack only
  python tools/check_dependency_versions.py --fix                   # rewrite all stale URLs
  python tools/check_dependency_versions.py --fix-dep nist-ir       # fix one dependency only
  python tools/check_dependency_versions.py --strict                # exit 1 on mismatch (no fix)
  python tools/check_dependency_versions.py --pin dep reason        # add a suppression pin
"""

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

VERSION_IN_URL = re.compile(r"/releases/download/[^/]+-v([^/]+)/")
PINS_FILENAME = "dependency_pins.json"


def load_catalog(root: Path) -> dict[str, str]:
    """Returns {pack_name: version} from pack_catalog.json."""
    catalog_path = root / "pack_catalog.json"
    if not catalog_path.exists():
        print("::warning::pack_catalog.json not found — skipping dependency check.")
        sys.exit(0)
    catalog = json.loads(catalog_path.read_text())
    if isinstance(catalog, dict) and "packs" in catalog:
        return {p["id"]: p["version"] for p in catalog["packs"]}
    if isinstance(catalog, dict):
        return catalog
    raise ValueError(f"Unrecognized pack_catalog.json shape: {type(catalog)}")


def load_pins(pack_dir: Path) -> dict[str, dict]:
    """Returns {dep_name: pin_record} for this pack."""
    pins_path = pack_dir / PINS_FILENAME
    if not pins_path.exists():
        return {}
    return json.loads(pins_path.read_text())


def write_pins(pack_dir: Path, pins: dict) -> None:
    (pack_dir / PINS_FILENAME).write_text(json.dumps(pins, indent=2) + "\n")


def pack_name_from_id(entry_id: str) -> str:
    return entry_id.removesuffix(".zip")


def version_from_url(url: str) -> str | None:
    m = VERSION_IN_URL.search(url)
    return m.group(1) if m else None


def updated_url(url: str, new_version: str) -> str:
    """Rewrites both the tag segment and filename segment in the URL."""
    return re.sub(
        r"(/releases/download/([^/]+)-v)[^/]+(/\2-v)[^/]+(\.zip)",
        lambda m: f"{m.group(1)}{new_version}{m.group(3)}{new_version}{m.group(4)}",
        url,
    )


class Mismatch:
    def __init__(self, pack: str, dep_name: str, url_version: str,
                 catalog_version: str, url: str):
        self.pack = pack
        self.dep_name = dep_name
        self.url_version = url_version
        self.catalog_version = catalog_version
        self.url = url


def check_pack(
    pack_dir: Path,
    catalog: dict[str, str],
    fix_dep: str | None = None,
    fix_all: bool = False,
) -> list[Mismatch]:
    """
    Returns Mismatch list for this pack.
    Pinned dependencies are silently skipped.
    fix_dep: rewrite one dependency URL in-place.
    fix_all: rewrite all stale URLs in-place.
    """
    config_path = pack_dir / "xsoar_config.json"
    if not config_path.exists():
        return []

    config = json.loads(config_path.read_text())
    custom_packs = config.get("custom_packs", [])
    pins = load_pins(pack_dir)
    mismatches = []
    dirty = False

    for entry in custom_packs:
        entry_id = entry.get("id", "")
        url = entry.get("url", "")
        dep_name = pack_name_from_id(entry_id)

        if dep_name not in catalog:
            continue

        if dep_name in pins:
            pin = pins[dep_name]
            print(f"  [{pack_dir.name}] {dep_name} pinned at "
                  f"v{pin.get('pinned_version', '?')} — {pin.get('reason', 'no reason')} "
                  f"(by {pin.get('pinned_by', '?')} on {pin.get('pinned_at', '?')}) — skipping.")
            continue

        catalog_version = catalog[dep_name]
        url_version = version_from_url(url)

        if url_version is None:
            print(f"  ::warning:: [{pack_dir.name}] Cannot parse version from URL "
                  f"for {dep_name}: {url}")
            continue

        if url_version != catalog_version:
            mismatches.append(Mismatch(
                pack=pack_dir.name,
                dep_name=dep_name,
                url_version=url_version,
                catalog_version=catalog_version,
                url=url,
            ))
            if fix_all or (fix_dep and fix_dep == dep_name):
                entry["url"] = updated_url(url, catalog_version)
                dirty = True

    if dirty:
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        print(f"  [{pack_dir.name}] xsoar_config.json updated.")

    return mismatches


def add_pin(pack_dir: Path, dep_name: str, reason: str,
            actor: str, catalog: dict[str, str]) -> None:
    pins = load_pins(pack_dir)
    pinned_version = catalog.get(dep_name, "unknown")
    pins[dep_name] = {
        "pinned_version": pinned_version,
        "reason": reason,
        "pinned_by": actor,
        "pinned_at": str(date.today()),
    }
    write_pins(pack_dir, pins)
    print(f"Pinned {dep_name} at v{pinned_version} "
          f"in {pack_dir.name}/{PINS_FILENAME}")


def format_github_comment(mismatches: list[Mismatch], pack_name: str) -> str:
    rows = "\n".join(
        f"| `{m.dep_name}` | `v{m.url_version}` | `v{m.catalog_version}` | "
        f"`/fix-dep {m.dep_name}` &nbsp;·&nbsp; `/pin-dep {m.dep_name} <reason>` |"
        for m in mismatches
    )
    return f"""### ⚠️ Stale dependency versions in `{pack_name}`

| Dependency | xsoar_config.json | pack_catalog.json | Options |
|---|---|---|---|
{rows}

**Fix one:** Reply `/fix-dep <dependency-name>`
**Fix all:** Reply `/fix-deps`
**Keep this version intentionally:** Reply `/pin-dep <dependency-name> <reason>`

Pins are recorded in `{pack_name}/dependency_pins.json` and silently skipped on future runs.
"""


def resolve_pack_dirs(packs_dir: Path, pack_arg: str | None) -> list[Path]:
    if pack_arg:
        return [packs_dir / pack_arg]
    return sorted(
        p for p in packs_dir.iterdir()
        if p.is_dir() and (p / "pack_metadata.json").exists()
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pack",
        help="Scope to one pack (directory name under Packs/).")
    parser.add_argument("--fix", action="store_true",
        help="Rewrite all stale URLs in-place.")
    parser.add_argument("--fix-dep",
        help="Rewrite one specific dependency URL in-place.")
    parser.add_argument("--strict", action="store_true",
        help="Exit 1 on any mismatch. No fix is applied.")
    parser.add_argument("--pin", nargs=2, metavar=("DEP_NAME", "REASON"),
        help="Add a suppression pin. Requires --pack.")
    parser.add_argument("--actor", default="unknown",
        help="GitHub actor written into pin records.")
    parser.add_argument("--root", default=".",
        help="Repo root (default: current directory).")
    parser.add_argument("--output-format", choices=["text", "github-comment"],
        default="text")
    args = parser.parse_args()

    root = Path(args.root)
    packs_dir = root / "Packs"
    catalog = load_catalog(root)

    # ── Pin mode ──────────────────────────────────────────────────
    if args.pin:
        if not args.pack:
            print("--pin requires --pack.")
            sys.exit(1)
        dep_name, reason = args.pin
        add_pin(packs_dir / args.pack, dep_name, reason, args.actor, catalog)
        return

    # ── Check mode ────────────────────────────────────────────────
    pack_dirs = resolve_pack_dirs(packs_dir, args.pack)
    for pd in pack_dirs:
        if not pd.exists():
            print(f"Pack directory not found: {pd}")
            sys.exit(1)

    all_mismatches: list[Mismatch] = []
    for pack_dir in pack_dirs:
        all_mismatches.extend(check_pack(
            pack_dir,
            catalog,
            fix_dep=None if args.strict else args.fix_dep,
            fix_all=args.fix and not args.strict,
        ))

    if not all_mismatches:
        print("All dependency versions match pack_catalog.json. ✓")
        return

    if args.output_format == "github-comment":
        pack_name = args.pack or "multiple packs"
        print(format_github_comment(all_mismatches, pack_name))
    else:
        label = "ERROR" if args.strict else "WARNING"
        print(f"\n{label}: {len(all_mismatches)} stale reference(s):\n")
        for m in all_mismatches:
            print(f"  [{m.pack}] {m.dep_name}: "
                  f"config=v{m.url_version}  catalog=v{m.catalog_version}")
        if not args.strict:
            print("\nOptions:")
            print("  --fix              rewrite all stale URLs")
            print("  --fix-dep <name>   rewrite one dependency")
            print("  --pin <name> <reason>  suppress this mismatch permanently")
        else:
            sys.exit(1)


if __name__ == "__main__":
    main()
