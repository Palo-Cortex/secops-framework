#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Dict, Any, Optional, List


def load_existing_catalog(catalog_path: Path) -> Dict[str, Any]:
    """Load existing catalog if it exists, otherwise return an empty skeleton."""
    if not catalog_path.exists():
        return {"packs": []}
    with catalog_path.open("r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            raise SystemExit(f"ERROR: Failed to parse existing catalog: {catalog_path}")
    if "packs" not in data or not isinstance(data["packs"], list):
        data["packs"] = []
    return data


def index_catalog_by_id(catalog: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Return a dict mapping pack id -> catalog entry for quick lookup."""
    by_id: Dict[str, Dict[str, Any]] = {}
    for entry in catalog.get("packs", []):
        pid = entry.get("id")
        if isinstance(pid, str):
            by_id[pid] = entry
    return by_id


def discover_packs(packs_dir: Path) -> List[Path]:
    """Return a list of candidate pack directories (those with pack_metadata.json)."""
    if not packs_dir.is_dir():
        raise SystemExit(f"ERROR: Packs directory does not exist: {packs_dir}")

    pack_dirs: List[Path] = []
    for child in sorted(packs_dir.iterdir()):
        if not child.is_dir():
            continue
        meta_path = child / "pack_metadata.json"
        if meta_path.is_file():
            pack_dirs.append(child)
    return pack_dirs


def read_pack_metadata(meta_path: Path) -> Dict[str, Any]:
    with meta_path.open("r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            raise SystemExit(f"ERROR: Failed to parse pack_metadata.json: {meta_path}")


def build_catalog_entry(
        pack_dir: Path,
        meta: Dict[str, Any],
        existing_entry: Optional[Dict[str, Any]],
        org: str,
        repo: str,
        ref: str,
) -> Dict[str, Any]:
    """
    Build a single catalog entry for a pack.

    - id: folder name under Packs/
    - display_name: from metadata.name (fallback to id)
    - version: from metadata.currentVersion (optional)
    - path: relative path to pack (e.g., Packs/soc-framework-unified)
    - visible: preserve existing visible if present, otherwise default false
    - xsoar_config: raw.githubusercontent.com URL to xsoar_config.json if present, else None
    """
    pack_id = pack_dir.name
    display_name = meta.get("name") or meta.get("id") or pack_id
    version = meta.get("currentVersion", "")

    # Preserve existing "visible" if present; otherwise default to False
    visible = False
    if existing_entry is not None and isinstance(existing_entry.get("visible"), bool):
        visible = existing_entry["visible"]

    # Detect xsoar_config.json and build raw URL if it exists
    xsoar_config_path = pack_dir / "xsoar_config.json"
    if xsoar_config_path.is_file():
        rel_path = f"{pack_dir.as_posix()}/xsoar_config.json"
        xsoar_config_url = (
            f"https://raw.githubusercontent.com/{org}/{repo}/{ref}/{rel_path}"
        )
    else:
        xsoar_config_url = None

    return {
        "id": pack_id,
        "display_name": display_name,
        "version": version,
        "path": str(pack_dir.as_posix()),
        "visible": visible,
        "xsoar_config": xsoar_config_url,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Build or update pack_catalog.json from Packs/*/pack_metadata.json"
    )
    parser.add_argument(
        "--packs-dir",
        default="Packs",
        help="Path to the Packs directory (default: Packs)",
    )
    parser.add_argument(
        "--catalog",
        default="pack_catalog.json",
        help="Path to the catalog JSON file (default: pack_catalog.json at repo root)",
    )
    parser.add_argument(
        "--org",
        default="Palo-Cortex",
        help="GitHub org for raw.githubusercontent URLs (default: Palo-Cortex)",
    )
    parser.add_argument(
        "--repo",
        default="secops-framework",
        help="GitHub repo for raw.githubusercontent URLs (default: secops-framework)",
    )
    parser.add_argument(
        "--ref",
        default="refs/heads/main",
        help=(
            "Git ref/branch used for constructing raw.githubusercontent URLs "
            "(default: refs/heads/main)"
        ),
    )

    args = parser.parse_args()

    packs_dir = Path(args.packs_dir)
    catalog_path = Path(args.catalog)
    org = args.org
    repo = args.repo
    ref = args.ref

    print(f"Using packs directory: {packs_dir}")
    print(f"Using catalog file:    {catalog_path}")
    print(f"Using GitHub org:      {org}")
    print(f"Using GitHub repo:     {repo}")
    print(f"Using Git ref:         {ref}")

    existing_catalog = load_existing_catalog(catalog_path)
    existing_by_id = index_catalog_by_id(existing_catalog)

    pack_dirs = discover_packs(packs_dir)
    print(f"Discovered {len(pack_dirs)} packs with pack_metadata.json")

    new_entries = []
    for pack_dir in pack_dirs:
        meta_path = pack_dir / "pack_metadata.json"
        meta = read_pack_metadata(meta_path)
        existing_entry = existing_by_id.get(pack_dir.name)
        entry = build_catalog_entry(pack_dir, meta, existing_entry, org, repo, ref)
        new_entries.append(entry)

    # Sort for stable diffs
    new_entries.sort(key=lambda e: e.get("id", ""))

    new_catalog = {"packs": new_entries}

    catalog_path.parent.mkdir(parents=True, exist_ok=True)
    with catalog_path.open("w", encoding="utf-8") as f:
        json.dump(new_catalog, f, indent=2)
        f.write("\n")

    print(f"Wrote catalog with {len(new_entries)} packs to: {catalog_path}")


if __name__ == "__main__":
    main()
