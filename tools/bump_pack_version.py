#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Tuple


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"ERROR: File not found: {path}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"ERROR: Failed to parse JSON {path}: {e}")


def save_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote: {path}")


def choose_bump_type(current_version: str) -> str:
    """
    Ask the user whether to bump Major, Minor, or Revision (patch),
    showing the semantic version guidance.
    Returns one of: 'major', 'minor', 'revision'
    """
    print(f"Current version: {current_version}")
    print()
    print("Select version bump type:")
    print("  [R] Revision  - when you make backwards compatible bug fixes.")
    print("  [M] Minor     - when you add functionality in a backwards compatible manner.")
    print(
        "  [J] Major     - when you make incompatible API changes or revamping the pack "
        "by adding to it a lot of new backwards compatible functionality."
    )
    print()

    while True:
        choice = input("Enter choice (R=Revision, M=Minor, J=Major): ").strip().lower()

        if choice in ("r", "rev", "revision", "patch"):
            return "revision"
        if choice in ("m", "min", "minor"):
            return "minor"
        if choice in ("j", "maj", "major"):
            return "major"

        print("Invalid choice. Please enter R, M, or J.")


def bump_semver(version: str, part: str) -> str:
    """
    Bump the given semantic version:

      part='revision' -> X.Y.(Z+1)
      part='minor'    -> X.(Y+1).0
      part='major'    -> (X+1).0.0
    """
    parts = version.strip().split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise SystemExit(f"ERROR: Version '{version}' is not in expected X.Y.Z format")

    major, minor, patch = map(int, parts)

    if part == "revision":
        patch += 1
    elif part == "minor":
        minor += 1
        patch = 0
    elif part == "major":
        major += 1
        minor = 0
        patch = 0
    else:
        raise SystemExit(f"ERROR: Unknown bump part '{part}'")

    return f"{major}.{minor}.{patch}"


def bump_pack_metadata(pack_metadata_path: Path) -> Tuple[str, str]:
    """
    Bump version in pack_metadata.json *interactively* based on user choice.
    Returns (old_version, new_version).
    """
    meta = load_json(pack_metadata_path)

    old_version = meta.get("version") or meta.get("currentVersion")
    if not old_version:
        raise SystemExit(
            f"ERROR: No 'version' or 'currentVersion' found in {pack_metadata_path}"
        )

    bump_type = choose_bump_type(old_version)
    new_version = bump_semver(old_version, bump_type)

    print(f"Selected bump: {bump_type.upper()}")
    print(f"pack_metadata.json: {old_version} -> {new_version}")

    # Update whichever fields exist
    if "version" in meta:
        meta["version"] = new_version
    if "currentVersion" in meta:
        meta["currentVersion"] = new_version

    save_json(pack_metadata_path, meta)
    return old_version, new_version


def bump_xsoar_config(config_path: Path, old_version: str, new_version: str) -> None:
    """
    - If top-level 'version' exists, set it to new_version.
    - For ALL custom_packs entries, replace
        ...-v<old_version>...
      with
        ...-v<new_version>...
      in the 'url' field.
    - Only write the file if something actually changed.
    """
    if not config_path.exists():
        print(f"xsoar_config.json not found at {config_path}, skipping.")
        return

    cfg = load_json(config_path)
    changed = False

    # Top-level version (if present)
    old_cfg_version = cfg.get("version")
    if old_cfg_version is not None and old_cfg_version != new_version:
        print(f"xsoar_config.json version: {old_cfg_version} -> {new_version}")
        cfg["version"] = new_version
        changed = True

    # Update URLs under custom_packs[*].url
    custom_packs = cfg.get("custom_packs")
    if isinstance(custom_packs, list):
        pattern_old = f"-v{old_version}"
        pattern_new = f"-v{new_version}"

        for entry in custom_packs:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url")
            if not isinstance(url, str):
                continue

            new_url = url.replace(pattern_old, pattern_new)
            if new_url != url:
                print(f"custom_packs[{entry.get('id', '?')}].url:")
                print(f"  {url}")
                print(f"  -> {new_url}")
                entry["url"] = new_url
                changed = True
    else:
        print(f"No 'custom_packs' list in {config_path}, skipping URL updates.")

    if changed:
        save_json(config_path, cfg)
    else:
        print("No changes made to xsoar_config.json; not rewriting file.")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Interactively bump version in pack_metadata.json and xsoar_config.json "
            "for a given pack (Major / Minor / Revision), and update custom_packs.url "
            "version segments in-place."
        )
    )
    parser.add_argument(
        "pack_path",
        help="Path to the pack directory (e.g. Packs/soc-optimization-unified)",
    )

    args = parser.parse_args()
    pack_dir = Path(args.pack_path)

    if not pack_dir.is_dir():
        raise SystemExit(f"ERROR: Pack directory does not exist: {pack_dir}")

    pack_metadata_path = pack_dir / "pack_metadata.json"
    xsoar_config_path = pack_dir / "xsoar_config.json"

    print(f"Using pack directory: {pack_dir}")

    old_ver, new_ver = bump_pack_metadata(pack_metadata_path)
    bump_xsoar_config(xsoar_config_path, old_ver, new_ver)

    print()
    print(f"Done. Version bumped from {old_ver} to {new_ver}.")


if __name__ == "__main__":
    main()
