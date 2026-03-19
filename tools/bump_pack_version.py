#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Tuple

GITHUB_REPO = "Palo-Cortex/secops-framework"


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


def build_correct_url(pack_id: str, version: str) -> str:
    """
    Build the canonical GitHub release zip URL for a pack.
    Format: https://github.com/{repo}/releases/download/{pack_id}-v{version}/{pack_id}-v{version}.zip
    """
    tag = f"{pack_id}-v{version}"
    return f"https://github.com/{GITHUB_REPO}/releases/download/{tag}/{tag}.zip"


def build_correct_doc_base(pack_id: str) -> str:
    """
    Build the canonical GitHub blob base URL for a pack's docs.
    Format: https://github.com/{repo}/blob/main/Packs/{pack_id}
    """
    return f"https://github.com/{GITHUB_REPO}/blob/main/Packs/{pack_id}"


def fix_doc_urls(config_path: Path, pack_id: str) -> None:
    """
    Fix URLs in pre_config_docs and post_config_docs so they point at the
    correct pack directory in the current repo.

    Any URL that doesn't already start with the correct base is replaced.
    The filename portion (everything after the last '/') is preserved.
    """
    if not config_path.exists():
        return

    cfg = load_json(config_path)
    correct_base = build_correct_doc_base(pack_id)
    changed = False

    for section in ("pre_config_docs", "post_config_docs"):
        docs = cfg.get(section)
        if not isinstance(docs, list):
            continue

        for entry in docs:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url", "")
            if not url:
                continue

            # Preserve just the filename (e.g. POST_CONFIG_README.md)
            filename = url.rstrip("/").split("/")[-1]
            correct_url = f"{correct_base}/{filename}"

            if url != correct_url:
                print(f"{section}[{entry.get('name', '?')}] url:")
                print(f"  was: {url}")
                print(f"  now: {correct_url}")
                entry["url"] = correct_url
                changed = True

    if changed:
        save_json(config_path, cfg)
    else:
        print("pre/post_config_docs urls are already correct; not rewriting file.")


def fix_custom_pack_url(config_path: Path, pack_id: str, new_version: str) -> None:
    """
    Derive the correct zip URL from the pack directory name and new version,
    then replace whatever is currently in custom_packs[*].url.

    This catches both stale pack names (renamed directories) and stale
    version numbers in one pass.

    Also corrects custom_packs[*].id to match the expected filename.
    """
    if not config_path.exists():
        print(f"xsoar_config.json not found at {config_path}, skipping.")
        return

    cfg = load_json(config_path)
    custom_packs = cfg.get("custom_packs")
    if not isinstance(custom_packs, list):
        print(f"No 'custom_packs' list in {config_path}, skipping URL fix.")
        return

    correct_url = build_correct_url(pack_id, new_version)
    correct_id  = f"{pack_id}-v{new_version}.zip"
    changed = False

    for entry in custom_packs:
        if not isinstance(entry, dict):
            continue

        current_url = entry.get("url", "")
        current_id  = entry.get("id", "")

        # Only update the entry that belongs to this pack — match on pack_id
        # in either the existing id or url to avoid clobbering sibling packs.
        if pack_id not in current_id and pack_id not in current_url:
            continue

        if current_url != correct_url:
            print(f"custom_packs url:")
            print(f"  was: {current_url}")
            print(f"  now: {correct_url}")
            entry["url"] = correct_url
            changed = True

        if current_id != correct_id:
            print(f"custom_packs id:")
            print(f"  was: {current_id}")
            print(f"  now: {correct_id}")
            entry["id"] = correct_id
            changed = True

    if changed:
        save_json(config_path, cfg)
    else:
        print("custom_packs url and id are already correct; not rewriting file.")


def bump_xsoar_config_version(config_path: Path, old_version: str, new_version: str) -> None:
    """
    Update the top-level 'version' field in xsoar_config.json if present.
    URL/id correction is handled separately by fix_custom_pack_url.
    """
    if not config_path.exists():
        return

    cfg = load_json(config_path)
    changed = False

    old_cfg_version = cfg.get("version")
    if old_cfg_version is not None and old_cfg_version != new_version:
        print(f"xsoar_config.json version: {old_cfg_version} -> {new_version}")
        cfg["version"] = new_version
        changed = True

    if changed:
        save_json(config_path, cfg)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Interactively bump version in pack_metadata.json and xsoar_config.json "
            "for a given pack (Major / Minor / Revision). "
            "Auto-corrects custom_packs zip URL and id based on the actual pack "
            "directory name — catches stale names from directory renames."
        )
    )
    parser.add_argument(
        "pack_path",
        help="Path to the pack directory (e.g. Packs/SocFrameworkProofPointTap)",
    )

    args = parser.parse_args()
    pack_dir = Path(args.pack_path)

    if not pack_dir.is_dir():
        raise SystemExit(f"ERROR: Pack directory does not exist: {pack_dir}")

    # Derive pack ID from the directory name — this is the source of truth
    pack_id = pack_dir.name
    pack_metadata_path = pack_dir / "pack_metadata.json"
    xsoar_config_path  = pack_dir / "xsoar_config.json"

    print(f"Pack directory : {pack_dir}")
    print(f"Pack ID (dir)  : {pack_id}")
    print()

    old_ver, new_ver = bump_pack_metadata(pack_metadata_path)

    # 1. Update top-level version in xsoar_config.json
    bump_xsoar_config_version(xsoar_config_path, old_ver, new_ver)

    # 2. Fix custom_packs url + id using directory name as source of truth
    fix_custom_pack_url(xsoar_config_path, pack_id, new_ver)

    # 3. Fix pre/post_config_docs urls using directory name as source of truth
    fix_doc_urls(xsoar_config_path, pack_id)

    print()
    print(f"Done. Version bumped from {old_ver} to {new_ver}.")
    print(f"Zip URL target : {build_correct_url(pack_id, new_ver)}")


if __name__ == "__main__":
    main()
