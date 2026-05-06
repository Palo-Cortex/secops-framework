#!/usr/bin/env python3
"""
new_vendor_pack.py — One-shot vendor pack creator from a schema YAML
=====================================================================

Orchestrates the full new-vendor-pack flow. Reads a vendor schema
(schemas/vendors/<vendor-id>/<datasource>.yaml), derives everything
needed (pack id, name, vendor / product strings, category, dataset),
and runs the existing tools in sequence:

  1. generate_vendor_content.py validate    Schema structural check
  2. init_pack.py --no-sdk                  Pack directory scaffold
                                            (pack_metadata.json, README,
                                             xsoar_config.json)
  3. generate_vendor_content.py emit        Modeling rule + correlation
                                            rule files from schema
  4. write ReleaseNotes/1_0_0.md            Templated from schema
  5. build_pack_catalog.py                  Register at v1.0.0 in the
                                            repo-root pack_catalog.json

Each underlying tool stays focused on one thing. This wrapper only
adds: schema → arg derivation, release-notes templating, and a
next-steps checklist.

Usage
-----
  python3 tools/new_vendor_pack.py \\
      --schema schemas/vendors/checkpoint-ndr/ndr-generic-alerts.yaml

  # Preview without writing anything
  python3 tools/new_vendor_pack.py --schema <path> --dry-run

  # Skip the catalog update (e.g. when iterating before first commit)
  python3 tools/new_vendor_pack.py --schema <path> --skip-catalog

  # Skip schema validation (NOT recommended — fails late)
  python3 tools/new_vendor_pack.py --schema <path> --skip-validate

Notes
-----
* Routing entry into SOCProductCategoryMap_V3 is intentionally NOT
  automated. That's an edit to a different pack and affects routing
  globally — review and add it manually as part of the same PR.
* The script must be run from the repo root (where Packs/ and
  schemas/ live), or pass --repo-root explicitly.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Schema category → Marketplace category mapping
# ---------------------------------------------------------------------------
# SOC Framework categories are coarse (Endpoint / Network / Email / etc.)
# Marketplace categories are display-oriented and slightly different.
CATEGORY_MAP = {
    "Endpoint":         "Endpoint",
    "Network":          "Network Security",
    "Email":            "Email Security",
    "Identity":         "Identity",
    "Cloud":            "Cloud",
    "Workload":         "Cloud",
    "SaaS":             "Email Security",
    "PAM":              "Identity",
    "Data":             "Utilities",
    "agentic_endpoint": "Endpoint",
}

REQUIRED_SCHEMA_FIELDS = {"vendor", "product", "data_source", "category", "pack"}


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def log(msg: str = "", prefix: str = "[new-pack]") -> None:
    if msg:
        print(f"{prefix} {msg}")
    else:
        print()


def abort(msg: str, code: int = 1) -> None:
    print(f"[new-pack] ABORT: {msg}", file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------------------
# Schema loading + derivation
# ---------------------------------------------------------------------------

def load_schema(path: Path) -> dict:
    if not path.exists():
        abort(f"Schema not found: {path}")
    try:
        with path.open() as f:
            d = yaml.safe_load(f)
    except yaml.YAMLError as e:
        abort(f"Invalid YAML: {e}")
    if not isinstance(d, dict):
        abort("Schema root must be a mapping")
    missing = REQUIRED_SCHEMA_FIELDS - set(d.keys())
    if missing:
        abort(f"Schema missing required fields: {sorted(missing)}")
    return d


def derive_description(vendor: str, product: str, data_source: str,
                       category: str) -> str:
    return (
        f"Enhancements for {vendor} {product} telemetry used by the SOC "
        f"Framework on Cortex XSIAM. Reshapes events from "
        f"`{data_source}` into properly-shaped XSIAM alerts with "
        f"DS:{vendor}/{product} tags so Foundation Product Classification "
        f"routes them into the {category} category."
    )


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------

def run_step(name: str, cmd: list, cwd: Path, dry_run: bool = False,
             allow_fail: bool = False) -> int:
    log(f"--- {name} ---")
    log(f"    $ {' '.join(str(c) for c in cmd)}")
    if dry_run:
        log("    (dry-run; not executing)")
        return 0
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.stdout:
        for line in result.stdout.rstrip().splitlines():
            log(line, prefix="    >")
    if result.stderr:
        for line in result.stderr.rstrip().splitlines():
            log(line, prefix="    !")
    if result.returncode != 0 and not allow_fail:
        abort(f"Step '{name}' failed (exit {result.returncode})", code=2)
    return result.returncode


# ---------------------------------------------------------------------------
# Release notes templating
# ---------------------------------------------------------------------------

def write_release_notes(pack_dir: Path, schema: dict, dry_run: bool = False) -> None:
    rn_dir = pack_dir / "ReleaseNotes"
    rn_path = rn_dir / "1_0_0.md"
    if rn_path.exists():
        log(f"Release notes already exist; leaving in place: {rn_path}")
        return

    vendor = schema["vendor"]
    product = schema["product"]
    data_source = schema["data_source"]
    rules = schema.get("correlation_rules", []) or []
    modeling = schema.get("modeling_rule")

    lines = [
        f"## [1.0.0] - {date.today().strftime('%B %Y')}",
        "",
        "### Added",
        "",
    ]

    if modeling:
        mr_name = modeling.get("modeling_rule_name", "Modeling Rule")
        field_count = len(modeling.get("fields", []))
        lines += [
            f"#### {mr_name} — New modeling rule",
            "",
            (
                f"Maps {vendor} {product} events from `{data_source}` into the "
                f"XDM schema. Provides {field_count} XDM field mapping"
                f"{'s' if field_count != 1 else ''} covering event identity, "
                f"alert metadata, and core artifacts. Creates the dataset "
                f"placeholder via `_schema.json` so the correlation rule can "
                f"upload on tenants where {vendor} integration data isn't yet "
                f"flowing."
            ),
            "",
        ]

    for rule in rules:
        name = rule.get("name", "Correlation Rule")
        desc = (rule.get("description") or "").strip()
        # Squash newlines/whitespace inside the description (it's a YAML folded scalar)
        desc = " ".join(desc.split())
        lines += [
            f"#### {name} — New correlation rule",
            "",
            desc if desc else f"New correlation rule for {vendor} {product}.",
            "",
        ]

    if not modeling and not rules:
        lines += [
            f"#### {vendor} {product} content",
            "",
            f"Initial release for {vendor} {product} (`{data_source}`).",
            "",
        ]

    content = "\n".join(lines).rstrip() + "\n"

    log(f"Writing release notes: {rn_path}")
    if dry_run:
        log("(dry-run; preview):")
        for line in content.splitlines():
            log(line, prefix="    |")
        return

    rn_dir.mkdir(parents=True, exist_ok=True)
    rn_path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# xsoar_config.json URL fix
# ---------------------------------------------------------------------------
# init_pack.py writes a prerelease placeholder URL
# (releases/download/prerelease/{pack_id}.zip) expecting
# bump_pack_version.py to rewrite it on subsequent version bumps.
# First-release packs at v1.0.0 never go through a bump, so the
# placeholder reaches preflight and fails. Rewrite here.

def fix_xsoar_config_url(pack_dir: Path, pack_id: str,
                         github_org: str = "Palo-Cortex",
                         repo: str = "secops-framework",
                         dry_run: bool = False) -> None:
    config_path = pack_dir / "xsoar_config.json"
    metadata_path = pack_dir / "pack_metadata.json"

    if not config_path.exists():
        log(f"    no xsoar_config.json at {config_path}; skipping")
        return
    if not metadata_path.exists():
        log(f"    no pack_metadata.json at {metadata_path}; skipping")
        return

    try:
        version = json.loads(metadata_path.read_text())["currentVersion"]
    except (json.JSONDecodeError, KeyError) as e:
        log(f"    could not read currentVersion from {metadata_path}: {e}")
        return

    config = json.loads(config_path.read_text())
    custom_packs = config.get("custom_packs", [])
    if not custom_packs:
        log("    no custom_packs entries to fix")
        return

    expected_url = (
        f"https://github.com/{github_org}/{repo}/releases/download/"
        f"{pack_id}-v{version}/{pack_id}-v{version}.zip"
    )

    changed = False
    for i, entry in enumerate(custom_packs):
        if not isinstance(entry, dict):
            continue
        old_url = entry.get("url", "")
        if old_url == expected_url:
            continue
        entry["url"] = expected_url
        changed = True
        log(f"    custom_packs[{i}].url:")
        log(f"      was:  {old_url}")
        log(f"      now:  {expected_url}")

    if not changed:
        log("    URLs already correct; no changes")
        return

    if dry_run:
        log("    (dry-run; not writing)")
        return

    config_path.write_text(json.dumps(config, indent=4) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a new vendor pack from a schema YAML.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--schema", "-s", required=True, type=Path,
        help="Path to the vendor schema YAML "
             "(e.g. schemas/vendors/checkpoint-ndr/ndr-generic-alerts.yaml)",
    )
    parser.add_argument(
        "--repo-root", type=Path, default=Path("."),
        help="Repository root. Default: current directory.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would happen without writing or executing.",
    )
    parser.add_argument(
        "--skip-validate", action="store_true",
        help="Skip the up-front schema validation step (NOT recommended).",
    )
    parser.add_argument(
        "--skip-catalog", action="store_true",
        help="Skip the pack_catalog.json update step.",
    )
    parser.add_argument(
        "--display-name", type=str, default=None,
        help="Human-readable vendor name to use in the pack description "
             "(e.g. 'Check Point'). Overrides the schema's vendor machine id "
             "(e.g. 'check-point-ndr') for prose only — does not affect file "
             "names or routing.",
    )
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    schema_path = args.schema.resolve()

    # Sanity check that we're in something that looks like the repo
    if not (repo_root / "tools").is_dir() or not (repo_root / "Packs").is_dir():
        abort(
            f"Repo root doesn't have tools/ and Packs/: {repo_root}\n"
            f"Run from the repo root or pass --repo-root explicitly."
        )

    schema = load_schema(schema_path)

    pack_id = schema["pack"]
    vendor = schema["vendor"]
    product = schema["product"]
    category = schema["category"]
    data_source = schema["data_source"]
    marketplace_category = CATEGORY_MAP.get(category, "Utilities")

    pack_dir = repo_root / "Packs" / pack_id
    description_vendor = args.display_name or vendor
    description = derive_description(description_vendor, product, data_source, category)

    # Banner
    log("=" * 60)
    log(f"Schema:           {schema_path.relative_to(repo_root) if schema_path.is_relative_to(repo_root) else schema_path}")
    log(f"Pack id:          {pack_id}")
    log(f"Pack directory:   Packs/{pack_id}")
    log(f"Vendor / Product: {vendor} / {product}")
    log(f"Category:         {category}  →  marketplace: {marketplace_category}")
    log(f"Data source:      {data_source}")
    log(f"Repo root:        {repo_root}")
    if args.dry_run:
        log("Mode:             DRY RUN")
    log("=" * 60)
    log()

    tools = repo_root / "tools"

    # 1. Validate schema
    if not args.skip_validate:
        run_step(
            "Step 1: validate schema",
            ["python3", str(tools / "generate_vendor_content.py"), "validate",
             "--mapping", str(schema_path)],
            cwd=repo_root,
            dry_run=args.dry_run,
        )
    else:
        log("Step 1: validate schema  (skipped per --skip-validate)")

    # 2. Scaffold pack directory via init_pack.py
    init_cmd = [
        "python3", str(tools / "init_pack.py"),
        "--name", pack_id,
        "--type", "vendor",
        "--desc", description,
        "--category", marketplace_category,
        "--no-sdk",
        "--packs-root", "Packs",
    ]
    if args.dry_run:
        init_cmd.append("--dry-run")
    run_step("Step 2: scaffold pack", init_cmd, cwd=repo_root, dry_run=False)
    # init_pack.py respects its own --dry-run, so pass-through above

    # 2b. Fix xsoar_config.json URL (init_pack writes a prerelease placeholder)
    log("--- Step 2b: fix xsoar_config.json URL ---")
    fix_xsoar_config_url(pack_dir, pack_id, dry_run=args.dry_run)

    # 3. Emit rules from schema
    run_step(
        "Step 3: emit content from schema",
        ["python3", str(tools / "generate_vendor_content.py"), "emit",
         "--mapping", str(schema_path),
         "--pack-root", str(pack_dir)],
        cwd=repo_root,
        dry_run=args.dry_run,
    )

    # 4. Release notes
    log("--- Step 4: write release notes ---")
    write_release_notes(pack_dir, schema, dry_run=args.dry_run)

    # 5. Update pack_catalog.json
    if not args.skip_catalog:
        run_step(
            "Step 5: update pack_catalog.json",
            ["python3", str(tools / "build_pack_catalog.py")],
            cwd=repo_root,
            dry_run=args.dry_run,
        )
    else:
        log("Step 5: update pack_catalog.json  (skipped per --skip-catalog)")

    # Next steps
    log()
    log("=" * 60)
    log("Done. Suggested next steps:")
    log()
    log(f"  Review:")
    log(f"    {pack_dir}/pack_metadata.json")
    log(f"    {pack_dir}/CorrelationRules/")
    if (pack_dir / "ModelingRules").exists() or schema.get("modeling_rule"):
        log(f"    {pack_dir}/ModelingRules/")
    log(f"    {pack_dir}/ReleaseNotes/1_0_0.md")
    log(f"    pack_catalog.json (entry for {pack_id} at v1.0.0)")
    log()
    log(f"  Add routing entry to SOCProductCategoryMap_V3:")
    log(f"    Edit Packs/soc-optimization-unified/Lists/SOCProductCategoryMap_V3/SOCProductCategoryMap_V3_data.json")
    log(f'    Add an entry whose key matches what Foundation Product Classification')
    log(f'    derives from the DS: tag your correlation rule emits — usually')
    log(f'    "ds_<vendor>_<product>" with non-alphanumerics replaced by underscores.')
    log()
    log(f"  Validate:")
    log(f"    python3 tools/pack_prep.py {pack_dir}")
    log()
    log(f"  Upload:")
    log(f"    bash tools/upload_package.sh -x -z {pack_dir}")
    log("=" * 60)


if __name__ == "__main__":
    main()
