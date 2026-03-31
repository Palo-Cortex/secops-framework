#!/usr/bin/env python3
"""
init_pack.py — SOC Framework Pack Initializer
=============================================
Wraps `demisto-sdk init --pack --xsiam` and post-processes the result
for SOC Framework conventions:

  - Correct pack_metadata.json with framework fields + dependencies
  - Prune SDK-generated directories not used by this pack type
  - Pre-create content subdirectories for the chosen pack type
  - Wire a stub entry into xsoar_config.json custom_packs
  - Emit a ready-to-run next-steps checklist

Pack types
----------
  vendor      Thin vendor layer. Correlation rules + optional modeling rule.
              Dependencies: soc-optimization-unified, soc-framework-nist-ir.
              Examples: SocFrameworkCrowdstrikeFalcon, SocFrameworkProofPointTap,
                        SocFrameworkZscalerZPA

  foundation  Shared infrastructure (SOCCommandWrapper, lists, lookups, dashboards).
              Reserved — soc-optimization-unified already exists. Use for forks only.

  nist-ir     NIST IR lifecycle playbooks. Entry points, phase playbooks, workflows.
              Dependencies: soc-optimization-unified.

Usage
-----
  python3 tools/init_pack.py --name SocFrameworkZscalerZPA --type vendor
  python3 tools/init_pack.py --name SocFrameworkAcmeSIEM --type vendor --desc "ACME SIEM correlation rules"
  python3 tools/init_pack.py --name soc-framework-nist-ir-v4 --type nist-ir

Options
-------
  --name          Pack directory name (also used as pack ID). Required.
  --type          Pack type: vendor | foundation | nist-ir. Default: vendor.
  --desc          Pack description. SDK prompts interactively if omitted.
  --category      Marketplace category. Default per type (see CATEGORY_DEFAULTS).
  --no-sdk        Skip demisto-sdk init; only write framework files (useful if
                  SDK is unavailable or pack dir was already scaffolded).
  --dry-run       Print what would happen without writing anything.
  --packs-root    Path to Packs directory. Default: Packs/ relative to repo root.
  --config        Path to xsoar_config.json. Default: xsoar_config.json.
  --github-org    GitHub org for release URL in xsoar_config.json.
                  Default: Palo-Cortex.
  --repo          Repo name for release URL. Default: secops-framework.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from textwrap import dedent


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FRAMEWORK_AUTHOR = "Palo Alto Networks"
FRAMEWORK_SUPPORT = "partner"
FRAMEWORK_EMAIL = ""
GITHUB_ORG_DEFAULT = "Palo-Cortex"
REPO_DEFAULT = "secops-framework"

CATEGORY_DEFAULTS = {
    "vendor": "Endpoint",          # override per vendor (network, email, etc.)
    "foundation": "Utilities",
    "nist-ir": "Utilities",
}

# Directories demisto-sdk creates that we strip per pack type.
# Vendor packs are intentionally thin — no playbooks, no automations.
SDK_DIRS_TO_PRUNE = {
    "vendor": [
        "Classifiers",
        "Dashboards",
        "GenericDefinitions",
        "GenericModules",
        "GenericTypes",
        "IncidentFields",
        "IncidentTypes",
        "Indicators",
        "Integrations",
        "Layouts",
        "Lists",
        "Playbooks",
        "Reports",
        "Scripts",
        "TestPlaybooks",
        "Triggers",
        "Widgets",
        "XDRCTemplates",
    ],
    "foundation": [
        "Classifiers",
        "GenericDefinitions",
        "GenericModules",
        "GenericTypes",
        "IncidentTypes",
        "Indicators",
        "Reports",
        "TestPlaybooks",
        "Triggers",
        "XDRCTemplates",
    ],
    "nist-ir": [
        "Classifiers",
        "CorrelationRules",
        "GenericDefinitions",
        "GenericModules",
        "GenericTypes",
        "IncidentTypes",
        "Indicators",
        "ModelingRules",
        "Reports",
        "Triggers",
        "XDRCTemplates",
    ],
}

# Directories we ensure exist after pruning (SDK may not create all of them)
DIRS_TO_CREATE = {
    "vendor": [
        "CorrelationRules",
        "ModelingRules",       # created but optional; remove if not needed
    ],
    "foundation": [
        "Automations",
        "Dashboards",
        "IncidentFields",
        "Integrations",
        "Layouts",
        "Lists",
        "Lookup",
        "Playbooks",
        "Scripts",
        "Widgets",
    ],
    "nist-ir": [
        "IncidentFields",
        "Layouts",
        "Playbooks",
        "Scripts",
        "TestPlaybooks",
    ],
}

# pack_metadata.json dependencies per pack type.
# Exact pack IDs as they appear in xsoar_config.json.
DEPENDENCIES = {
    "vendor": {
        "soc-optimization-unified": {},
        "soc-framework-nist-ir": {},
    },
    "foundation": {},
    "nist-ir": {
        "soc-optimization-unified": {},
    },
}

# Tags added to every SOC Framework pack (in addition to any passed in)
BASE_TAGS = ["SOC Framework"]

TAGS_BY_TYPE = {
    "vendor": ["Vendor Pack"],
    "foundation": ["Foundation"],
    "nist-ir": ["NIST IR", "Lifecycle"],
}

# xsoar_config.json release URL template
# URL uses the prerelease tag as a stub; bump_pack_version.py will
# rewrite it to the versioned tag on first release cut.
RELEASE_URL_TEMPLATE = (
    "https://github.com/{org}/{repo}/releases/download/"
    "prerelease/{pack_id}.zip"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(msg: str, dry_run: bool = False) -> None:
    prefix = "[DRY-RUN] " if dry_run else ""
    print(f"{prefix}{msg}")


def abort(msg: str) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)


def run_sdk_init(pack_name: str, packs_root: Path, dry_run: bool) -> Path:
    """Run demisto-sdk init --pack --xsiam and return the created pack path."""
    pack_path = packs_root / pack_name
    cmd = [
        "demisto-sdk", "init",
        "--pack",
        "--xsiam",
        "-n", pack_name,
        "-o", str(packs_root),
    ]
    log(f"Running: {' '.join(cmd)}", dry_run)
    if dry_run:
        return pack_path

    if pack_path.exists():
        abort(
            f"Pack directory already exists: {pack_path}\n"
            f"Delete it first or use --no-sdk to skip SDK init."
        )

    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        abort("demisto-sdk init failed. Check output above.")

    if not pack_path.exists():
        abort(
            f"demisto-sdk init reported success but {pack_path} was not created.\n"
            f"The SDK may have used a different output path."
        )
    return pack_path


def prune_directories(pack_path: Path, pack_type: str, dry_run: bool) -> None:
    """Remove SDK-generated directories the framework doesn't use."""
    to_prune = SDK_DIRS_TO_PRUNE.get(pack_type, [])
    for d in to_prune:
        target = pack_path / d
        if target.exists():
            log(f"  Removing {d}/", dry_run)
            if not dry_run:
                shutil.rmtree(target)


def create_directories(pack_path: Path, pack_type: str, dry_run: bool) -> None:
    """Create content subdirectories for the chosen pack type."""
    for d in DIRS_TO_CREATE.get(pack_type, []):
        target = pack_path / d
        if not target.exists():
            log(f"  Creating {d}/", dry_run)
            if not dry_run:
                target.mkdir(parents=True, exist_ok=True)

    # Place a .gitkeep in empty dirs so git tracks them
    if not dry_run:
        for d in DIRS_TO_CREATE.get(pack_type, []):
            target = pack_path / d
            gitkeep = target / ".gitkeep"
            if target.exists() and not any(target.iterdir()):
                gitkeep.touch()


def write_pack_metadata(
    pack_path: Path,
    pack_name: str,
    pack_type: str,
    description: str,
    category: str,
    github_org: str,
    repo: str,
    dry_run: bool,
) -> None:
    """Write a SOC Framework-compliant pack_metadata.json."""

    # Derive a human-readable display name from the pack dir name.
    # SocFrameworkZscalerZPA  →  SOC Framework - Zscaler ZPA
    # soc-framework-nist-ir-v4 →  SOC Framework - NIST IR V4
    display = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", pack_name)   # camelCase → spaces
    display = re.sub(r"[-_]+", " ", display)                    # hyphens/underscores → spaces
    display = display.strip()

    tags = list(dict.fromkeys(BASE_TAGS + TAGS_BY_TYPE.get(pack_type, [])))

    metadata = {
        "name": display,
        "id": pack_name,
        "description": description,
        "version": "1.0.0",
        "currentVersion": "1.0.0",
        "author": FRAMEWORK_AUTHOR,
        "support": FRAMEWORK_SUPPORT,
        "email": FRAMEWORK_EMAIL,
        "url": f"https://github.com/{github_org}/{repo}",
        "categories": [category],
        "tags": tags,
        "useCases": [],
        "keywords": [],
        "dependencies": DEPENDENCIES.get(pack_type, {}),
        "marketplaces": ["marketplacev2"],
    }

    meta_path = pack_path / "pack_metadata.json"
    log(f"  Writing pack_metadata.json", dry_run)
    if not dry_run:
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)
            f.write("\n")


def write_readme(pack_path: Path, pack_name: str, pack_type: str, dry_run: bool) -> None:
    """Write a minimal framework README.md stub."""
    readme_path = pack_path / "README.md"
    if readme_path.exists():
        log("  README.md exists, skipping stub", dry_run)
        return

    content = dedent(f"""\
        # {pack_name}

        SOC Framework — {pack_type.replace("-", " ").title()} Pack

        ## Overview

        <!-- Describe what this pack detects/responds to. -->

        ## Pack Contents

        <!-- List correlation rules, modeling rules, playbooks, etc. -->

        ## Dependencies

        - `soc-optimization-unified` — Foundation layer (Universal Command, lists, lookups)
        - `soc-framework-nist-ir` — NIST IR lifecycle playbooks

        ## Value Driver Alignment

        <!-- Which of VD1/VD2/VD3/VD4 does this pack serve, and which metric proves it? -->

        ## Shadow Mode

        All Containment, Eradication, and Recovery actions ship with `shadow_mode: true`.
        To go live: flip `shadow_mode` to `false` in `SOCFrameworkActions_V3` for each action.

        ## Version History

        | Version | Change |
        |---------|--------|
        | 1.0.0   | Initial release |
    """)

    log("  Writing README.md stub", dry_run)
    if not dry_run:
        readme_path.write_text(content)


def write_xsoar_config(
    pack_path: Path,
    pack_name: str,
    github_org: str,
    repo: str,
    dry_run: bool,
) -> None:
    """Write a per-pack xsoar_config.json into the pack root directory.

    Produces a fully-formed config file with:
      - custom_packs entry (correct id.zip format + system: yes)
      - pre_config_docs stub
      - post_config_docs stub
      - marketplace_packs stub
      - integration_instances stub (common Connect + Collect fields)

    Pack-specific values (id, urls, instance name) are derived from pack_name.
    All vendor-specific fields (brand, category, data params) are left as
    clearly-named placeholders for manual completion.
    """
    config_path = pack_path / "xsoar_config.json"

    if config_path.exists():
        log(f"  xsoar_config.json already exists — skipping", dry_run)
        return

    release_url = RELEASE_URL_TEMPLATE.format(
        org=github_org, repo=repo, pack_id=pack_name
    )

    credential_value = {
        "credential": "",
        "credentials": {
            "cacheVersn": 0,
            "id": "",
            "locked": False,
            "modified": "0001-01-01T00:00:00Z",
            "name": "",
            "sizeInBytes": 0,
            "user": "",
            "vaultInstanceId": "",
            "version": 0,
            "workgroup": "",
        },
        "identifier": "",
        "passwordChanged": False,
    }

    configuration_block = {
        "id": "",
        "version": 0,
        "cacheVersn": 0,
        "modified": "0001-01-01T00:00:00Z",
        "sizeInBytes": 0,
        "packID": "",
        "packName": "",
        "itemVersion": "",
        "fromServerVersion": "",
        "toServerVersion": "",
        "definitionId": "",
        "isOverridable": False,
        "vcShouldIgnore": False,
        "vcShouldKeepItemLegacyProdMachine": False,
        "commitMessage": "",
        "shouldCommit": False,
        "name": "",
        "prevName": "",
        "display": "",
        "brand": "",
        "category": "",
        "icon": "",
        "description": "",
        "configuration": None,
        "integrationScript": None,
        "hidden": False,
        "canGetSamples": False,
    }

    config = {
        "custom_packs": [
            {
                "id": f"{pack_name}.zip",
                "url": release_url,
                "system": "yes",
            }
        ],
        "pre_config_docs": [
            {
                "name": f"{pack_name} - Pre-Config Steps",
                "url": f"https://github.com/{github_org}/{repo}/blob/main/Packs/{pack_name}/PRE_CONFIG_README.md",
            }
        ],
        "post_config_docs": [
            {
                "name": f"{pack_name} - Manual Steps",
                "url": f"https://github.com/{github_org}/{repo}/blob/main/Packs/{pack_name}/POST_CONFIG_README.md",
            }
        ],
        "marketplace_packs": [
            {
                "id": "MarketplacePackId",
                "version": "latest",
            }
        ],
        "integration_instances": [
            {
                "version": 1,
                "propagationLabels": ["all"],
                "isOverridable": False,
                "enabled": "true",
                "name": f"{pack_name}_instance_1",
                "brand": "Integration Brand Name",
                "category": "Category",
                "engine": "",
                "engineGroup": "",
                "isIntegrationScript": True,
                "mappingId": "",
                "outgoingMapperId": "",
                "incomingMapperId": "",
                "canSample": True,
                "defaultIgnore": False,
                "integrationLogLevel": "",
                "skipItemsBefore": "0001-01-01T00:00:00Z",
                "cloudIntegrationInfo": {},
                "configuration": configuration_block,
                "data": [
                    {
                        "section": "Connect",
                        "display": "Server URL",
                        "displayPassword": "",
                        "name": "url",
                        "defaultValue": "https://",
                        "type": 0,
                        "required": True,
                        "hidden": False,
                        "hiddenUsername": False,
                        "hiddenPassword": False,
                        "options": None,
                        "info": "",
                        "hasvalue": True,
                        "value": "https://",
                    },
                    {
                        "section": "Connect",
                        "display": "",
                        "displayPassword": "API Key",
                        "name": "apikey",
                        "defaultValue": "",
                        "type": 9,
                        "required": True,
                        "hidden": False,
                        "hiddenUsername": True,
                        "hiddenPassword": False,
                        "options": None,
                        "info": "",
                        "hasvalue": True,
                        "value": credential_value,
                    },
                    {
                        "section": "Connect",
                        "display": "Use system proxy settings",
                        "displayPassword": "",
                        "name": "proxy",
                        "defaultValue": "false",
                        "type": 8,
                        "required": False,
                        "hidden": False,
                        "hiddenUsername": False,
                        "hiddenPassword": False,
                        "options": None,
                        "info": "",
                        "hasvalue": True,
                        "value": False,
                    },
                    {
                        "section": "Connect",
                        "display": "Trust any certificate (not secure)",
                        "displayPassword": "",
                        "name": "insecure",
                        "defaultValue": "false",
                        "type": 8,
                        "required": False,
                        "hidden": False,
                        "hiddenUsername": False,
                        "hiddenPassword": False,
                        "options": None,
                        "info": "",
                        "hasvalue": True,
                        "value": False,
                    },
                    {
                        "section": "Collect",
                        "display": "Fetch incidents",
                        "displayPassword": "",
                        "name": "isFetch",
                        "defaultValue": "",
                        "type": 8,
                        "required": False,
                        "hidden": False,
                        "hiddenUsername": False,
                        "hiddenPassword": False,
                        "options": None,
                        "info": "",
                        "hasvalue": True,
                        "value": True,
                    },
                    {
                        "section": "Collect",
                        "display": "Incidents Fetch Interval",
                        "displayPassword": "",
                        "name": "incidentFetchInterval",
                        "defaultValue": "5",
                        "type": 19,
                        "required": False,
                        "hidden": False,
                        "hiddenUsername": False,
                        "hiddenPassword": False,
                        "options": None,
                        "info": "",
                        "hasvalue": True,
                        "value": "5",
                    },
                    {
                        "section": "Collect",
                        "display": "Max Incidents",
                        "displayPassword": "",
                        "name": "max_fetch",
                        "defaultValue": "50",
                        "type": 0,
                        "required": False,
                        "hidden": False,
                        "hiddenUsername": False,
                        "hiddenPassword": False,
                        "options": None,
                        "info": "",
                        "hasvalue": True,
                        "value": "50",
                    },
                    {
                        "section": "Collect",
                        "display": "Sync On First Run (days)",
                        "displayPassword": "",
                        "name": "first_fetch",
                        "defaultValue": "30",
                        "type": 0,
                        "required": False,
                        "hidden": False,
                        "hiddenUsername": False,
                        "hiddenPassword": False,
                        "options": None,
                        "info": "",
                        "hasvalue": True,
                        "value": "30",
                    },
                ],
                "passwordProtected": False,
            }
        ],
    }

    log(f"  Writing xsoar_config.json → {config_path}", dry_run)
    if not dry_run:
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
            f.write("\n")


def print_next_steps(
    pack_path: Path,
    pack_name: str,
    pack_type: str,
    dry_run: bool,
) -> None:
    """Print the post-init checklist."""
    checklist = dedent(f"""
        ╔══════════════════════════════════════════════════════════╗
        ║  SOC Framework Pack Initialized: {pack_name:<24}║
        ╚══════════════════════════════════════════════════════════╝

        Pack path:  {pack_path}
        Pack type:  {pack_type}

        ── REQUIRED BEFORE FIRST UPLOAD ───────────────────────────

        [ ] Edit pack_metadata.json
              - Set a meaningful description
              - Set useCases and keywords
              - Set correct categories (Network Security / Endpoint /
                Email / Identity — pick what matches the vendor)
              - DO NOT touch version/currentVersion — bump manually
                when you're ready to cut a release

        [ ] Write your content
              - Vendor pack: drop correlation rule YAML into CorrelationRules/
              - Modeling rule: CorrelationRules/ + matching _schema.json
              - Playbooks: Playbooks/ (nist-ir type only)

        ── CORRELATION RULE CHECKLIST (vendor packs) ──────────────

        [ ] fromversion: 6.10.0         (NOT 8.0.0 — causes HTTP 500)
        [ ] rule_id: 0                  (required — removal breaks SDK id resolution)
        [ ] alert_category: User Defined (NOT OTHER — causes 101704)
        [ ] All optional fields explicitly null (alert_type, crontab,
            search_window, simple_schedule, timezone)
        [ ] description: populated string (not empty)
        [ ] investigation_query_link: populated (not empty string)
        [ ] mitre_defs: populated map (not empty dict)
        [ ] user_defined_category: present and set

        ── VALIDATION & UPLOAD ─────────────────────────────────────

        [ ] python3 tools/pack_prep.py --pack {pack_name}
        [ ] python3 tools/fix_errors.py --pack {pack_name}   # if errors found
        [ ] bash upload_package.sh {pack_name}
        [ ] python3 tools/bump_pack_version.py --pack {pack_name}  # triggers CI

        ── CI / BRANCHING ──────────────────────────────────────────

        [ ] Open branch: git checkout -b pack/{pack_name.lower().replace("_", "-")}
        [ ] One commit = one reversible decision (git add -p)
        [ ] PR target: main

        ── XSOAR CONFIG ────────────────────────────────────────────

        [ ] Edit xsoar_config.json in pack root
              - Set brand, category, and instance name
              - Fill in integration data[] params for your vendor
              - Remove marketplace_packs entry if vendor pack is
                not on the XSIAM marketplace
              - Remove pre_config_docs if no pre-install steps needed
        [ ] After first GitHub release, bump_pack_version.py will
            auto-correct the custom_packs URL to the versioned tag

        ── VALUE DRIVER SIGN-OFF ───────────────────────────────────

        Before merging, answer in the PR description:
          1. Which SOC Challenge does this pack solve?
          2. Which Value Driver (VD1/VD2/VD3/VD4)?
          3. Which metric in the Value Metrics Dashboard proves it?

    """)
    print(checklist)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SOC Framework pack initializer wrapping demisto-sdk init.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--name", "-n", required=True,
        help="Pack directory name / ID (e.g. SocFrameworkZscalerZPA)",
    )
    parser.add_argument(
        "--type", "-t", dest="pack_type",
        choices=["vendor", "foundation", "nist-ir"],
        default="vendor",
        help="Pack type. Default: vendor",
    )
    parser.add_argument(
        "--desc", "-d", default="",
        help="Pack description (written into pack_metadata.json).",
    )
    parser.add_argument(
        "--category", "-c", default=None,
        help="Marketplace category. Defaults per pack type if omitted.",
    )
    parser.add_argument(
        "--no-sdk", action="store_true",
        help="Skip demisto-sdk init; only write framework files.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would happen without writing anything.",
    )
    parser.add_argument(
        "--packs-root", default="Packs",
        help="Path to the Packs/ directory. Default: Packs/",
    )
    parser.add_argument(
        "--github-org", default=GITHUB_ORG_DEFAULT,
        help=f"GitHub org for release URL. Default: {GITHUB_ORG_DEFAULT}",
    )
    parser.add_argument(
        "--repo", default=REPO_DEFAULT,
        help=f"GitHub repo name. Default: {REPO_DEFAULT}",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    pack_name = args.name
    pack_type = args.pack_type
    dry_run = args.dry_run
    packs_root = Path(args.packs_root)
    category = args.category or CATEGORY_DEFAULTS[pack_type]
    description = args.desc or f"SOC Framework {pack_type} pack: {pack_name}"

    # ── Validation ──────────────────────────────────────────────────────────
    if not re.match(r"^[A-Za-z][A-Za-z0-9_-]+$", pack_name):
        abort(
            f"Pack name '{pack_name}' is invalid.\n"
            f"Must start with a letter and contain only letters, digits, _ or -."
        )

    if not packs_root.exists() and not dry_run:
        abort(f"Packs root not found: {packs_root}\nRun from the repo root.")

    pack_path = packs_root / pack_name

    log(f"\n{'='*60}")
    log(f"  SOC Framework Pack Init")
    log(f"  name:     {pack_name}")
    log(f"  type:     {pack_type}")
    log(f"  category: {category}")
    log(f"  output:   {pack_path}")
    if dry_run:
        log("  mode:     DRY RUN — nothing will be written")
    log(f"{'='*60}\n")

    # ── Step 1: demisto-sdk init ─────────────────────────────────────────────
    if args.no_sdk:
        log("Step 1: Skipping demisto-sdk init (--no-sdk)")
        if not dry_run and not pack_path.exists():
            pack_path.mkdir(parents=True)
            log(f"  Created {pack_path}")
    else:
        log("Step 1: Running demisto-sdk init --pack --xsiam")
        run_sdk_init(pack_name, packs_root, dry_run)

    # ── Step 2: Prune SDK-generated directories ──────────────────────────────
    log(f"\nStep 2: Pruning directories not used by {pack_type} packs")
    prune_directories(pack_path, pack_type, dry_run)

    # ── Step 3: Create framework directories ────────────────────────────────
    log(f"\nStep 3: Creating {pack_type} content directories")
    create_directories(pack_path, pack_type, dry_run)

    # ── Step 4: Write pack_metadata.json ────────────────────────────────────
    log("\nStep 4: Writing pack_metadata.json")
    write_pack_metadata(
        pack_path, pack_name, pack_type, description,
        category, args.github_org, args.repo, dry_run,
    )

    # ── Step 5: Write README stub ───────────────────────────────────────────
    log("\nStep 5: Writing README.md stub")
    write_readme(pack_path, pack_name, pack_type, dry_run)

    # ── Step 6: Write xsoar_config.json ─────────────────────────────────────
    log("\nStep 6: Writing xsoar_config.json")
    write_xsoar_config(pack_path, pack_name, args.github_org, args.repo, dry_run)

    # ── Done ────────────────────────────────────────────────────────────────
    print_next_steps(pack_path, pack_name, pack_type, dry_run)


if __name__ == "__main__":
    main()
