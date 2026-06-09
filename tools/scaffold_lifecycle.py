#!/usr/bin/env python3
"""
scaffold_lifecycle.py — Stamp a new SOC Framework lifecycle pack.

Composes with `generate_soc_framework_content.py`:
  - This tool stamps the pack skeleton, four schema templates, EP stub, and
    phase playbook stubs.
  - The human authors schema content + phase playbook content.
  - `generate_soc_framework_content.py emit` materializes lists from the
    filled-in schemas.

Generated artifacts (all Tier 4 per docs/architecture/cross-lifecycle-surfaces.md):
  - Packs/soc-framework-<id>/pack_metadata.json
  - Packs/soc-framework-<id>/xsoar_config.json (with System XQL HTTP Collector
    instance for the lifecycle's dataset)
  - Packs/soc-framework-<id>/ReleaseNotes/1_0_0.md
  - Packs/soc-framework-<id>/Lists/<schema-name>/  (empty subdirs — populated
    by emit)
  - Packs/soc-framework-<id>/Layouts/             (empty)
  - Packs/soc-framework-<id>/Dashboards/          (empty)
  - Packs/soc-framework-<id>/Playbooks/EP_<Lifecycle>_V3.yml
  - Packs/soc-framework-<id>/Playbooks/SOC_<Phase>_V3.yml × N
  - schemas/soc-framework/soc-framework-<id>/SOCFrameworkNormalizeMap_<ID>.yaml
  - schemas/soc-framework/soc-framework-<id>/SOCFrameworkEnrichmentMap_<ID>.yaml
  - schemas/soc-framework/soc-framework-<id>/SOCFrameworkDedupContract_<ID>.yaml
  - schemas/soc-framework/soc-framework-<id>/SOCFrameworkPhaseContract_<ID>.yaml
  - docs/<id>/overview.md

Usage:
  python3 tools/scaffold_lifecycle.py \\
      --lifecycle-id posture \\
      --lifecycle-name "Posture" \\
      --phases "Identify,Plan,Execute,Verify" \\
      --description "Cloud posture / attack-surface management lifecycle (NIST SP 800-40 Rev 4)"

  # Dry run — print what would be created, don't write:
  python3 tools/scaffold_lifecycle.py --lifecycle-id posture --lifecycle-name "Posture" \\
      --phases "Identify,Plan,Execute,Verify" --dry-run
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from pathlib import Path
from textwrap import dedent

REPO_ROOT_MARKERS = ("Packs", "schemas", "tools")


# ---------------------------------------------------------------------------
# Repo discovery
# ---------------------------------------------------------------------------

def find_repo_root(start: Path) -> Path:
    """Walk up from `start` until we find a dir containing all REPO_ROOT_MARKERS."""
    cur = start.resolve()
    while cur != cur.parent:
        if all((cur / m).is_dir() for m in REPO_ROOT_MARKERS):
            return cur
        cur = cur.parent
    raise SystemExit(
        f"Could not locate repo root from {start}. "
        f"Expected to find {REPO_ROOT_MARKERS} alongside each other."
    )


# ---------------------------------------------------------------------------
# Argument parsing + validation
# ---------------------------------------------------------------------------

LIFECYCLE_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")
LIFECYCLE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 ]*[A-Za-z0-9]$|^[A-Za-z]$")
PHASE_NAME_RE = re.compile(r"^[A-Z][A-Za-z0-9_ ]*$")
DESCRIPTION_BAD_CHARS_RE = re.compile(r'[\x00-\x1f\x7f"\\]')  # control chars, raw quote, backslash

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Stamp a new SOC Framework lifecycle pack skeleton.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--lifecycle-id",
        required=True,
        help="snake_case id (e.g., 'posture', 'nist_ir', 'vuln_mgmt'). Used in "
             "schema names, dataset name, System XQL HTTP Collector instance name.",
    )
    p.add_argument(
        "--lifecycle-name",
        required=True,
        help="Human-readable display name (e.g., 'Posture', 'NIST IR'). Used in "
             "playbook display names and docs.",
    )
    p.add_argument(
        "--phases",
        required=True,
        help="Comma-separated phase names in order (e.g., "
             "'Identify,Plan,Execute,Verify' for posture; "
             "'Containment,Eradication,Recovery' for IR). Used to stamp one "
             "phase playbook stub per phase.",
    )
    p.add_argument(
        "--categories",
        required=True,
        help="Comma-separated product categories in scope (e.g., "
             "'posture_misconfig,posture_compliance,posture_drift' for posture; "
             "'Endpoint,Email,Identity,Network,Cloud,Generic' for NIST IR). "
             "One Workflow leaf playbook is generated per (phase x category), "
             "and the phase router branches on SOCFramework.Product.category.",
    )
    p.add_argument(
        "--action-phases",
        default="",
        help="Comma-separated subset of --phases whose Workflow leaves call "
             "SOCCommandWrapper (Universal Command, shadow default) rather than "
             "Set-based decision stubs. e.g. 'Execute,Verify' for posture, "
             "'Containment,Eradication,Recovery' for NIST IR. Phases not listed "
             "here get Set-based discovery/decision leaves.",
    )
    p.add_argument(
        "--description",
        default="",
        help="One-line lifecycle description (used in pack_metadata + docs).",
    )
    p.add_argument(
        "--author",
        default="Palo Alto Networks Cortex",
        help="Pack author. Default: 'Palo Alto Networks Cortex'.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be created without writing any files.",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing files. Default: skip files that already exist.",
    )
    return p.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if not LIFECYCLE_ID_RE.match(args.lifecycle_id):
        raise SystemExit(
            f"Invalid --lifecycle-id '{args.lifecycle_id}'. "
            "Must be snake_case starting with a lowercase letter, "
            "containing only [a-z0-9_]. "
            "Used in dataset name, instance name, file paths — must be safe."
        )
    name = args.lifecycle_name.strip()
    if not name:
        raise SystemExit("--lifecycle-name cannot be empty.")
    if not LIFECYCLE_NAME_RE.match(name):
        raise SystemExit(
            f"Invalid --lifecycle-name '{args.lifecycle_name}'. "
            "Must start with a letter, end with a letter or digit, and contain "
            "only letters, digits, and single spaces in between. "
            "No punctuation, no symbols (becomes part of playbook IDs)."
        )
    if "  " in name:
        raise SystemExit(
            f"Invalid --lifecycle-name '{args.lifecycle_name}'. "
            "Consecutive spaces are not allowed."
        )
    args.lifecycle_name = name  # store the trimmed version

    phases = [p.strip() for p in args.phases.split(",") if p.strip()]
    if not phases:
        raise SystemExit("--phases must contain at least one phase.")
    for ph in phases:
        if not PHASE_NAME_RE.match(ph):
            raise SystemExit(
                f"Invalid phase name '{ph}'. Phase names must start with an "
                "uppercase letter and contain only letters, digits, "
                "underscores, or spaces."
            )
        if "  " in ph:
            raise SystemExit(f"Phase name '{ph}' contains consecutive spaces.")

    if DESCRIPTION_BAD_CHARS_RE.search(args.description):
        raise SystemExit(
            "--description contains control characters, raw quotes, or "
            "backslashes that would break JSON/YAML output. Remove them."
        )
    if DESCRIPTION_BAD_CHARS_RE.search(args.author):
        raise SystemExit(
            "--author contains control characters, raw quotes, or backslashes. "
            "Remove them."
        )

    # Annotate for downstream
    args._phases = phases  # list[str], cleaned

    # Categories — used for per-category Workflow leaves + router branches.
    cats = [c.strip() for c in args.categories.split(",") if c.strip()]
    if not cats:
        raise SystemExit("--categories must contain at least one category.")
    CAT_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
    for c in cats:
        if not CAT_TOKEN_RE.match(c):
            raise SystemExit(
                f"Invalid category '{c}'. Categories must start with a letter "
                "and contain only letters, digits, and underscores (they become "
                "playbook-name segments and routing condition values)."
            )
    args._categories = cats

    # Action phases — subset of phases whose leaves call SOCCommandWrapper.
    action_phases = [p.strip() for p in args.action_phases.split(",") if p.strip()]
    bad = [ap for ap in action_phases if ap not in phases]
    if bad:
        raise SystemExit(
            f"--action-phases entries not found in --phases: {bad}. "
            f"Phases are: {phases}"
        )
    args._action_phases = action_phases

    args._lifecycle_pack_id = args.lifecycle_id.replace("_", "-")
    args._LIFECYCLE = args.lifecycle_id.upper()


# ---------------------------------------------------------------------------
# Derived names (single source of truth for all naming conventions)
# ---------------------------------------------------------------------------

def derive_names(args: argparse.Namespace) -> dict:
    lid = args.lifecycle_id              # snake_case  e.g. "posture"
    pid = args._lifecycle_pack_id        # kebab-case  e.g. "posture"
    LID = args._LIFECYCLE                # UPPER       e.g. "POSTURE"
    Lname = args.lifecycle_name          # display     e.g. "Posture"
    return {
        "lifecycle_id": lid,
        "LIFECYCLE": LID,
        "lifecycle_name": Lname,
        "pack_name": f"soc-framework-{pid}",
        "pack_display": f"SOC Framework {Lname} Lifecycle",
        "dataset": f"xsiam_socfw_{lid}_execution_raw",
        "http_collector_instance": f"socfw_{lid}_execution",
        "ep_playbook": f"EP_{Lname.replace(' ', '_')}",
        "lifecycle_controller": f"SOC_{Lname.replace(' ', '_')}",
        "schemas": {
            "NormalizeMap":   f"SOCFrameworkNormalizeMap_{LID}",
            "EnrichmentMap":  f"SOCFrameworkEnrichmentMap_{LID}",
            "DedupContract":  f"SOCFrameworkDedupContract_{LID}",
            "PhaseContract":  f"SOCFrameworkPhaseContract_{LID}",
        },
        "execution_list": f"SOCExecutionList_{LID}",
        # Per-category label used in Workflow leaf names: SOC_{Label}_{Phase}.
        # posture_misconfig -> Misconfig ; Endpoint -> Endpoint.
        "category_label": {
            c: "".join(part.capitalize() for part in c.split("_")[1:]) or c.capitalize()
            if "_" in c else c
            for c in args._categories
        },
    }


# ---------------------------------------------------------------------------
# File-writing utility (dry-run aware, force-aware)
# ---------------------------------------------------------------------------

class Writer:
    def __init__(self, dry_run: bool, force: bool):
        self.dry_run = dry_run
        self.force = force
        self.created: list[Path] = []
        self.skipped: list[Path] = []

    def write(self, path: Path, content: str) -> None:
        if path.exists() and not self.force:
            self.skipped.append(path)
            return
        if self.dry_run:
            self.created.append(path)
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        self.created.append(path)

    def mkdir(self, path: Path) -> None:
        if path.exists():
            self.skipped.append(path)
            return
        if self.dry_run:
            self.created.append(path)
            return
        path.mkdir(parents=True, exist_ok=True)
        self.created.append(path)


# ---------------------------------------------------------------------------
# Template content
# ---------------------------------------------------------------------------

def tpl_pack_metadata(n: dict, args: argparse.Namespace) -> str:
    today = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    desc = args.description or (
        f"{n['lifecycle_name']} lifecycle for the SOC Framework. "
        "See docs/<id>/overview.md."
    )
    obj = {
        "id": n["pack_name"],
        "name": n["pack_display"],
        "description": desc,
        "support": "internal",
        "currentVersion": "1.0.0",
        "author": args.author,
        "url": "",
        "email": "",
        "created": today,
        "categories": ["Utilities"],
        "tags": [],
        "useCases": [],
        "keywords": ["soc-framework", n["lifecycle_id"]],
        "marketplaces": ["marketplacev2"],
        "supportedModules": ["agent", "X1", "X3", "X5"],
        # No declared dependencies. Lifecycle packs are independent — install
        # soc-optimization-unified separately if needed. (NIST IR happens to
        # bundle alongside soc-opt at install time, but that's an operational
        # choice, not a declared dependency.) If a future lifecycle has a real
        # hard dep, add it manually here.
    }
    return json.dumps(obj, indent=4) + "\n"


def tpl_xsoar_config(n: dict) -> str:
    """xsoar_config.json — mirrors the actual soc-optimization-unified shape.

    Key facts learned from the real file:
      - Top-level key for instances is `integration_instances`, not `instances`.
      - The brand is **System XQL HTTP Collector** — NOT the generic
        "HTTP Collector" integration (which requires API keys). The System
        XQL HTTP Collector is XSIAM-internal and keyless.
      - System XQL HTTP Collector instance has NO URL field — XSIAM
        server-provisions the URL when the instance is created.
      - The instance has NO dataset_name field — XSIAM derives the dataset
        from the convention `<vendor>_<product>_raw` (lowercased).
        For us: vendor=XSIAM, product=socfw_<lifecycle>_execution → dataset
        xsiam_socfw_<lifecycle>_execution_raw, automatically.
      - The instance ships with a fully-populated `configuration` block of
        XSIAM machinery defaults (empty IDs, version 0, etc.) — left as-is.
      - `data` carries the actual user-facing config (product + vendor here).

    custom_packs catch-22 (per design discussion 2026-05-28):
      - The lifecycle pack's xsoar_config must include its own self-ref so
        the bundle installer can deploy it. The URL points to v1.0.0 even
        though that release doesn't exist until AFTER the first PR merges
        and CI tags it.
      - On first publish: URL 404s during preflight; resolves after CI tags.
      - On subsequent versions: stale by one cycle, fix with tiny follow-up
        PR (same pattern as cross-pack refs).

    The lifecycle pack's xsoar_config provisions one System XQL HTTP Collector
    instance for the lifecycle's execution dataset. PlaybookMetrics is NOT
    included (per memory rule: xsiam_playbookmetrics_raw is out of scope)."""

    # XSIAM machinery defaults — copy of the empty-defaults block from real file
    _config_defaults = {
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

    # custom_packs self-reference at v1.0.0. Will 404 on first PR's preflight;
    # CI publishes the release on merge and the URL becomes valid.
    self_pack_id = f"{n['pack_name']}.zip"
    self_pack_url = (
        f"https://github.com/Palo-Cortex/secops-framework/releases/download/"
        f"{n['pack_name']}-v1.0.0/{n['pack_name']}-v1.0.0.zip"
    )

    obj = {
        "post_config_docs": [
            {
                "name": f"{n['pack_display']} - Manual Steps",
                "url": (
                    f"https://github.com/Palo-Cortex/secops-framework/blob/main/"
                    f"Packs/{n['pack_name']}/POST_CONFIG_README.md"
                ),
            }
        ],
        # custom_packs: self-reference only. Lifecycle packs are independent
        # by default — no soc-optimization-unified cross-ref. Add cross-pack
        # entries manually here if a specific lifecycle genuinely needs them.
        "custom_packs": [
            {
                "id": self_pack_id,
                "url": self_pack_url,
                "system": "yes",
            },
        ],
        # EP playbook is the user-facing export from the lifecycle pack.
        "exported_playbooks": [n["ep_playbook"]],
        # Lifecycle packs inherit marketplace deps from soc-optimization-unified.
        # Add lifecycle-specific marketplace pack deps here if/when needed.
        "marketplace_packs": [],
        # No lookup datasets for new lifecycles by default (value_tags is deprecated).
        "lookup_datasets": [],
        "integration_instances": [
            {
                "version": 1,
                "propagationLabels": ["all"],
                "isOverridable": False,
                "enabled": "true",
                "name": n["http_collector_instance"],
                "brand": "System XQL HTTP Collector",
                "category": "Utilities",
                "engine": "",
                "engineGroup": "",
                "isIntegrationScript": True,
                "mappingId": "",
                "outgoingMapperId": "",
                "incomingMapperId": "",
                "canSample": False,
                "defaultIgnore": False,
                "integrationLogLevel": "",
                "configuration": _config_defaults,
                "data": [
                    {
                        "display": "Product Name",
                        "displayPassword": "",
                        "name": "product",
                        "defaultValue": n["http_collector_instance"],
                        "type": 0,
                        "required": False,
                        "hidden": False,
                        "hiddenUsername": False,
                        "hiddenPassword": False,
                        "options": None,
                        "info": "The name of the 'Product' to include in the event data",
                        "hasvalue": True,
                        "value": n["http_collector_instance"],
                    },
                    {
                        "display": "vendor name",
                        "displayPassword": "",
                        "name": "vendor",
                        "defaultValue": "XSIAM",
                        "type": 0,
                        "required": False,
                        "hidden": False,
                        "hiddenUsername": False,
                        "hiddenPassword": False,
                        "options": None,
                        "info": "The name of the 'Vendor' to include in the event data",
                        "hasvalue": True,
                        "value": "XSIAM",
                    },
                ],
                "passwordProtected": False,
            }
        ],
        # No scheduled jobs by default. Lifecycle-specific JOB playbooks (e.g., a
        # lifecycle-specific Auto Triage) get added here when authored.
        "jobs": [],
    }
    return json.dumps(obj, indent=2) + "\n"


def tpl_release_notes(n: dict, args: argparse.Namespace) -> str:
    return dedent(f"""\
        #### {n['pack_display']}

        ##### New

        - First release. Scaffolded by `tools/scaffold_lifecycle.py`.
        - Includes empty schema templates for NormalizeMap, EnrichmentMap,
          DedupContract, PhaseContract — human authors content before running
          `tools/generate_soc_framework_content.py emit`.
        - EP playbook stub: `{n['ep_playbook']}`.
        - Phase playbook stubs: {", ".join(f"`SOC_{p.replace(' ', '_')}`" for p in args._phases)}.
        - System XQL HTTP Collector instance config in xsoar_config.json:
          `{n['http_collector_instance']}` → auto-derived dataset
          `{n['dataset']}`.
        """)


def tpl_normalize_schema(n: dict) -> str:
    return dedent(f"""\
        # SOCFrameworkNormalizeMap — {n['lifecycle_name']}
        # Per-lifecycle normalize contract. Engine: SOCNormalizeFromList (lifecycle-agnostic).
        # Drives: raw issue fields → SOCFramework.<Category>.* (flat) and
        #         SOCFramework.Artifacts.<Domain>.* (structured, via mirrors).
        #
        # FILL IN: one section per product category. NIST IR ships endpoint, email,
        # identity, network, cloud, generic. Posture will ship posture_patch,
        # posture_vuln, posture_exposure, generic (per cross-lifecycle-surfaces.md
        # Tier 3 SOCProductCategoryMap_V3 decision).
        #
        # After authoring, run:
        #   python3 tools/generate_soc_framework_content.py emit \\
        #       --pack {n['pack_name']} --list {n['schemas']['NormalizeMap']}

        lifecycle: {n['lifecycle_id']}
        pack: {n['pack_name']}
        list_name: {n['schemas']['NormalizeMap']}
        description: |
          Normalize contract for the {n['lifecycle_name']} lifecycle.

        validation:
          required_blocks: [categories]
          blocks:
            categories:
              item_required: [mappings, stamps, mirrors]

        emit:
          group_by: categories

        categories:
          # TODO: add one section per category in scope for this lifecycle.
          # Example shape (per skill section "NORMALIZE MAP — PER-LIFECYCLE SHAPE V3"):
          #
          # endpoint:
          #   mappings:
          #     - target: Endpoint.hostname
          #       issue_field: hostname
          #       shape: flat
          #       role: canonical
          #       source_origin: native
          #   stamps:
          #     - target: Endpoint.normalization_source
          #       value: endpoint
          #   mirrors:
          #     - target: Artifacts.Endpoint.Hostname
          #       source: Endpoint.hostname
          #       role: canonical
          #       shape: structured
          generic:
            mappings: []
            stamps: []
            mirrors: []
        """)


def tpl_enrichment_schema(n: dict) -> str:
    return dedent(f"""\
        # SOCFrameworkEnrichmentMap — {n['lifecycle_name']}
        # Per-lifecycle enrichment contract. Engine: SOCEnrichFromList (lifecycle-agnostic).
        # Drives: SOCFramework.Artifacts.* paths → reputation lookups via the
        # four built-in lanes (ip, file, domain, url).
        #
        # FILL IN: lane keys map to built-in reputation commands of the same name.
        # Each lane lists the Artifacts.* paths to feed into that lookup.
        # Lanes you don't need can be left empty.

        lifecycle: {n['lifecycle_id']}
        pack: {n['pack_name']}
        list_name: {n['schemas']['EnrichmentMap']}
        description: |
          Enrichment contract for the {n['lifecycle_name']} lifecycle.

        validation:
          required_blocks: [lanes]
          blocks:
            lanes:
              item_required: []  # empty list = lane key with no paths is valid

        emit:
          group_by: lanes

        lanes:
          ip: []
            # - source: Artifacts.Network.IP
            # - source: Artifacts.Source.IP
          file: []
            # - source: Artifacts.Process.SHA256
            # - source: Artifacts.Target.SHA256
          domain: []
            # - source: Artifacts.Endpoint.Domain
          url: []
            # - source: Artifacts.Email.ThreatURL
        """)


def tpl_dedup_schema(n: dict) -> str:
    return dedent(f"""\
        # SOCFrameworkDedupContract — {n['lifecycle_name']}
        # Per-lifecycle dedup contract. Engine: SOCDedupFromList (TO BUILD).
        # Drives: which artifact paths key uniqueness, time window, action on duplicate.
        #
        # See docs/architecture/cross-lifecycle-surfaces.md V2.
        #
        # Examples:
        #   NIST IR : hostname + signal type + MITRE technique, window=hours
        #   Posture : asset ID + finding ID,                    window=long-or-absent
        #   VM      : asset ID + CVE,                           window=long

        lifecycle: {n['lifecycle_id']}
        pack: {n['pack_name']}
        list_name: {n['schemas']['DedupContract']}
        description: |
          Dedup contract for the {n['lifecycle_name']} lifecycle.

        validation:
          required_blocks: [dedup]
          blocks:
            dedup:
              item_required: [key_fields, time_window, duplicate_action]

        emit:
          group_by: dedup

        dedup:
          key_fields: []
            # - source: Artifacts.<Domain>.<Field>
          time_window:
            value: 0           # 0 = no window; use null if windowing is N/A
            unit: hours        # hours | minutes | days | null
          duplicate_action: link_as_child   # link_as_child | suppress | merge | count
        """)


def tpl_phase_schema(n: dict, args: argparse.Namespace) -> str:
    """Build the PhaseContract template line by line so phase indentation is
    consistent. Earlier dedent + pre-built block approach produced broken YAML."""
    lines = [
        f"# SOCFrameworkPhaseContract — {n['lifecycle_name']}",
        "# Per-lifecycle phase contract. Consumed by the phase routers' outputs",
        "# block and (if used) a lifecycle phase-init script. Declares what each",
        "# phase writes and reads.",
        "#",
        "# FILL IN: one section per phase, declaring what the phase writes and",
        "# what it reads from upstream phases. Schema enables test-harness modes",
        "# (synthesize-upstream + post-condition assertions).",
        "",
        f"lifecycle: {n['lifecycle_id']}",
        f"pack: {n['pack_name']}",
        f"list_name: {n['schemas']['PhaseContract']}",
        "description: |",
        f"  Phase contract for the {n['lifecycle_name']} lifecycle.",
        "",
        "validation:",
        "  required_blocks: [phases]",
        "  blocks:",
        "    phases:",
        "      item_required: [writes, writes_by_category, reads_from_phases]",
        "",
        "emit:",
        "  group_by: phases",
        "",
        "phases:",
    ]
    for ph in args._phases:
        ph_key = ph.lower().replace(" ", "_")
        lines.extend([
            f"  {ph_key}:",
            "    writes: []",
            f"      # - target: {ph}.<field>",
            '      #   init: ""',
            "    writes_by_category: {}",
            "    reads_from_phases: []",
        ])
    return "\n".join(lines) + "\n"


def tpl_ep_playbook(n: dict, args: argparse.Namespace) -> str:
    """EP stub. CRITICAL: first task stamps SOCFramework.lifecycle (V4).
    The dataset is derived by SOCCommandWrapper from this stamp (V1).
    Phase dispatch is left as a stub for the human."""
    return dedent(f"""\
        # {n['ep_playbook']}
        # Entry Point playbook for the {n['lifecycle_name']} lifecycle.
        # Scaffolded by tools/scaffold_lifecycle.py.
        #
        # CONTRACT (do not remove):
        #   Task '1' MUST stamp SOCFramework.lifecycle as the very first thing.
        #   Every framework engine (SOCNormalizeFromList, SOCEnrichFromList,
        #   SOCDedupFromList, SOCCommandWrapper) reads this key to resolve
        #   the lifecycle's schemas, dataset, and System XQL HTTP Collector instance.
        #   See docs/architecture/cross-lifecycle-surfaces.md V4.

        adopted: true
        id: {n['ep_playbook']}
        version: -1
        contentitemexportablefields:
          contentitemfields:
            packID: {n['pack_name']}
            packName: {n['pack_display']}
            itemVersion: 1.0.0
            fromServerVersion: 5.0.0
            toServerVersion: ""
            definitionid: ""
            prevname: ""
            isoverridable: false
            supportedModules: []
        name: {n['ep_playbook']}
        description: |
          Entry Point for the {n['lifecycle_name']} lifecycle. Stamps lifecycle
          context, runs Foundation playbooks, dispatches to the lifecycle controller.
        starttaskid: "0"
        tasks:
          "0":
            id: "0"
            taskid: ep-{n['lifecycle_id']}-start
            type: start
            task:
              id: ep-{n['lifecycle_id']}-start
              version: -1
              name: ""
              iscommand: false
              brand: ""
            nexttasks:
              '#none#':
              - "1"
            separatecontext: false
            view: |-
              {{"position": {{"x": 50, "y": 50}}}}
          "1":
            id: "1"
            taskid: ep-{n['lifecycle_id']}-stamp-lifecycle
            type: regular
            task:
              id: ep-{n['lifecycle_id']}-stamp-lifecycle
              version: -1
              name: Stamp SOCFramework.lifecycle
              description: |
                Required by all framework engines. Do not remove or relocate.
                See cross-lifecycle-surfaces.md V4.
              scriptName: Set
              type: regular
              iscommand: false
              brand: ""
            scriptarguments:
              key:
                simple: SOCFramework.lifecycle
              value:
                simple: {n['lifecycle_id']}
            nexttasks:
              '#none#':
              - "2"
            separatecontext: false
            continueonerror: false
            view: |-
              {{"position": {{"x": 50, "y": 200}}}}
          "2":
            id: "2"
            taskid: ep-{n['lifecycle_id']}-foundation
            type: playbook
            task:
              id: ep-{n['lifecycle_id']}-foundation
              version: -1
              name: Foundation - Upon Trigger V3
              description: |
                Shared Foundation pipeline (Normalize, Enrich, Dedup).
                TODO: Confirm Foundation_-_Upon_Trigger_V3 is the right entry for
                this lifecycle or substitute the appropriate Foundation playbook.
              playbookName: Foundation - Upon Trigger V3
              type: playbook
              iscommand: false
              brand: ""
            nexttasks:
              '#none#':
              - "3"
            separatecontext: false
            view: |-
              {{"position": {{"x": 50, "y": 360}}}}
          "3":
            id: "3"
            taskid: ep-{n['lifecycle_id']}-dispatch
            type: playbook
            task:
              id: ep-{n['lifecycle_id']}-dispatch
              version: -1
              name: {n['lifecycle_controller']}
              description: |
                TODO: Wire the lifecycle controller here once authored.
                The controller orchestrates phases:
                {", ".join(args._phases)}
              playbookName: {n['lifecycle_controller']}
              type: playbook
              iscommand: false
              brand: ""
            nexttasks:
              '#none#':
              - "4"
            separatecontext: false
            view: |-
              {{"position": {{"x": 50, "y": 520}}}}
          "4":
            id: "4"
            taskid: ep-{n['lifecycle_id']}-done
            type: title
            task:
              id: ep-{n['lifecycle_id']}-done
              version: -1
              name: Done
              type: title
              iscommand: false
              brand: ""
            separatecontext: false
            view: |-
              {{"position": {{"x": 50, "y": 680}}}}
        view: |-
          {{"linkLabelsPosition": {{}}, "paper": {{"dimensions": {{"height": 700, "width": 380, "x": 40, "y": 40}}}}}}
        inputs: []
        outputs: []
        fromversion: 5.0.0
        marketplaces:
        - marketplacev2
        system: true
        """)


def tpl_controller(n: dict, args: argparse.Namespace) -> str:
    """Lifecycle controller (phase router). Linear chain of
    title -> phase-subplaybook, in lifecycle order. No category routing here —
    each phase sub-playbook owns its own product-category router."""
    pb = n["lifecycle_controller"]
    tid = pb.lower()
    L = [
        f"# {pb}",
        f"# Lifecycle controller (phase router) for the {n['lifecycle_name']} lifecycle.",
        "# Scaffolded by tools/scaffold_lifecycle.py. Linear chain of",
        "# title -> phase sub-playbook, in lifecycle order. Performs NO product-",
        "# category routing and NO actions — each phase sub-playbook owns the",
        "# product-category router and the Workflow Action leaves.",
        "",
        "adopted: true",
        f"id: {pb}",
        "version: -1",
        "contentitemexportablefields:",
        "  contentitemfields:",
        f"    packID: {n['pack_name']}",
        f"    packName: {n['pack_display']}",
        "    itemVersion: 1.0.0",
        "    fromServerVersion: 5.0.0",
        '    toServerVersion: ""',
        '    definitionid: ""',
        '    prevname: ""',
        "    isoverridable: false",
        "    supportedModules: []",
        f"name: {pb}",
        "description: |-",
        f"  Top-level controller for the {n['lifecycle_name']} lifecycle. Orchestrates",
        f"  phases in order: {', '.join(args._phases)}. Each phase sub-playbook owns",
        "  its own product-category router. No category routing or actions here.",
        "tags:",
        "- SOC",
        "- SOC_Framework_Unified",
        f"- {n['lifecycle_name'].replace(' ', '_')}",
        'starttaskid: "0"',
        "tasks:",
        '  "0":',
        '    id: "0"',
        f"    taskid: {tid}-start",
        "    type: start",
        "    task:",
        f"      id: {tid}-start",
        "      version: -1",
        '      name: ""',
        "      iscommand: false",
        '      brand: ""',
        "    nexttasks:",
        "      '#none#':",
        '      - "1"',
        "    separatecontext: false",
        "    view: |-",
        '      {"position": {"x": 450, "y": 50}}',
    ]
    # phases: alternate title (odd ids) and playbook (even ids), chain forward
    y = 200
    task_id = 1
    for i, ph in enumerate(args._phases):
        ph_pb = f"SOC_{ph.replace(' ', '_')}"
        title_id = task_id
        pb_id = task_id + 1
        next_after = task_id + 2  # next title, or Done
        # title
        L += [
            f'  "{title_id}":',
            f'    id: "{title_id}"',
            f"    taskid: {tid}-title-{ph.lower().replace(' ', '-')}",
            "    type: title",
            "    task:",
            f"      id: {tid}-title-{ph.lower().replace(' ', '-')}",
            "      version: -1",
            f"      name: {ph}",
            "      type: title",
            "      iscommand: false",
            '      brand: ""',
            "    nexttasks:",
            "      '#none#':",
            f'      - "{pb_id}"',
            "    separatecontext: false",
            "    view: |-",
            f'      {{"position": {{"x": 450, "y": {y}}}}}',
        ]
        y += 160
        # phase playbook
        L += [
            f'  "{pb_id}":',
            f'    id: "{pb_id}"',
            f"    taskid: {tid}-phase-{ph.lower().replace(' ', '-')}",
            "    type: playbook",
            "    task:",
            f"      id: {tid}-phase-{ph.lower().replace(' ', '-')}",
            "      version: -1",
            f"      name: {ph_pb}",
            f"      playbookName: {ph_pb}",
            "      type: playbook",
            "      iscommand: false",
            '      brand: ""',
            "    nexttasks:",
            "      '#none#':",
            f'      - "{next_after}"',
            "    separatecontext: false",
            "    view: |-",
            f'      {{"position": {{"x": 450, "y": {y}}}}}',
        ]
        y += 160
        task_id += 2
    # Done
    done_id = task_id
    L += [
        f'  "{done_id}":',
        f'    id: "{done_id}"',
        f"    taskid: {tid}-done",
        "    type: title",
        "    task:",
        f"      id: {tid}-done",
        "      version: -1",
        "      name: Done",
        "      type: title",
        "      iscommand: false",
        '      brand: ""',
        "    separatecontext: false",
        "    view: |-",
        f'      {{"position": {{"x": 450, "y": {y}}}}}',
        "view: |-",
        f'  {{"linkLabelsPosition": {{}}, "paper": {{"dimensions": {{"height": {y + 100}, "width": 500, "x": 440, "y": 40}}}}}}',
        "inputs: []",
        "outputs: []",
        "fromversion: 5.0.0",
        "marketplaces:",
        "- marketplacev2",
        "system: true",
    ]
    return "\n".join(L) + "\n"


def tpl_phase_router(n: dict, args: argparse.Namespace, phase: str) -> str:
    """Phase = PRODUCT-CATEGORY ROUTER. Mirrors NIST IR SOC Analysis_V3:
      start -> Product Category switch (on SOCFramework.Product.category)
            -> per-category Execution Branch gate (reads SOCExecutionList_<ID>)
            -> per-category Workflow leaf -> Done."""
    pb = f"SOC_{phase.replace(' ', '_')}"
    tid = pb.lower()
    cats = args._categories
    labels = n["category_label"]
    # task id plan: 0 start, 1 category switch, then per cat (branch_id, wf_ref), DONE = "done"
    # branch ids start at 2, step 2; wf ref id is a string label to keep unique
    branch_ids = {}
    next_id = 2
    for c in cats:
        branch_ids[c] = next_id
        next_id += 2
    L = [
        f"# {pb}",
        f"# {phase} phase — PRODUCT-CATEGORY ROUTER for the {n['lifecycle_name']} lifecycle.",
        "# Scaffolded by tools/scaffold_lifecycle.py.",
        "adopted: true",
        f"id: {pb}",
        "version: -1",
        "contentitemexportablefields:",
        "  contentitemfields:",
        f"    packID: {n['pack_name']}",
        f"    packName: {n['pack_display']}",
        "    itemVersion: 1.0.0",
        "    fromServerVersion: 5.0.0",
        '    toServerVersion: ""',
        '    definitionid: ""',
        '    prevname: ""',
        "    isoverridable: false",
        "    supportedModules: []",
        f"name: {pb}",
        "description: |-",
        f"  {phase} phase for the {n['lifecycle_name']} lifecycle. Routes on product",
        "  category (SOCFramework.Product.category) to the per-category Workflow",
        f"  playbook, gated by {n['execution_list']} execute_branch.",
        "tags:",
        "- SOC",
        "- SOC_Framework_Unified",
        f"- {n['lifecycle_name'].replace(' ', '_')}",
        'starttaskid: "0"',
        "tasks:",
        '  "0":',
        '    id: "0"',
        f"    taskid: {tid}-start",
        "    type: start",
        "    task:",
        f"      id: {tid}-start",
        "      version: -1",
        '      name: ""',
        "      iscommand: false",
        '      brand: ""',
        "    nexttasks:",
        "      '#none#':",
        "      - phasestamp",
        "    separatecontext: false",
        "    view: |-",
        '      {"position": {"x": 450, "y": 50}}',
        # Phase marker: SOCCommandWrapper reads SOCFramework.phase for the dataset `phase` column.
        "  phasestamp:",
        "    id: phasestamp",
        f"    taskid: {tid}-phasestamp",
        "    type: regular",
        "    task:",
        f"      id: {tid}-phasestamp",
        "      version: -1",
        "      name: Stamp SOCFramework.phase",
        "      description: Phase marker consumed by SOCCommandWrapper for the dataset phase column.",
        "      script: Set",
        "      type: regular",
        "      iscommand: false",
        '      brand: ""',
        "    scriptarguments:",
        "      key:",
        "        simple: SOCFramework.phase",
        "      value:",
        f"        simple: {phase.replace(' ', '_')}",
        "    nexttasks:",
        "      '#none#':",
        '      - "1"',
        "    separatecontext: false",
        "    continueonerror: true",
        "    view: |-",
        '      {"position": {"x": 450, "y": 120}}',
        '  "1":',
        '    id: "1"',
        f"    taskid: {tid}-category",
        "    type: condition",
        "    task:",
        f"      id: {tid}-category",
        "      version: -1",
        "      name: Product Category",
        "      type: condition",
        "      iscommand: false",
        '      brand: ""',
        "    nexttasks:",
        "      '#default#':",
        '      - "done"',
    ]
    for c in cats:
        L += [f"      {c}:", f'      - "{branch_ids[c]}"']
    L += ["    separatecontext: false", "    conditions:"]
    for c in cats:
        L += [
            f"    - label: {c}",
            "      condition:",
            "      - - operator: isEqualString",
            "          left:",
            "            value:",
            "              simple: inputs.ProductCategory",
            "            iscontext: true",
            "          right:",
            "            value:",
            f"              simple: {c}",
        ]
    L += ["    view: |-", '      {"position": {"x": 450, "y": 200}}']
    # per-category branch gate + workflow ref
    xs = 150
    for c in cats:
        lbl = labels[c]
        wfname = f"SOC_{lbl}_{phase.replace(' ', '_')}"
        bid = branch_ids[c]
        wf_ref = f"wf-{c}"
        L += [
            f'  "{bid}":',
            f'    id: "{bid}"',
            f"    taskid: {tid}-branch-{c}",
            "    type: condition",
            "    task:",
            f"      id: {tid}-branch-{c}",
            "      version: -1",
            f"      name: {lbl} Execution Branch",
            "      type: condition",
            "      iscommand: false",
            '      brand: ""',
            "    nexttasks:",
            "      '#default#':",
            '      - "done"',
            "      Run:",
            f'      - "{wf_ref}"',
            "    separatecontext: false",
            "    conditions:",
            "    - label: Run",
            "      condition:",
            "      - - operator: isEqualString",
            "          left:",
            "            value:",
            "              complex:",
            "                root: inputs.ExecutionBranch",
            "                transformers:",
            "                - operator: getField",
            "                  args:",
            "                    field:",
            "                      value:",
            f"                        simple: {wfname}",
            "                - operator: getField",
            "                  args:",
            "                    field:",
            "                      value:",
            "                        simple: execute_branch",
            "            iscontext: true",
            "          right:",
            "            value:",
            "              simple: default",
            "    view: |-",
            f'      {{"position": {{"x": {xs}, "y": 360}}}}',
            f'  "{wf_ref}":',
            f'    id: "{wf_ref}"',
            f"    taskid: {tid}-wf-{c}",
            "    type: playbook",
            "    task:",
            f"      id: {tid}-wf-{c}",
            "      version: -1",
            f"      name: {wfname}",
            f"      playbookName: {wfname}",
            "      type: playbook",
            "      iscommand: false",
            '      brand: ""',
            "    nexttasks:",
            "      '#none#':",
            '      - "done"',
            "    separatecontext: false",
            "    view: |-",
            f'      {{"position": {{"x": {xs}, "y": 520}}}}',
        ]
        xs += 300
    L += [
        '  "done":',
        '    id: "done"',
        f"    taskid: {tid}-done",
        "    type: title",
        "    task:",
        f"      id: {tid}-done",
        "      version: -1",
        "      name: Done",
        "      type: title",
        "      iscommand: false",
        '      brand: ""',
        "    separatecontext: false",
        "    view: |-",
        '      {"position": {"x": 450, "y": 700}}',
        "view: |-",
        '  {"linkLabelsPosition": {}, "paper": {"dimensions": {"height": 720, "width": 980, "x": 140, "y": 40}}}',
        "inputs:",
        "- key: ExecutionBranch",
        "  value:",
        f"    simple: ${{lists.{n['execution_list']}}}",
        "  required: false",
        "  description: Branch-routing list (execute_branch per Workflow playbook).",
        "  playbookInputQuery: null",
        "- key: ProductCategory",
        "  value:",
        "    simple: ${SOCFramework.Product.category}",
        "  required: false",
        "  description: Routed product category.",
        "  playbookInputQuery: null",
        "outputs: []",
        "fromversion: 5.0.0",
        "marketplaces:",
        "- marketplacev2",
        "system: true",
    ]
    return "\n".join(L) + "\n"


def tpl_workflow_leaf(n: dict, args: argparse.Namespace, phase: str, category: str) -> str:
    """Workflow Action leaf for (phase x category).
      - action phase  -> SOCCommandWrapper call (shadow default via SOCFrameworkActions).
      - other phase   -> Set-based decision/discovery stub (acknowledge marker).
    Action names are PLACEHOLDERS that must be registered in the shared
    SOCFrameworkActions list before runtime resolution."""
    lbl = n["category_label"][category]
    name = f"SOC_{lbl}_{phase.replace(' ', '_')}"
    tid = name.lower()
    is_action = phase in args._action_phases
    phase_clean = phase.replace(" ", "_")
    L = [
        f"# {name}",
        f"# Workflow Action (leaf) — {phase} phase, category {category}.",
        "# Scaffolded by tools/scaffold_lifecycle.py.",
        f"# SEEDED STUB: {'SOCCommandWrapper call (shadow default).' if is_action else 'Set-based decision/discovery stub.'}",
        "adopted: true",
        f"id: {name}",
        "version: -1",
        "contentitemexportablefields:",
        "  contentitemfields:",
        f"    packID: {n['pack_name']}",
        f"    packName: {n['pack_display']}",
        "    itemVersion: 1.0.0",
        "    fromServerVersion: 5.0.0",
        '    toServerVersion: ""',
        '    definitionid: ""',
        '    prevname: ""',
        "    isoverridable: false",
        "    supportedModules: []",
        f"name: {name}",
        "description: |-",
        f"  {phase}-phase Workflow for {category}. Seeded stub.",
        "tags:",
        "- SOC",
        "- SOC_Framework_Unified",
        f"- {n['lifecycle_name'].replace(' ', '_')}",
        'starttaskid: "0"',
        "tasks:",
        '  "0":',
        '    id: "0"',
        f"    taskid: {tid}-start",
        "    type: start",
        "    task:",
        f"      id: {tid}-start",
        "      version: -1",
        '      name: ""',
        "      iscommand: false",
        '      brand: ""',
        "    nexttasks:",
        "      '#none#':",
        '      - "1"',
        "    separatecontext: false",
        "    view: |-",
        '      {"position": {"x": 50, "y": 50}}',
    ]
    if is_action:
        action = f"soc-{n['lifecycle_id']}-{phase.lower()}-{category.split('_')[-1]}"
        L += [
            '  "1":',
            '    id: "1"',
            f"    taskid: {tid}-wrap",
            "    type: regular",
            "    task:",
            f"      id: {tid}-wrap",
            "      version: -1",
            f'      name: "Universal Command: {action}"',
            "      description: |-",
            "        SEEDED placeholder action. SOCCommandWrapper reads the vendor",
            "        command and shadow_mode for this action from the shared",
            "        SOCFrameworkActions list. ACTION MUST BE REGISTERED there",
            "        (shadow_mode: true at PoV) before runtime resolution.",
            "      script: SOCCommandWrapper",
            "      type: regular",
            "      iscommand: false",
            '      brand: ""',
            "    scriptarguments:",
            "      Action_Actor:",
            "        simple: automation",
            "      LifeCycle:",
            f"        simple: {n['lifecycle_id']}",
            "      Phase:",
            f"        simple: {phase_clean}",
            "      action:",
            f"        simple: {action}",
            "      output_key:",
            f"        simple: {phase_clean}.Execution",
            "    nexttasks:",
            "      '#none#':",
            '      - "done"',
            "    separatecontext: false",
            "    continueonerror: true",
            '    continueonerrortype: ""',
            "    view: |-",
            '      {"position": {"x": 50, "y": 200}}',
        ]
    else:
        # Set-based discovery/decision stub: a single acknowledge marker.
        L += [
            '  "1":',
            '    id: "1"',
            f"    taskid: {tid}-seed",
            "    type: regular",
            "    task:",
            f"      id: {tid}-seed",
            "      version: -1",
            f"      name: Seed {phase_clean} marker",
            "      description: |-",
            "        Seeded stub — replace with category discovery/decision logic.",
            "      script: Set",
            "      type: regular",
            "      iscommand: false",
            '      brand: ""',
            "    scriptarguments:",
            "      key:",
            f"        simple: {phase_clean}.attempted",
            "      value:",
            '        simple: "true"',
            "    nexttasks:",
            "      '#none#':",
            '      - "done"',
            "    separatecontext: false",
            "    continueonerror: true",
            '    continueonerrortype: ""',
            "    view: |-",
            '      {"position": {"x": 50, "y": 200}}',
        ]
    L += [
        '  "done":',
        '    id: "done"',
        f"    taskid: {tid}-done",
        "    type: title",
        "    task:",
        f"      id: {tid}-done",
        "      version: -1",
        "      name: Done",
        "      type: title",
        "      iscommand: false",
        '      brand: ""',
        "    separatecontext: false",
        "    view: |-",
        '      {"position": {"x": 50, "y": 360}}',
        "view: |-",
        '  {"linkLabelsPosition": {}, "paper": {"dimensions": {"height": 380, "width": 380, "x": 40, "y": 40}}}',
        "inputs: []",
        "outputs: []",
        "fromversion: 5.0.0",
        "marketplaces:",
        "- marketplacev2",
        "system: true",
    ]
    return "\n".join(L) + "\n"


def tpl_execution_list_descriptor(n: dict) -> str:
    """SOCExecutionList_<ID> list descriptor (matches SOCExecutionList_V3 shape)."""
    obj = {
        "allRead": True, "allReadWrite": True, "cacheVersn": 0, "data": "-",
        "definitionId": "", "description": (
            f"Branch-routing for the {n['lifecycle_name']} lifecycle. Maps each "
            "Workflow playbook to its execute_branch (default = run, custom = "
            "alternate, omitted = skip)."),
        "detached": False, "fromServerVersion": "6.5.0", "id": n["execution_list"],
        "isOverridable": False, "itemVersion": "1.0.0", "locked": False,
        "name": n["execution_list"], "nameLocked": False, "packID": "", "packName": "",
        "previousAllRead": True, "previousAllReadWrite": True, "system": False,
        "tags": None, "toServerVersion": "", "truncated": False, "type": "json",
        "version": -1, "fromVersion": "6.5.0", "display_name": n["execution_list"],
    }
    return json.dumps(obj, indent=2) + "\n"


def tpl_execution_list_data(n: dict, args: argparse.Namespace) -> str:
    """Populate execute_branch=default for every (phase x category) Workflow leaf."""
    rows = {}
    for ph in args._phases:
        for c in args._categories:
            lbl = n["category_label"][c]
            rows[f"SOC_{lbl}_{ph.replace(' ', '_')}"] = {"execute_branch": "default"}
    return json.dumps(rows, indent=2) + "\n"



def tpl_docs_overview(n: dict, args: argparse.Namespace) -> str:
    return dedent(f"""\
        # {n['pack_display']}

        {args.description or f"{n['lifecycle_name']} lifecycle for the SOC Framework."}

        ## Pack contents

        - **Schemas** (in `schemas/soc-framework/{n['pack_name']}/`):
          - `{n['schemas']['NormalizeMap']}.yaml`
          - `{n['schemas']['EnrichmentMap']}.yaml`
          - `{n['schemas']['DedupContract']}.yaml`
          - `{n['schemas']['PhaseContract']}.yaml`
        - **Entry Point playbook:** `{n['ep_playbook']}`
        - **Phase playbooks:** {", ".join(f"`SOC_{p.replace(' ', '_')}`" for p in args._phases)}
        - **Dataset:** `{n['dataset']}` (per-lifecycle, RBAC-isolated;
          auto-derived from XSIAM convention `<vendor>_<product>_raw`)
        - **System XQL HTTP Collector instance:** `{n['http_collector_instance']}`
          (provisioned at pack install via xsoar_config.json; XSIAM
          server-provisions the URL; keyless, XSIAM-internal auth — NOT the
          generic "HTTP Collector" integration which requires API keys)

        ## Next steps

        1. Author the four schemas with this lifecycle's actual contract content.
        2. Run `tools/generate_soc_framework_content.py emit --pack {n['pack_name']}`
           to materialize the lists from schemas.
        3. Author the phase playbook bodies (the scaffolded stubs are minimal).

        ## Architecture references

        - `docs/architecture/cross-lifecycle-surfaces.md` — tier model, blast-radius
          rubric, known violations and resolutions.
        """)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def stamp(args: argparse.Namespace, repo: Path, n: dict) -> Writer:
    w = Writer(dry_run=args.dry_run, force=args.force)

    pack_dir = repo / "Packs" / n["pack_name"]
    schema_dir = repo / "schemas" / "soc-framework" / n["pack_name"]
    docs_dir = repo / "docs" / args._lifecycle_pack_id

    # Pack files
    # TODO: refactor pack_metadata.json + dir layout generation to delegate to
    # tools/init_pack.py (per design discussion 2026-05-28). Keeping inline for
    # now so scaffold_lifecycle.py works standalone; will refactor once
    # init_pack.py CLI interface is confirmed.
    w.write(pack_dir / "pack_metadata.json",   tpl_pack_metadata(n, args))
    w.write(pack_dir / "xsoar_config.json",    tpl_xsoar_config(n))
    w.write(pack_dir / "ReleaseNotes" / "1_0_0.md", tpl_release_notes(n, args))

    # Empty list subdirs (populated by generate_soc_framework_content.py emit)
    for sname in n["schemas"].values():
        w.mkdir(pack_dir / "Lists" / sname)
    # NOTE: execution_list dir is NOT pre-created here — it's written populated
    # (descriptor + data) in the playbook-layer section below.

    # Other content dirs (empty)
    w.mkdir(pack_dir / "Layouts")
    w.mkdir(pack_dir / "Dashboards")

    # Schemas
    w.write(schema_dir / f"{n['schemas']['NormalizeMap']}.yaml",  tpl_normalize_schema(n))
    w.write(schema_dir / f"{n['schemas']['EnrichmentMap']}.yaml", tpl_enrichment_schema(n))
    w.write(schema_dir / f"{n['schemas']['DedupContract']}.yaml", tpl_dedup_schema(n))
    w.write(schema_dir / f"{n['schemas']['PhaseContract']}.yaml", tpl_phase_schema(n, args))

    # Playbook layer — the full standard (mirrors NIST IR), generated:
    #   EP -> controller -> phase routers -> per-category Workflow leaves
    w.write(pack_dir / "Playbooks" / f"{n['ep_playbook']}.yml", tpl_ep_playbook(n, args))
    w.write(pack_dir / "Playbooks" / f"{n['lifecycle_controller']}.yml", tpl_controller(n, args))
    for ph in args._phases:
        pid = f"SOC_{ph.replace(' ', '_')}"
        w.write(pack_dir / "Playbooks" / f"{pid}.yml", tpl_phase_router(n, args, ph))
        for cat in args._categories:
            lbl = n["category_label"][cat]
            leaf = f"SOC_{lbl}_{ph.replace(' ', '_')}"
            w.write(pack_dir / "Playbooks" / f"{leaf}.yml",
                    tpl_workflow_leaf(n, args, ph, cat))

    # Execution list — descriptor + populated data (one row per Workflow leaf)
    el = n["execution_list"]
    w.write(pack_dir / "Lists" / el / f"{el}.json", tpl_execution_list_descriptor(n))
    w.write(pack_dir / "Lists" / el / f"{el}_data.json", tpl_execution_list_data(n, args))

    # Docs
    w.write(docs_dir / "overview.md", tpl_docs_overview(n, args))

    return w


def print_summary(args: argparse.Namespace, n: dict, w: Writer) -> None:
    mode = "DRY RUN" if args.dry_run else "Created"
    print(f"\n{mode} — {n['pack_display']} ({n['pack_name']})")
    print(f"  lifecycle id        : {n['lifecycle_id']}")
    print(f"  dataset             : {n['dataset']}")
    print(f"  System XQL HTTP inst: {n['http_collector_instance']}")
    print(f"  EP playbook         : {n['ep_playbook']}")
    print(f"  Phase playbooks     : {', '.join('SOC_' + p.replace(' ', '_') for p in args._phases)}")
    if w.created:
        print(f"\n{mode} files / dirs ({len(w.created)}):")
        for p in sorted(w.created):
            print(f"  + {p}")
    if w.skipped:
        print(f"\nSkipped (already exist, use --force to overwrite) ({len(w.skipped)}):")
        for p in sorted(w.skipped):
            print(f"  - {p}")
    print("\nNext steps:")
    print(f"  1. Author the four schemas in schemas/soc-framework/{n['pack_name']}/")
    print( "  2. python3 tools/generate_soc_framework_content.py emit "
          f"--pack {n['pack_name']}")
    print( "  3. Author the phase playbook bodies (stubs are minimal).")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    args = parse_args()
    validate_args(args)
    repo = find_repo_root(Path.cwd())
    n = derive_names(args)
    w = stamp(args, repo, n)
    print_summary(args, n, w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
