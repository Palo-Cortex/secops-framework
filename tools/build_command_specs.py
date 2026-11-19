#!/usr/bin/env python3
"""Record the arguments of every vendor command the framework calls.

Reads a checkout of demisto/content and writes ``policies/vendor_command_specs.json``:
for each command named in ``SOCFrameworkActions_V3``, every integration or script
that defines it, with its arguments (required, list, default, allowed values) and
whether it is deprecated. ``tools/check_action_args.py`` holds the actions list to
this file, so a mapping that names a command or an argument the vendor does not
have fails the gate instead of failing the first time PS turns the action on.

Only the commands the list uses are recorded, so the file stays small enough to
review. Commands that content does not define are listed under ``not_in_content``
with no arguments; ``check_action_args.py`` fails on them unless the command is
in the file's ``unverified`` section with a reason.

Re-run after a content update or when a new command is mapped:

    git clone --depth 1 --filter=blob:none --sparse https://github.com/demisto/content.git /tmp/content
    git -C /tmp/content sparse-checkout set --no-cone \\
        "/Packs/*/Integrations/*/*.yml" "/Packs/*/Scripts/*/*.yml"
    python3 tools/build_command_specs.py --content /tmp/content

The ``unverified`` section is hand-maintained and kept across runs.
"""

from __future__ import annotations

import argparse
import glob
import json
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ACTIONS = REPO_ROOT / "Packs/soc-optimization-unified/Lists/SOCFrameworkActions_V3/SOCFrameworkActions_V3_data.json"
OUT = REPO_ROOT / "policies" / "vendor_command_specs.json"
PLATFORM_BRANDS = {"Builtin"}


def used_commands(actions: dict) -> set[str]:
    cmds = set()
    for entry in actions.values():
        if not isinstance(entry, dict):
            continue
        for brand, resp in (entry.get("responses") or {}).items():
            if brand not in PLATFORM_BRANDS and isinstance(resp, dict) and resp.get("command"):
                cmds.add(resp["command"])
    return cmds


def arg_spec(a: dict) -> dict:
    spec = {}
    if a.get("required"):
        spec["required"] = True
    if a.get("isArray"):
        spec["list"] = True
    if a.get("defaultValue") not in (None, ""):
        spec["default"] = str(a["defaultValue"])
    allowed = [str(v) for v in (a.get("predefined") or []) if str(v) != ""]
    if allowed:
        spec["allowed"] = allowed
    return spec


def read_definitions(content: Path, wanted: set[str]) -> dict:
    found: dict[str, list] = {}
    for path in sorted(glob.glob(str(content / "Packs/*/Integrations/*/*.yml"))
                       + glob.glob(str(content / "Packs/*/Scripts/*/*.yml"))):
        if path.endswith("_unified.yml") or "/test_data/" in path:
            continue
        try:
            doc = yaml.safe_load(open(path))
        except Exception:  # noqa: BLE001 - one unreadable file must not stop the run
            continue
        if not isinstance(doc, dict):
            continue
        rel = str(Path(path).relative_to(content))
        if "script" in doc and isinstance(doc["script"], dict) and "commands" in doc["script"]:
            source = (doc.get("commonfields") or {}).get("id") or doc.get("name")
            for cmd in doc["script"].get("commands") or []:
                if isinstance(cmd, dict) and cmd.get("name") in wanted:
                    found.setdefault(cmd["name"], []).append({
                        "source": source, "kind": "integration", "path": rel,
                        "deprecated": bool(doc.get("deprecated") or cmd.get("deprecated")),
                        "args": {a["name"]: arg_spec(a) for a in cmd.get("arguments") or []}})
        elif doc.get("name") in wanted and "args" in doc:
            found.setdefault(doc["name"], []).append({
                "source": doc["name"], "kind": "script", "path": rel,
                "deprecated": bool(doc.get("deprecated")),
                "args": {a["name"]: arg_spec(a) for a in doc.get("args") or []}})
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--content", required=True, type=Path, help="path to a demisto/content checkout")
    args = ap.parse_args()

    actions = json.loads(ACTIONS.read_text())
    wanted = used_commands(actions)
    found = read_definitions(args.content, wanted)
    previous = json.loads(OUT.read_text()) if OUT.exists() else {}
    commit = subprocess.run(["git", "-C", str(args.content), "log", "-1", "--format=%h %cs"],
                            capture_output=True, text=True).stdout.strip()

    out = {
        "source": f"demisto/content {commit}".strip(),
        "commands": {c: found[c] for c in sorted(found)},
        "not_in_content": sorted(wanted - set(found)),
        "unverified": previous.get("unverified", {}),
    }
    OUT.write_text(json.dumps(out, indent=2, sort_keys=False) + "\n")
    print(f"{OUT.relative_to(REPO_ROOT)}: {len(found)} commands, "
          f"{len(out['not_in_content'])} not in content ({', '.join(out['not_in_content']) or 'none'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
