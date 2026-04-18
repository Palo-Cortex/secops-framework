#!/usr/bin/env bash
# release_pack.sh
# ─────────────────────────────────────────────────────────────────────────────
# Promote a pack from dev iteration to a tagged release.
#
# Bumps pack_metadata.json + xsoar_config.json by minor OR major (NOT revision),
# regenerates pack_catalog.json at the repo root, and prints the resulting
# version so you can tag the commit.
#
# This is the ONE sanctioned way to produce a release-level version bump.
# upload_package.sh auto-bumps revision on every dev upload; those revision
# numbers are iteration noise. When you want to mark "this is a delivery we
# stand behind," run this script.
#
# Workflow:
#   1.  Iterate locally with `bash tools/upload_package.sh <pack>`
#       (auto-bumps revision, deploys to dev tenant, doesn't touch catalog)
#   2.  When ready to promote:  `bash tools/release_pack.sh <pack> minor`
#       (bumps minor, updates catalog, leaves you ready to commit + tag)
#   3.  Commit, push, tag.
#
# Usage:
#   bash tools/release_pack.sh Packs/soc-framework-nist-ir minor
#   bash tools/release_pack.sh Packs/soc-optimization-unified major
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Locate repo root ──────────────────────────────────────────────────────────
if git_root=$(git rev-parse --show-toplevel 2>/dev/null); then
  cd "$git_root"
fi

# ── Args ──────────────────────────────────────────────────────────────────────
PACK_PATH="${1:-}"
LEVEL="${2:-}"

if [[ -z "$PACK_PATH" || -z "$LEVEL" ]]; then
  echo "Usage: $0 <pack-path> <minor|major>"
  echo ""
  echo "  pack-path   Path to the pack directory (e.g. Packs/soc-framework-nist-ir)"
  echo "  level       Release bump level: minor or major"
  echo ""
  echo "  Revision bumps happen automatically during dev iteration via"
  echo "  upload_package.sh — do not use this script for revision bumps."
  exit 1
fi

if [[ "$LEVEL" != "minor" && "$LEVEL" != "major" ]]; then
  echo "ERROR: Release bumps are minor or major only. Got: $LEVEL"
  echo "       Revision bumps are handled by upload_package.sh during dev."
  exit 1
fi

[[ -d "$PACK_PATH" ]]                    || { echo "ERROR: Pack path not found: $PACK_PATH"; exit 1; }
[[ -f "$PACK_PATH/pack_metadata.json" ]] || { echo "ERROR: Missing pack_metadata.json in $PACK_PATH"; exit 1; }

BUMP_SCRIPT="$(dirname "$0")/bump_pack_version.py"
CATALOG_SCRIPT="$(dirname "$0")/build_pack_catalog.py"

[[ -f "$BUMP_SCRIPT" ]]    || { echo "ERROR: $BUMP_SCRIPT not found"; exit 1; }
[[ -f "$CATALOG_SCRIPT" ]] || { echo "ERROR: $CATALOG_SCRIPT not found"; exit 1; }

echo ""
echo "  Pack   : $PACK_PATH"
echo "  Level  : $LEVEL release"
echo ""

# ── 1. Bump pack_metadata + xsoar_config ──────────────────────────────────────
echo "  ▶  Bumping pack version ($LEVEL)…"
python3 "$BUMP_SCRIPT" "$PACK_PATH" --level "$LEVEL"
echo ""

# ── 2. Rebuild pack_catalog.json ──────────────────────────────────────────────
echo "  ▶  Rebuilding pack_catalog.json…"
python3 "$CATALOG_SCRIPT"
echo ""

# ── 3. Summary + next steps ───────────────────────────────────────────────────
NEW_VERSION=$(python3 -c "
import json, sys
meta = json.load(open('$PACK_PATH/pack_metadata.json'))
print(meta.get('currentVersion') or meta.get('version'))
")

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✓ Release prepared: $PACK_PATH at $NEW_VERSION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Next steps:"
echo "    git add $PACK_PATH/pack_metadata.json $PACK_PATH/xsoar_config.json pack_catalog.json"
echo "    git commit -m 'release: $(basename $PACK_PATH) $NEW_VERSION'"
echo "    git tag $(basename $PACK_PATH)-$NEW_VERSION"
echo "    git push && git push --tags"
echo ""
