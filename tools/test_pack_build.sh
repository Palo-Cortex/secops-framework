#!/usr/bin/env bash
set -euo pipefail

PACKS_DIR="Packs"
EXPECTED_SDK_VERSION="1.38.14"

#
# 1) Resolve pack name
#
PACK_NAME="${1-}"

if [ -z "$PACK_NAME" ]; then
  # Case: running from inside Packs/<pack>
  CURR_DIR_NAME=$(basename "$PWD")
  PARENT_DIR_NAME=$(basename "$(dirname "$PWD")")
  if [ "$PARENT_DIR_NAME" = "$PACKS_DIR" ] && [ -d "../$CURR_DIR_NAME" ]; then
    PACK_NAME="$CURR_DIR_NAME"
  fi
fi

if [ -z "$PACK_NAME" ]; then
  # Case: infer from changed files (staged or unstaged)
  echo "No pack name provided; trying to infer from changed files under ${PACKS_DIR}/..."

  # Prefer staged changes; fall back to working tree changes
  CHANGED=$(git diff --cached --name-only || true)
  if [ -z "$CHANGED" ]; then
    CHANGED=$(git diff --name-only || true)
  fi

  if [ -z "$CHANGED" ]; then
    echo "ERROR: No changed files found. Specify a pack name explicitly:"
    echo "  tools/test_single_pack.sh <pack-name>"
    exit 1
  fi

  PACKS=$(echo "$CHANGED" | grep "^${PACKS_DIR}/" | cut -d/ -f2 | sort -u || true)

  if [ -z "$PACKS" ]; then
    echo "ERROR: No changed files under ${PACKS_DIR}/. Specify a pack name explicitly:"
    echo "  tools/test_single_pack.sh <pack-name>"
    exit 1
  fi

  NUM_PACKS=$(echo "$PACKS" | wc -w | tr -d ' ')
  if [ "$NUM_PACKS" -ne 1 ]; then
    echo "ERROR: Changes detected in multiple packs: $PACKS"
    echo "Please specify which pack to test explicitly, e.g.:"
    echo "  tools/test_single_pack.sh soc-optimization"
    exit 1
  fi

  PACK_NAME="$PACKS"
fi

PACK_PATH="${PACKS_DIR}/${PACK_NAME}"

if [ ! -d "$PACK_PATH" ]; then
  echo "ERROR: Pack directory not found: $PACK_PATH"
  exit 1
fi

echo "📦 Testing pack: $PACK_NAME"
echo "   Path: $PACK_PATH"
echo

#
# 2) Check demisto-sdk presence + version
#
if ! command -v demisto-sdk >/dev/null 2>&1; then
  echo "ERROR: demisto-sdk not found on PATH."
  echo "Install with:"
  echo "  pip install demisto-sdk==${EXPECTED_SDK_VERSION}"
  exit 1
fi

SDK_VERSION=$(pip show demisto-sdk 2>/dev/null | awk '/Version/{print $2}')
if [ -n "$SDK_VERSION" ] && [ "$SDK_VERSION" != "$EXPECTED_SDK_VERSION" ]; then
  echo "⚠️  WARNING: demisto-sdk version is ${SDK_VERSION}, expected ${EXPECTED_SDK_VERSION}"
  echo "    Consider: pip install --upgrade demisto-sdk==${EXPECTED_SDK_VERSION}"
  echo
fi

echo "Using demisto-sdk version:"
demisto-sdk --version || true
echo

#
# 3) Validate + build the pack
#
echo "=== Validating pack: $PACK_NAME ==="
demisto-sdk validate -i "$PACK_PATH" --no-docker-checks --no-conf-json

echo "=== Test-building pack: $PACK_NAME ==="
mkdir -p dist
demisto-sdk prepare-content \
  -i "$PACK_PATH" \
  -o dist \
  --force \
  --marketplace marketplacev2

echo
echo "✅ Single-pack validate + build completed for: $PACK_NAME"
echo "   Output zips in: dist/uploadable_packs/"
