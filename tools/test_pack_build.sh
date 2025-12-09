#!/usr/bin/env bash
set -euo pipefail

PACK_NAME="$1"
REQUIRED_SDK_VERSION="1.38.14"

ROOT_DIR="$(pwd)"
PACK_PATH="${ROOT_DIR}/Packs/${PACK_NAME}"

echo
echo "=== Local Pack Build Test ==="
echo "Pack name: ${PACK_NAME}"
echo "Pack path: ${PACK_PATH}"
echo

if [[ ! -d "${PACK_PATH}" ]]; then
  echo "❌ ERROR: Pack directory does not exist: ${PACK_PATH}"
  exit 1
fi

########################################
# 1. Validate demisto-sdk version
########################################

echo "=== Checking demisto-sdk version ==="

SDK_VERSION_LINE="$(
  DEMISTO_SDK_IGNORE_CONTENT_WARNING=1 demisto-sdk --version 2>&1 | tail -n 1
)"

SDK_VERSION="$(echo "${SDK_VERSION_LINE}" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' || true)"

echo "demisto-sdk version: ${SDK_VERSION}"

if [[ -z "${SDK_VERSION}" ]]; then
  echo "❌ Could not parse demisto-sdk version"
  exit 1
fi

if [[ "${SDK_VERSION}" != "${REQUIRED_SDK_VERSION}" ]]; then
  echo "❌ ERROR: Expected demisto-sdk ${REQUIRED_SDK_VERSION}, got ${SDK_VERSION}"
  exit 1
fi

echo "✔ demisto-sdk version OK"
echo

########################################
# 2. Run your normalizer on the pack
########################################

echo "=== Running normalize (fix mode) ==="
python3 tools/normalize_ruleid_adopted.py --root "${PACK_PATH}" --fix
echo "✔ Fix mode done"
echo

echo "=== Running normalize (check-only) ==="
python3 tools/normalize_ruleid_adopted.py --root "${PACK_PATH}"
echo "✔ Check-only passed"
echo

########################################
# 3. Build pack using prepare-content
########################################

echo "=== Building pack with demisto-sdk prepare-content ==="
rm -rf dist
mkdir -p dist

DEMISTO_SDK_IGNORE_CONTENT_WARNING=1 \
    demisto-sdk prepare-content \
      -i "${PACK_PATH}" \
      -o dist \
      --marketplace marketplacev2 \
      --force

echo
echo "=== Listing dist directory ==="
ls -l dist

echo
echo "=== Done. Pack built locally ==="
echo
