#!/usr/bin/env bash
# upload_package.sh
# ─────────────────────────────────────────────────────────────────────────────
# Upload a pack to an XSIAM tenant via demisto-sdk (no zipfiles).
#
# Credentials are read from .env at the repo root (local dev) or from
# environment variables already set by the caller (CI / GitHub Actions).
# Variables already in the environment always take precedence over .env values.
#
# Required variables:
#   DEMISTO_BASE_URL      XSIAM tenant URL
#   DEMISTO_API_KEY       API key
#   XSIAM_AUTH_ID         API auth ID (numeric)
#
# Optional (used by other tools, not this script directly):
#   CONTENT_REPO_RAW_LINK Raw URL to xsoar_config.json for bundle installer
#
# Usage:
#   bash tools/upload_package.sh Packs/soc-framework-nist-ir
#   bash tools/upload_package.sh Packs/soc-optimization-unified
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Locate repo root ──────────────────────────────────────────────────────────
if git_root=$(git rev-parse --show-toplevel 2>/dev/null); then
  cd "$git_root"
fi

# ── Load .env (only sets vars not already in the environment) ─────────────────
ENV_FILE=".env"
if [[ -f "$ENV_FILE" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Skip blank lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    # Only process KEY=VALUE lines
    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      val="${BASH_REMATCH[2]}"
      # Never overwrite a variable already set in the environment (CI case)
      if [[ -z "${!key+x}" ]]; then
        export "$key"="$val"
      fi
    fi
  done < "$ENV_FILE"
fi

# ── Validate required credentials ─────────────────────────────────────────────
missing=()
[[ -z "${DEMISTO_BASE_URL:-}" ]] && missing+=("DEMISTO_BASE_URL")
[[ -z "${DEMISTO_API_KEY:-}"  ]] && missing+=("DEMISTO_API_KEY")
[[ -z "${XSIAM_AUTH_ID:-}"   ]] && missing+=("XSIAM_AUTH_ID")

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "ERROR: Missing required credentials: ${missing[*]}"
  echo "       Set them in .env at the repo root or export them before running."
  echo "       See tools/.env.example for the expected format."
  exit 1
fi

# ── Resolve pack path ─────────────────────────────────────────────────────────
PACK_PATH="${1:-}"
if [[ -z "$PACK_PATH" ]]; then
  read -rp "Pack path (e.g. Packs/soc-framework-nist-ir): " PACK_PATH
fi

[[ -d "$PACK_PATH" ]]                    || { echo "ERROR: Pack path not found: $PACK_PATH"; exit 1; }
[[ -f "$PACK_PATH/pack_metadata.json" ]] || { echo "ERROR: Missing pack_metadata.json in $PACK_PATH"; exit 1; }

# ── Upload ────────────────────────────────────────────────────────────────────
export DEMISTO_SDK_IGNORE_CONTENT_WARNING=1

echo ""
echo "  Tenant : $DEMISTO_BASE_URL"
echo "  Pack   : $PACK_PATH"
echo ""

start=$(date +%s)

demisto-sdk upload \
  -x -z \
  -i "$PACK_PATH" \
  --marketplace marketplacev2 \
  --console-log-threshold DEBUG

end=$(date +%s)
elapsed=$((end - start))
echo ""
echo "  Upload completed in $((elapsed/60))m $((elapsed%60))s (${elapsed}s)"
