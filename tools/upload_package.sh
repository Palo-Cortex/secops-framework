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

# ── Platform health check ─────────────────────────────────────────────────────
HEALTH_SCRIPT="$(dirname "$0")/platform_health_check.sh"
if [[ -f "$HEALTH_SCRIPT" ]]; then
  # shellcheck source=tools/platform_health_check.sh
  source "$HEALTH_SCRIPT"
  if ! check_platform_health "$PACK_PATH"; then
    echo "  Aborting upload — platform is unhealthy."
    exit 1
  fi
fi

start=$(date +%s)

demisto-sdk upload \
  -x -z \
  -i "$PACK_PATH" \
  --marketplace marketplacev2 \
  --override-existing \
  --console-log-threshold DEBUG

end=$(date +%s)
elapsed=$((end - start))
echo ""
echo "  Upload completed in $((elapsed/60))m $((elapsed%60))s (${elapsed}s)"

# ── Correlation rules — demisto-sdk does NOT deliver these ────────────────────
# Verified 18 Sep 2026 on demisto-sdk 1.38.14 (container) and 1.39.3 (thor),
# with and without -z, on soc-crowdstrike-idp and soc-crowdstrike-falcon: the
# zip it builds has no CorrelationRules/ and declares
# contentItems.correlationrule: []. The pack installs, the version updates, the
# upload reports success, and the rule is silently never created — deathstar had
# zero pack-delivered correlation rules across 184 installed packs.
#
# So the upload is not complete until the rules are pushed through the
# correlations API, which is the only mechanism observed to create one.
if compgen -G "${PACK_PATH}/CorrelationRules/*.yml" > /dev/null; then
  echo ""
  echo "  Installing correlation rules via the correlations API…"
  if ! python3 "$(dirname "$0")/install_correlation_rules.py" "$PACK_PATH"; then
    echo "  ✗ Correlation rule install FAILED — the pack is on the tenant but"
    echo "    its rules are not. Do not treat this upload as successful."
    exit 1
  fi
fi
