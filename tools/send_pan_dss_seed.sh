#!/usr/bin/env bash
# Seed socfw identity source data into pan_dss_raw via the brumxdr HTTP Collector.
# Then run correlation rule 416 (SOC IdentityResolve) to build socfw_identity_map.
#
# Reads API_URL + API_KEY from the same env file the replay tool uses.
# Adjust ENV path if yours differs.
set -euo pipefail

ENV="${1:-.env-brumxdr-pan-dss}"
SEED="${2:-pan_dss_raw_seed.json}"

# Pull collector URL + token from the env file (KEY=VALUE lines).
API_URL="$(grep -E '^API_URL=' "$ENV" | cut -d= -f2-)"
API_KEY="$(grep -E '^API_KEY=' "$ENV" | cut -d= -f2-)"

if [ -z "$API_URL" ] || [ -z "$API_KEY" ]; then
  echo "API_URL or API_KEY missing from $ENV" >&2
  exit 1
fi

echo "[*] Posting $(python3 -c "import json;print(len(json.load(open('$SEED'))))") rows to $API_URL"

curl --fail --silent --show-error \
  -X POST "$API_URL" \
  -H "Authorization: $API_KEY" \
  -H "Content-Type: application/json" \
  --data-binary "@$SEED"

echo
echo "[*] Done. Now run rule 416 (SOC IdentityResolve) to build socfw_identity_map,"
echo "    then verify:  dataset = socfw_identity_map | fields sid, upn, netbios_and_sam_account_name"
