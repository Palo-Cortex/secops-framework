#!/usr/bin/env bash
set -euo pipefail

PACK_PATH="${1:-}"

if [[ -z "$PACK_PATH" ]]; then
  read -rp "Pack path (e.g. Packs/soc-optimization): " PACK_PATH
fi

[[ -d "$PACK_PATH" ]] || { echo "Pack path not found: $PACK_PATH"; exit 1; }
[[ -f "$PACK_PATH/pack_metadata.json" ]] || { echo "Missing pack_metadata.json"; exit 1; }

export DEMISTO_SDK_IGNORE_CONTENT_WARNING=1

# go to git root if available
if git_root=$(git rev-parse --show-toplevel 2>/dev/null); then
  cd "$git_root"
fi

echo "Uploading $PACK_PATH ..."
start=$(date +%s)

demisto-sdk upload -x -z -i "$PACK_PATH" --console-log-threshold DEBUG

end=$(date +%s)
elapsed=$((end - start))

echo "✔ Upload completed in $((elapsed/60))m $((elapsed%60))s (${elapsed}s)"
