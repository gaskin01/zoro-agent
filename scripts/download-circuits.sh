#!/usr/bin/env bash
# Download the public Groth16 circuit artifacts for the zkVerify Agent Games.
# The .wasm / .zkey files are NOT committed to git (they are binary, ~5.6 MB
# total) — this script fetches them from the official public URLs served by
# https://agentgames.zkverify.io (see /api/circuit-info for the canonical
# artifact URLs and the registered vk_hashes).
# Safe to re-run: files that already exist with the expected size are skipped.
set -euo pipefail

BASE="https://agentgames.zkverify.io/circuits"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/circuits"
mkdir -p "$DIR"

# file|expected bytes (verified against the local copies used in testing)
FILES="gatekeeper.wasm|1755820
gatekeeper_final.zkey|309750
vfy-policy.wasm|2991212
vfy-policy_final.zkey|810586"

while IFS='|' read -r file size; do
  [ -z "$file" ] && continue
  dest="$DIR/$file"
  if [ -f "$dest" ] && [ "$(wc -c < "$dest" | tr -d ' ')" = "$size" ]; then
    echo "ok   $file (already present, $size bytes)"
    continue
  fi
  echo "get  $file ..."
  curl -fSL --retry 3 -o "$dest" "$BASE/$file"
  got="$(wc -c < "$dest" | tr -d ' ')"
  if [ "$got" != "$size" ]; then
    echo "ERROR: $file downloaded $got bytes, expected $size" >&2
    rm -f "$dest"
    exit 1
  fi
  echo "ok   $file ($got bytes)"
done <<< "$FILES"

echo "circuits ready in $DIR"
