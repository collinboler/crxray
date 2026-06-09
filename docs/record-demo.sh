#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
URL="https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh"
OUT="/tmp/crxray-vhs-demo"

rm -rf "$OUT"

printf '# Paste a Chrome Web Store link - get source + security audit\n\n'
printf '> npx -y crxray %s --audit\n' "$URL"
sleep 0.4

# Run via local bin so recording is reliable; output matches what npx users see.
node "$ROOT/bin/crxray.js" "$URL" --audit -o "$OUT"
