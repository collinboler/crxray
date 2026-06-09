#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
URL="https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh"
OUT="/tmp/crxray-vhs-demo"

rm -rf "$OUT"
node "$ROOT/bin/crxray.js" "$URL" --audit -o "$OUT"
