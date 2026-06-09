#!/usr/bin/env bash
# Replays curated download output (used by VHS after the visible npx command is typed).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if command -v pv >/dev/null 2>&1; then
  pv -qL 3800 docs/demo-output.txt
else
  cat docs/demo-output.txt
fi

sleep 1.5
