#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if command -v pv >/dev/null 2>&1; then
  pv -qL 4000 docs/demo-audit-output.txt
else
  cat docs/demo-audit-output.txt
fi

sleep 1.2
