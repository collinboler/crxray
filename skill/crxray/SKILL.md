---
name: crxray
description: Download Chrome and Edge extension source code in one command from a store link or extension ID. Audits permissions, deobfuscates and beautifies JS, diffs versions, and maps entry points. Use when the user pastes a Chrome Web Store or Edge Add-ons URL, asks to download extension source code, audit, deobfuscate, beautify, diff, inspect, or review what a browser extension does.
---

# crxray — download extension source code

Download, audit, deobfuscate, and beautify any Chrome or Edge extension. No install needed — run via `npx`.

## Quick start

```bash
npx -y crxray <store-url-or-extension-id>
```

Full pipeline for security review:

```bash
npx -y crxray <url> --audit --deobfuscate --beautify --json
```

Then read `outDir`, `.crxray-audit.json`, and files listed in `audit.startHere`.

## Commands

| Command | Purpose |
|---------|---------|
| `crxray <url>` | Download and unpack source |
| `crxray <url> --audit` | + security report + entry-point map |
| `crxray <url> --deobfuscate --beautify` | + readable JS |
| `crxray audit <dir>` | Audit an already-unpacked folder |
| `crxray diff <left> <right>` | Compare two unpacked dirs or store URLs |

## Flags

| Flag | Effect |
|------|--------|
| `--json` | Machine-readable output — prefer for agents |
| `-o <dir>` | Output directory |
| `--audit` | Risk score, permissions, suspicious patterns, endpoints, start-here list |
| `--deobfuscate` | webcrack: obfuscator.io, webpack, browserify (best-effort) |
| `--beautify` | Format all `.js` files |
| `--map` | Entry-point map only (included in `--audit`) |
| `-q` | Quiet |

## Audit workflow

1. Run with `--audit --deobfuscate --beautify --json`.
2. Read `.crxray-audit.json` in `outDir` — check `risk.level`, `permissions.high`, `findings`, `endpoints`.
3. Start with files in `startHere` (manifest, background, content scripts, popup).
4. Grep for exfiltration if findings are sparse: `fetch(`, `chrome.cookies`, hardcoded domains.

## Diff workflow

```bash
npx -y crxray diff ./extension-v1 ./extension-v2 --json
```

Check `permissionChanges` first (new `tabs`, `cookies`, `<all_urls>` are red flags), then `files.added` and `endpointChanges.added`.

## Notes

- Node 18+. If `--deobfuscate` install fails: `npm install -g crxray --ignore-scripts`
- Store only serves the latest CRX — diff two local folders for version comparisons
- Extension code belongs to its authors — inspect and audit, don't redistribute
