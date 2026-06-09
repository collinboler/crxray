# crxray

> **Download Chrome & Edge extension source code in one command.** Paste a store link, get the full unpacked source on disk.

[![npm](https://img.shields.io/npm/v/crxray)](https://www.npmjs.com/package/crxray)
[![CI](https://github.com/collinboler/crxray/actions/workflows/test.yml/badge.svg)](https://github.com/collinboler/crxray/actions/workflows/test.yml)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
![node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)

The Chrome Web Store has no download button. Edge doesn't either. Every extension is just a ZIP file behind the browser's own update endpoint — but getting at it normally means browser extensions, sketchy websites, or stale npm packages.

`crxray` makes it trivial: paste a store URL (or extension ID), and it downloads the CRX, strips the signature header, and unpacks every file to a local folder. No account, no browser plugin, no manual steps. One command, full source code on disk.

```bash
npx crxray https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh
```

```
Unpacked 911 files to ublock-origin-lite-2026.607.1724/

  uBlock Origin Lite  v2026.607.1724  (MV3, chrome)
  An efficient content blocker. Blocks ads, trackers, miners, and more.

  Permissions: activeTab, declarativeNetRequest, offscreen, scripting, storage, userScripts
  Host permissions: <all_urls>
  Background: /js/background.js
```

**Zero install. Node 18+.** Download/unpack core is dependency-free; audit, beautify, and deobfuscate ship with `js-beautify` and `webcrack`.

## Download extension source in one command

```bash
# Chrome Web Store — paste any store link
npx crxray https://chromewebstore.google.com/detail/<slug>/<id>

# Edge Add-ons
npx crxray https://microsoftedge.microsoft.com/addons/detail/<slug>/<id>

# Just the extension ID works too
npx crxray cjpalhdlnbpafiamejdnhcphjbkeiagm
```

That's it. You get a folder with `manifest.json`, background scripts, content scripts, popup HTML, assets — everything the extension ships with. Ready to open in your editor, grep through, or hand to an AI agent.

## Why

- **Source code, instantly** — no CRX Viewer, no sketchy download sites, no wrestling with browser devtools. Paste a link, read the code.
- **Audit before installing** — extensions run with terrifying permissions. Download the source first and see what it actually does.
- **Built for AI agents** — paste a store link into Cursor, Claude Code, or any agent and let it review the unpacked source for you ([see below](#use-with-ai-agents)).
- **Learn from the best** — download how uBlock, React DevTools, or any popular extension is actually built.
- **Rescue abandoned extensions** — recover source when the author and GitHub repo have vanished.

## Usage

Works with Chrome Web Store URLs (current and legacy), Edge Add-ons URLs, or a bare 32-character extension ID.

### Options

| Flag | Description |
|------|-------------|
| `-o, --out <dir>` | Output directory (default: `./<name>-<version>/`) |
| `--store <name>` | Store for bare IDs: `chrome` (default) or `edge` |
| `--crx-only` | Save the raw `.crx` file, skip unpacking |
| `--keep-crx` | Keep the `.crx` alongside the unpacked source |
| `--audit` | Security audit + entry-point map (writes `.crxray-audit.json`) |
| `--map` | Entry-point map and readability stats only |
| `--deobfuscate` | Deobfuscate all JS via [webcrack](https://github.com/j4k0xb/webcrack) |
| `--beautify` | Beautify all JS files |
| `--json` | Machine-readable output (for scripts and agents) |
| `-q, --quiet` | Print only the output path |

### Security audit

```bash
npx crxray <url> --audit
npx crxray audit ./unpacked-extension/   # audit an existing folder
```

Prints a risk score, permission tiers, suspicious patterns (`eval`, `chrome.cookies`, etc.), network endpoints, and a **start here** file list. Writes `.crxray-audit.json` for agents.

### Deobfuscate & beautify

```bash
# Full pipeline: download → deobfuscate → beautify → audit
npx crxray <url> --deobfuscate --beautify --audit
```

- **`--deobfuscate`** — reverses obfuscator.io, unpacks webpack/browserify bundles (best-effort)
- **`--beautify`** — formats every `.js` file for reading in your editor or agent

> **Note:** `--deobfuscate` uses webcrack, which has a native optional dep (`isolated-vm`). If `npm install` fails, retry with `npm install -g crxray --ignore-scripts`. Node 18–22 LTS recommended.

### Diff two versions

```bash
npx crxray diff ./old-unpacked ./new-unpacked
npx crxray diff <url-a> <url-b>   # downloads both, then compares
```

Shows permission changes, added/removed/modified files, and new network endpoints in changed JS.

## Use with AI agents

`crxray` is designed to be agent-friendly: `npx` means no setup, `--json` means parseable output, and the unpacked source is immediately readable.

### Cursor / Claude Code skill

This repo ships an [agent skill](skill/crxray/SKILL.md) that teaches your agent to download and audit extensions when you paste a store link:

```bash
# Cursor (personal skill, all projects)
mkdir -p ~/.cursor/skills && cp -r skill/crxray ~/.cursor/skills/

# Cursor (this project only)
mkdir -p .cursor/skills && cp -r skill/crxray .cursor/skills/

# Claude Code
mkdir -p ~/.claude/skills && cp -r skill/crxray ~/.claude/skills/
```

Then just ask:

> *"Is this extension safe? https://chromewebstore.google.com/detail/..."*

and your agent will download it, read the manifest and source, and report what it actually does.

### Any other agent

No skill system? Just tell your agent:

> Run `npx -y crxray <store-url> --audit --deobfuscate --beautify --json`, then read `outDir` and `.crxray-audit.json`.

## Programmatic API

```js
import { crxray } from 'crxray';

const { outDir, summary } = await crxray(
  'https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm'
);

console.log(summary.permissions); // ['alarms', 'contextMenus', 'privacy', ...]
```

Lower-level pieces are exported too: `auditExtension`, `crxrayDiff`, `beautifyDirectory`, `deobfuscateDirectory`, `buildEntryPointMap`, `parseExtensionRef`, `downloadCrx`, `crxToZip`, `extractZip`, `readManifest`.

## How it works

1. **Parse** the extension ID out of the store URL.
2. **Download** the `.crx` from the same public update endpoint the browser itself uses (`clients2.google.com/service/update2/crx` for Chrome, `edge.microsoft.com` for Edge) — so the bytes are identical to what the store serves.
3. **Strip** the CRX header (a `Cr24` magic number plus signature block prepended to an ordinary ZIP — both CRX2 and CRX3 supported).
4. **Unpack** with a built-in zero-dependency ZIP extractor (with zip-slip protection, since you're unpacking untrusted code).
5. **Summarize** the manifest: permissions, host access, content scripts, background entry point — with `__MSG_*__` i18n placeholders resolved.

## Legal note

`crxray` downloads extensions from the stores' public endpoints — the same ones your browser hits on every update check. The unpacked code remains the property of its authors. Use it for inspection, security auditing, and learning; don't redistribute other people's code.

## License

[MIT](LICENSE)
