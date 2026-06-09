# crxray

> X-ray any Chrome or Edge extension — download and unpack its full source code from just the store link.

[![npm](https://img.shields.io/npm/v/crxray)](https://www.npmjs.com/package/crxray)
[![CI](https://github.com/collinboler/crxray/actions/workflows/test.yml/badge.svg)](https://github.com/collinboler/crxray/actions/workflows/test.yml)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
![node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)

The Chrome Web Store has no download button. But every extension is just a ZIP file sitting behind Google's own update endpoint. `crxray` fetches it, strips the CRX signature header, and unpacks the source — so you (or your AI agent) can read exactly what an extension does **before** trusting it with `<all_urls>`.

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

**Zero dependencies. Zero install. Node 18+.**

## Why

- **Audit before installing** — extensions run with terrifying permissions. Read the actual code, not the store blurb.
- **Built for AI agents** — paste a store link into Cursor, Claude Code, or any agent and let it review the source for you ([see below](#use-with-ai-agents)).
- **Learn from the best** — see how popular extensions are actually built.
- **Rescue abandoned extensions** — recover source when the author and repo have vanished.

## Usage

```bash
# Chrome Web Store URL (current or legacy format)
npx crxray https://chromewebstore.google.com/detail/<slug>/<id>

# Edge Add-ons URL
npx crxray https://microsoftedge.microsoft.com/addons/detail/<slug>/<id>

# Bare extension ID
npx crxray cjpalhdlnbpafiamejdnhcphjbkeiagm
```

### Options

| Flag | Description |
|------|-------------|
| `-o, --out <dir>` | Output directory (default: `./<name>-<version>/`) |
| `--store <name>` | Store for bare IDs: `chrome` (default) or `edge` |
| `--crx-only` | Save the raw `.crx` file, skip unpacking |
| `--keep-crx` | Keep the `.crx` alongside the unpacked source |
| `--json` | Machine-readable output (for scripts and agents) |
| `-q, --quiet` | Print only the output path |

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

> Run `npx -y crxray <store-url> --json`, then read the unpacked source in the reported `outDir`.

## Programmatic API

```js
import { crxray } from 'crxray';

const { outDir, summary } = await crxray(
  'https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm'
);

console.log(summary.permissions); // ['alarms', 'contextMenus', 'privacy', ...]
```

Lower-level pieces are exported too: `parseExtensionRef`, `downloadCrx`, `crxToZip`, `extractZip`, `readManifest`.

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
