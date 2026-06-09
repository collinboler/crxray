---
name: crxray
description: Download Chrome and Edge extension source code in one command from a store link or extension ID. Use when the user pastes a Chrome Web Store or Edge Add-ons URL, asks to download extension source code, get the source of an extension, unpack a CRX, inspect, audit, review, or read what a browser extension does, or asks about extension permissions or safety.
---

# crxray — download extension source code

The easiest way to get the full source code of any Chrome or Edge extension. Paste a store link, run one command, get every file unpacked locally. No install needed — run via `npx`.

## Quick start

```bash
npx -y crxray <store-url-or-extension-id>
```

This downloads the CRX, unpacks it to `./<name>-<version>/`, and prints the extension's name, version, manifest version, permissions, host permissions, background script, and content scripts.

Accepted inputs:

- `https://chromewebstore.google.com/detail/<slug>/<id>` (current Chrome Web Store)
- `https://chrome.google.com/webstore/detail/<slug>/<id>` (legacy)
- `https://microsoftedge.microsoft.com/addons/detail/<slug>/<id>` (Edge Add-ons)
- A bare 32-character extension ID (add `--store edge` for Edge IDs)

## Useful flags

| Flag | Effect |
|------|--------|
| `--json` | Machine-readable result: output dir, file count, permission summary. Prefer this when scripting. |
| `-o <dir>` | Choose the output directory |
| `--crx-only` | Save the raw `.crx` without unpacking |
| `-q` | Print only the output path |

## Auditing an unpacked extension

After unpacking, a typical security/behavior review:

1. Read `manifest.json` first — permissions, host permissions, content scripts, background entry point.
2. Check the highest-risk surfaces: `<all_urls>` host access, `webRequest`, `cookies`, `tabs`, `scripting`, `nativeMessaging`, `clipboardRead`.
3. Grep the source for exfiltration patterns: `fetch(`, `XMLHttpRequest`, `chrome.cookies`, `eval(`, `atob(`, hardcoded third-party domains.
4. Note that store-distributed code is usually minified; trace data flow rather than judging readability.

## Notes

- Requires Node 18+. The CLI is dependency-free.
- The download uses the browsers' own public update endpoints, so the fetched CRX is byte-identical to what the store serves.
- If an extension is unlisted/removed the store returns 204 and crxray reports "not found".
- Extension code belongs to its authors. Unpack for inspection, auditing, and learning — do not redistribute.
