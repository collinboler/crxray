#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { crxray } from '../src/index.js';

const HELP = `crxray — x-ray any Chrome or Edge extension from its store link

Usage:
  crxray <store-url-or-extension-id> [options]

Options:
  -o, --out <dir>     Output directory (default: ./<name>-<version>)
      --store <name>  Store for bare IDs: chrome (default) or edge
      --crx-only      Save the raw .crx file, skip unpacking
      --keep-crx      Keep the .crx alongside the unpacked source
      --json          Print machine-readable JSON (for scripts and agents)
  -q, --quiet         Only print the output path
  -h, --help          Show this help
  -v, --version       Show version

Examples:
  npx crxray https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh
  npx crxray cjpalhdlnbpafiamejdnhcphjbkeiagm --json
  npx crxray https://microsoftedge.microsoft.com/addons/detail/odfafepnkmbhccpbejgmiehpchacaeak -o ./ublock`;

function fail(msg) {
  console.error(`crxray: ${msg}`);
  process.exit(1);
}

let args;
try {
  args = parseArgs({
    allowPositionals: true,
    options: {
      out: { type: 'string', short: 'o' },
      store: { type: 'string' },
      'crx-only': { type: 'boolean' },
      'keep-crx': { type: 'boolean' },
      json: { type: 'boolean' },
      quiet: { type: 'boolean', short: 'q' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });
} catch (err) {
  fail(err.message);
}

const { values, positionals } = args;

if (values.version) {
  const pkgPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'package.json');
  console.log(JSON.parse(readFileSync(pkgPath, 'utf8')).version);
  process.exit(0);
}

if (values.help || positionals.length === 0) {
  console.log(HELP);
  process.exit(values.help ? 0 : 1);
}

if (values.store && !['chrome', 'edge'].includes(values.store)) {
  fail(`--store must be "chrome" or "edge", got "${values.store}"`);
}

try {
  const result = await crxray(positionals[0], {
    out: values.out,
    store: values.store,
    crxOnly: values['crx-only'],
    keepCrx: values['keep-crx'],
  });

  if (values.json) {
    const { manifest, ...rest } = result;
    console.log(JSON.stringify(rest, null, 2));
  } else if (values.quiet) {
    console.log(result.crxPath ?? result.outDir);
  } else if (values['crx-only']) {
    console.log(`Saved ${result.crxPath}`);
  } else {
    printSummary(result);
  }
} catch (err) {
  fail(err.message);
}

function printSummary({ id, store, outDir, crxPath, fileCount, summary }) {
  const rel = (p) => path.relative(process.cwd(), p) || '.';
  console.log(`Unpacked ${fileCount} files to ${rel(outDir)}/`);
  if (crxPath) console.log(`Kept CRX at ${rel(crxPath)}`);
  if (!summary) return;

  console.log('');
  console.log(`  ${summary.name ?? id}  v${summary.version ?? '?'}  (MV${summary.manifestVersion ?? '?'}, ${store})`);
  if (summary.description) console.log(`  ${summary.description}`);
  console.log('');

  const list = (label, items) => {
    if (items?.length) console.log(`  ${label}: ${items.join(', ')}`);
  };
  list('Permissions', summary.permissions);
  list('Optional permissions', summary.optionalPermissions);
  list('Host permissions', summary.hostPermissions);
  if (summary.background) console.log(`  Background: ${summary.background}`);
  for (const cs of summary.contentScripts) {
    console.log(`  Content script: [${cs.js.join(', ')}] on ${cs.matches.join(', ')}`);
  }
}
