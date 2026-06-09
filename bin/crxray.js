#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  crxray,
  crxrayDiff,
  processExtension,
  formatAuditReport,
  formatDiffReport,
} from '../src/index.js';

const HELP = `crxray — download Chrome & Edge extension source code from a store link

Usage:
  crxray <store-url-or-extension-id> [options]
  crxray diff <left> <right> [options]
  crxray audit <unpacked-directory> [options]

Download options:
  -o, --out <dir>       Output directory (default: ./<name>-<version>)
      --store <name>    Store for bare IDs: chrome (default) or edge
      --crx-only        Save the raw .crx file, skip unpacking
      --keep-crx        Keep the .crx alongside the unpacked source
      --audit           Security audit + entry-point map (writes .crxray-audit.json)
      --map             Entry-point map and readability stats only
      --deobfuscate     Deobfuscate all JS (webcrack: obfuscator.io, webpack, etc.)
      --beautify        Beautify all JS files
      --no-maps         Delete .map source maps (on by default with --audit)
      --keep-maps       Keep source maps even when using --audit
      --json            Machine-readable JSON output
  -q, --quiet           Only print paths / suppress post-process logs

Diff options:
  crxray diff <dir-or-url> <dir-or-url>   Compare two unpacked dirs or download both

Examples:
  npx crxray https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh
  npx crxray <url> --audit --deobfuscate --beautify
  npx crxray diff ./old-version ./new-version
  npx crxray audit ./some-extension/ --json`;

function fail(msg) {
  console.error(`crxray: ${msg}`);
  process.exit(1);
}

const sharedOptions = {
  store: { type: 'string' },
  json: { type: 'boolean' },
  quiet: { type: 'boolean', short: 'q' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean', short: 'v' },
};

let args;
try {
  args = parseArgs({
    allowPositionals: true,
    options: {
      ...sharedOptions,
      out: { type: 'string', short: 'o' },
      'crx-only': { type: 'boolean' },
      'keep-crx': { type: 'boolean' },
      audit: { type: 'boolean' },
      map: { type: 'boolean' },
      deobfuscate: { type: 'boolean' },
      beautify: { type: 'boolean' },
      'no-maps': { type: 'boolean' },
      'keep-maps': { type: 'boolean' },
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

if (values.help) {
  console.log(HELP);
  process.exit(0);
}

if (values.store && !['chrome', 'edge'].includes(values.store)) {
  fail(`--store must be "chrome" or "edge", got "${values.store}"`);
}

const command = positionals[0];

try {
  if (command === 'diff') {
    await runDiff(positionals.slice(1), values);
  } else if (command === 'audit') {
    await runAudit(positionals.slice(1), values);
  } else if (positionals.length === 0) {
    console.log(HELP);
    process.exit(1);
  } else {
    await runDownload(positionals[0], values);
  }
} catch (err) {
  fail(err.message);
}

function mapOpts(values) {
  return {
    noMaps: values['keep-maps'] ? false : values['no-maps'] || values.audit,
  };
}

async function runDownload(input, values) {
  const result = await crxray(input, {
    out: values.out,
    store: values.store,
    crxOnly: values['crx-only'],
    keepCrx: values['keep-crx'],
    audit: values.audit,
    map: values.map,
    deobfuscate: values.deobfuscate,
    beautify: values.beautify,
    quiet: values.quiet,
    ...mapOpts(values),
  });

  if (values.json) {
    const { manifest, ...rest } = result;
    console.log(JSON.stringify(rest, null, 2));
    return;
  }

  if (values.quiet) {
    console.log(result.crxPath ?? result.outDir);
    return;
  }

  if (values['crx-only']) {
    console.log(`Saved ${result.crxPath}`);
    return;
  }

  printSummary(result);
  if (result.mapsRemoved?.length) {
    console.log(`Removed ${result.mapsRemoved.length} source map(s) (use --keep-maps to retain)`);
  }
  if (result.audit) {
    console.log('');
    console.log(formatAuditReport(result.audit));
  } else if (result.map && values.map) {
    console.log('');
    console.log('Start here');
    for (const p of result.map.startHere) console.log(`  ${p}`);
  }

  if (result.deobfuscate && !values.quiet) {
    console.log('');
    console.log(
      `Deobfuscated ${result.deobfuscate.changed} files (${result.deobfuscate.unpacked} bundles unpacked)`
    );
  }
  if (result.beautify && !values.quiet) {
    console.log(`Beautified ${result.beautify.changed} files`);
  }
}

async function runAudit(args, values) {
  const dir = args[0];
  if (!dir) fail('audit requires a directory: crxray audit <unpacked-directory>');

  const result = await processExtension(dir, {
    audit: true,
    map: true,
    deobfuscate: values.deobfuscate,
    beautify: values.beautify,
    quiet: values.quiet,
    ...mapOpts({ ...values, audit: true }),
  });

  if (values.json) {
    const { manifest, ...rest } = result;
    console.log(JSON.stringify(rest, null, 2));
    return;
  }

  console.log(formatAuditReport(result.audit));
}

async function runDiff(args, values) {
  const [left, right] = args;
  if (!left || !right) fail('diff requires two targets: crxray diff <left> <right>');

  const diff = await crxrayDiff(left, right, { store: values.store });

  if (values.json) {
    console.log(JSON.stringify(diff, null, 2));
    return;
  }

  console.log(formatDiffReport(diff));
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
