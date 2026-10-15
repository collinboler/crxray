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
  captureBehavior,
  CAPTURE_BEHAVIOR_DISCLAIMER,
} from '../src/index.js';

const HELP = `crxray — download Chrome & Edge extension source code from a store link

Usage:
  crxray <store-url-or-extension-id> [options]
  crxray diff <left> <right> [options]
  crxray audit <unpacked-directory> [options]

Download options:
  -o, --out <dir>       Output directory (default: ./<name>-<version>)
      --store <name>    Store for bare IDs: chrome (default) or edge
      --chrome-version <ver>  Override the prodversion sent to the store's
                        update endpoint (default goes stale as Chrome ships
                        new versions, which can make current extensions that
                        require a newer Chrome report as "not found")
      --crx-only        Save the raw .crx file, skip unpacking
      --keep-crx        Keep the .crx alongside the unpacked source
      --force           Overwrite the output directory if it already exists
      --audit           Security audit + entry-point map (writes .crxray-audit.json)
      --map             Entry-point map and readability stats only
      --deobfuscate     Deobfuscate all JS (webcrack: obfuscator.io, webpack, etc.)
      --unpack-with-wakaru  Structurally unpack bundles with wakaru (npx), independent of --deobfuscate
      --humanify        Rename minified identifiers via humanify (a standalone
                        binary you must install yourself -- see
                        github.com/jehna/humanify/releases -- not npx-able).
                        Best after --deobfuscate/--unpack-with-wakaru.
      --humanify-provider <name>  ollama (default, local/free) | openai |
                        gemini | anthropic | openrouter | requesty
      --humanify-model <name>    Explicit model for --humanify-provider.
                        Strongly recommended for ollama: an 8B-class local
                        model gives usable names, a ~1.5B model does not.
      --rebuild         Reassemble a clean, loadable copy into
                        <outdir>-rebuilt/ (manifest + every referenced file).
                        A bundle a prior --deobfuscate/--unpack-with-wakaru
                        pass split into modules ships as-is alongside its
                        readable decomposition, not spliced back together --
                        see the "rebuild/duplicate gap" plan for why. Runs
                        after --deobfuscate/--unpack-with-wakaru/--humanify.
                        Also writes REBUILD-PROVENANCE.json into the output
                        (original extension ID/version, the original CRX's
                        sha256, and its CRX2/CRX3 signature verification
                        result) so a rebuilt copy's chain of custody back to
                        the verified download is on record.
      --beautify        Beautify all JS files
      --no-maps         Delete .map source maps (on by default with --audit)
      --keep-maps       Keep source maps even when using --audit
      --json            Machine-readable JSON output
  -q, --quiet           Only print paths / suppress post-process logs

Diff options:
  crxray diff <dir-or-url> <dir-or-url>   Compare two unpacked dirs or download both

Behavior capture (opt-in; never runs as part of a plain download):
  crxray capture-behavior <extension-dir> --scenario <file> [options]
      --scenario <file>   JSON scenario file ({"steps": [...]})-- see docs.
      --yes-i-reviewed-permissions  Required: confirms you reviewed this
                        extension's requested permissions (crxray audit)
                        before letting it run in a real browser.
      --timeout-ms <n>  Hard wall-clock cap for the scenario (default 60000).
  -o, --out <file>      Capture file path (default: <dir>-capture.json)

${CAPTURE_BEHAVIOR_DISCLAIMER}

Examples:
  npx crxray https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh
  npx crxray <url> --audit --deobfuscate --beautify
  npx crxray diff ./old-version ./new-version
  npx crxray audit ./some-extension/ --json
  npx crxray capture-behavior ./some-extension/ --scenario scenario.json --yes-i-reviewed-permissions`;

function fail(msg) {
  console.error(`crxray: ${msg}`);
  process.exit(1);
}

const sharedOptions = {
  store: { type: 'string' },
  'chrome-version': { type: 'string' },
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
      force: { type: 'boolean' },
      audit: { type: 'boolean' },
      map: { type: 'boolean' },
      deobfuscate: { type: 'boolean' },
      'unpack-with-wakaru': { type: 'boolean' },
      humanify: { type: 'boolean' },
      'humanify-provider': { type: 'string' },
      'humanify-model': { type: 'string' },
      rebuild: { type: 'boolean' },
      beautify: { type: 'boolean' },
      'no-maps': { type: 'boolean' },
      'keep-maps': { type: 'boolean' },
      scenario: { type: 'string' },
      'yes-i-reviewed-permissions': { type: 'boolean' },
      'timeout-ms': { type: 'string' },
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
  } else if (command === 'capture-behavior') {
    await runCaptureBehavior(positionals.slice(1), values);
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
    chromeVersion: values['chrome-version'],
    crxOnly: values['crx-only'],
    keepCrx: values['keep-crx'],
    force: values.force,
    audit: values.audit,
    map: values.map,
    deobfuscate: values.deobfuscate,
    unpackWithWakaru: values['unpack-with-wakaru'],
    humanify: values.humanify,
    humanifyProvider: values['humanify-provider'],
    humanifyModel: values['humanify-model'],
    rebuild: values.rebuild,
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
    const recoveredCount = result.mapsRecovered?.recovered.reduce((sum, r) => sum + r.fileCount, 0) ?? 0;
    console.log(
      `Removed ${result.mapsRemoved.length} source map(s)` +
        (recoveredCount ? `, recovered ${recoveredCount} original source file(s) first` : '') +
        ' (use --keep-maps to retain)'
    );
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
  if (result.wakaru && !values.quiet) {
    console.log('');
    console.log(
      `Unpacked ${result.wakaru.unpacked} bundle(s) with wakaru (${result.wakaru.errors.length} failed)`
    );
  }
  if (result.humanify && !values.quiet) {
    console.log('');
    console.log(
      `Renamed identifiers in ${result.humanify.renamed} file(s) with humanify (${result.humanify.errors.length} failed)`
    );
  }
  if (result.rebuild && !values.quiet) {
    console.log('');
    const rel = path.relative(process.cwd(), result.rebuild.outDir) || result.rebuild.outDir;
    console.log(
      `Rebuilt ${result.rebuild.copied} file(s) to ${rel}/` +
        (result.rebuild.missing.length ? ` (${result.rebuild.missing.length} referenced file(s) missing: ${result.rebuild.missing.join(', ')})` : '') +
        (result.rebuild.referenceOnly.length ? ` (${result.rebuild.referenceOnly.length} bundle(s) shipped as-is with readable reference material alongside)` : '')
    );
    const sig = result.rebuild.provenance?.signature;
    if (sig) {
      console.log(`Provenance: ${sig.verified ? `✅ verified store-signed CRX${sig.version}` : `⚠️ unverifiable (${sig.reason})`} (REBUILD-PROVENANCE.json)`);
    }
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
    unpackWithWakaru: values['unpack-with-wakaru'],
    humanify: values.humanify,
    humanifyProvider: values['humanify-provider'],
    humanifyModel: values['humanify-model'],
    rebuild: values.rebuild,
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

async function runCaptureBehavior(args, values) {
  const dir = args[0];
  if (!dir) fail('capture-behavior requires a directory: crxray capture-behavior <extension-dir> --scenario <file>');
  if (!values.scenario) fail('capture-behavior requires --scenario <file>');

  const result = await captureBehavior(dir, values.scenario, {
    outFile: values.out,
    yesIReviewedPermissions: values['yes-i-reviewed-permissions'],
    timeoutMs: values['timeout-ms'] ? Number(values['timeout-ms']) : undefined,
    quiet: values.quiet,
  });

  if (values.json) {
    console.log(JSON.stringify(result.capture, null, 2));
    return;
  }

  console.log(`Captured ${result.capture.events.length} event(s) to ${result.outFile}`);
  console.log(`${result.capture.limitations.length} limitation(s) recorded -- see the capture file's "limitations" field.`);
  if (result.timedOut) console.log('Scenario timed out before completing; the capture reflects whatever was observed before the cutoff.');
}

async function runDiff(args, values) {
  const [left, right] = args;
  if (!left || !right) fail('diff requires two targets: crxray diff <left> <right>');

  const diff = await crxrayDiff(left, right, { store: values.store, chromeVersion: values['chrome-version'] });

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
