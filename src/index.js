import { writeFileSync, readFileSync, rmSync, existsSync, renameSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseExtensionRef } from './parse.js';
import { downloadCrx } from './download.js';
import { crxToZip, verifyCrxSignature } from './crx.js';
import { extractZip } from './zip.js';
import { readManifest, summarizeManifest } from './manifest.js';
import { auditExtension } from './audit.js';
import { buildEntryPointMap } from './map.js';
import { beautifyDirectory } from './beautify.js';
import { deobfuscateDirectory } from './deobfuscate.js';
import { unpackWithWakaru } from './wakaru.js';
import { renameWithHumanify } from './humanify.js';
import { rebuildExtension, writeProvenance } from './rebuild.js';
import { diffExtensions } from './diff.js';
import { isDirectory } from './walk.js';
import { recoverFromSourceMaps, removeSourceMaps } from './sourcemaps.js';

export { parseExtensionRef } from './parse.js';
export { downloadCrx, crxUrl } from './download.js';
export { crxToZip, verifyCrx2Signature, verifyCrx3Signature, verifyCrxSignature } from './crx.js';
export { extractZip, readZipEntries } from './zip.js';
export { readManifest, summarizeManifest } from './manifest.js';
export { auditExtension, formatAuditReport } from './audit.js';
export { buildEntryPointMap } from './map.js';
export { beautifyDirectory } from './beautify.js';
export { deobfuscateDirectory } from './deobfuscate.js';
export { unpackWithWakaru } from './wakaru.js';
export { renameWithHumanify } from './humanify.js';
export { rebuildExtension, writeProvenance } from './rebuild.js';
export { diffExtensions, formatDiffReport } from './diff.js';
export { recoverFromSourceMaps, removeSourceMaps } from './sourcemaps.js';
// Deliberately NOT wired into crxray()/processExtension()'s default pipeline below -- this is
// a separate, explicitly opt-in capability with its own CLI subcommand (never reachable via
// `crxray <url>`'s flags). See docs/behavior-capture in the plan this implements.
export { captureBehavior, DISCLAIMER as CAPTURE_BEHAVIOR_DISCLAIMER } from './behavior-capture.js';

const CRXRAY_VERSION = JSON.parse(
  readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf8')
).version;

/**
 * Download and unpack an extension.
 *
 * @param {string} input - store URL or extension ID
 * @param {object} [opts]
 * @param {string} [opts.out] - output directory (default: ./<name>-<version> or ./<id>)
 * @param {string} [opts.store] - store for bare IDs ('chrome' | 'edge')
 * @param {string} [opts.chromeVersion] - override the prodversion sent to the store's update endpoint (default goes stale as Chrome ships new versions; see src/download.js)
 * @param {boolean} [opts.crxOnly] - save the .crx and skip unpacking
 * @param {boolean} [opts.keepCrx] - also save the .crx next to the unpacked dir
 * @param {boolean} [opts.audit] - run security audit after unpack
 * @param {boolean} [opts.map] - include entry-point map (always included with audit)
 * @param {boolean} [opts.deobfuscate] - deobfuscate all JS via webcrack
 * @param {boolean} [opts.unpackWithWakaru] - structurally unpack bundles via `npx wakaru`, independent of --deobfuscate
 * @param {boolean} [opts.humanify] - rename minified identifiers via humanify (a standalone binary, not npx-able); independent of --deobfuscate/--unpack-with-wakaru but most useful after them
 * @param {string} [opts.humanifyProvider] - humanify provider: 'ollama' (default, local/free) | 'openai' | 'gemini' | 'anthropic' | 'openrouter' | 'requesty'
 * @param {string} [opts.humanifyModel] - explicit model name passed to humanify's -m; strongly recommended for 'ollama' (see src/humanify.js doc comment on model-quality variance)
 * @param {boolean} [opts.rebuild] - reassemble a clean, loadable copy into `<outDir>-rebuilt/`; runs after wakaru/deobfuscate/humanify so it sees their output
 * @param {boolean} [opts.beautify] - beautify all JS via js-beautify
 * @param {boolean} [opts.quiet] - suppress post-process logs
 * @returns {Promise<object>}
 */
export async function crxray(input, opts = {}) {
  const { id, store } = parseExtensionRef(input, opts.store ?? 'chrome');
  const crx = await downloadCrx(id, store, opts.chromeVersion);

  if (opts.crxOnly) {
    const crxPath = path.resolve(opts.out ?? `${id}.crx`);
    writeFileSync(crxPath, crx);
    return { id, store, outDir: null, crxPath, fileCount: 0, manifest: null, summary: null };
  }

  const zip = crxToZip(crx);

  const extractDir = path.resolve(`.crxray-tmp-${id}`);
  const fileCount = extractZip(zip, extractDir);

  const manifest = readManifest(extractDir);
  const summary = summarizeManifest(manifest);

  const outDir = opts.out ? path.resolve(opts.out) : path.resolve(defaultDirName(manifest, id));
  finalizeOutputDir(extractDir, outDir, opts.force);

  let crxPath = null;
  if (opts.keepCrx) {
    crxPath = path.join(path.dirname(outDir), `${path.basename(outDir)}.crx`);
    writeFileSync(crxPath, crx);
  }

  const noMaps = opts.noMaps ?? opts.audit;
  let mapsRemoved = [];
  let mapsRecovered = { recovered: [], skipped: [] };
  if (noMaps) {
    mapsRecovered = recoverFromSourceMaps(outDir);
    mapsRemoved = removeSourceMaps(outDir);
  }

  const postProcess = await runPostProcess(outDir, manifest, summary, opts, { crx, id, store });

  return {
    id,
    store,
    outDir,
    crxPath,
    fileCount: fileCount - mapsRemoved.length,
    mapsRemoved,
    mapsRecovered,
    manifest,
    summary,
    ...postProcess,
  };
}

/**
 * Audit, beautify, or deobfuscate an already-unpacked extension directory.
 */
export async function processExtension(dir, opts = {}) {
  const outDir = path.resolve(dir);
  const manifest = readManifest(outDir);
  const summary = summarizeManifest(manifest);

  const noMaps = opts.noMaps ?? opts.audit;
  let mapsRemoved = [];
  let mapsRecovered = { recovered: [], skipped: [] };
  if (noMaps) {
    mapsRecovered = recoverFromSourceMaps(outDir);
    mapsRemoved = removeSourceMaps(outDir);
  }

  const postProcess = await runPostProcess(outDir, manifest, summary, opts);
  return { outDir, manifest, summary, mapsRemoved, mapsRecovered, ...postProcess };
}

/**
 * Diff two unpacked directories, store URLs, or extension IDs.
 */
export async function crxrayDiff(left, right, opts = {}) {
  const leftDir = await resolveDiffTarget(left, opts);
  const rightDir = await resolveDiffTarget(right, opts);
  return diffExtensions(leftDir, rightDir);
}

async function resolveDiffTarget(input, opts) {
  if (isDirectory(input)) return path.resolve(input);
  const result = await crxray(input, { store: opts.store, chromeVersion: opts.chromeVersion, quiet: true });
  return result.outDir;
}

async function runPostProcess(outDir, manifest, summary, opts, { crx, id, store } = {}) {
  const result = {};

  if (opts.unpackWithWakaru) {
    result.wakaru = await unpackWithWakaru(outDir, { quiet: opts.quiet });
  }

  if (opts.deobfuscate) {
    result.deobfuscate = await deobfuscateDirectory(outDir, { quiet: opts.quiet });
  }

  // humanify runs after wakaru/deobfuscate, unlike those two (which are
  // independent of each other by design -- see wakaru.js's own doc comment):
  // it looks for the `.wakaru`/`.unpacked` siblings those steps produce to
  // decide what to rename, so it only sees them if it runs last.
  if (opts.humanify) {
    result.humanify = await renameWithHumanify(outDir, {
      quiet: opts.quiet,
      provider: opts.humanifyProvider,
      model: opts.humanifyModel,
    });
  }

  if (opts.beautify) {
    result.beautify = beautifyDirectory(outDir, { quiet: opts.quiet });
  }

  if (opts.rebuild) {
    const rebuildOutDir = path.join(path.dirname(outDir), `${path.basename(outDir)}-rebuilt`);
    result.rebuild = rebuildExtension(outDir, rebuildOutDir, manifest, { quiet: opts.quiet });
    result.rebuild.outDir = rebuildOutDir;
    // Reuses the crx bytes already in memory from this same run (when a
    // fresh download preceded this, i.e. via crxray() not processExtension())
    // -- no new network call, no new trust assumption, see writeProvenance's
    // own doc comment. Independent of opts.audit: provenance shouldn't
    // silently depend on whether --audit was also passed.
    const signature = crx && id ? verifyCrxSignature(crx, id) : null;
    result.rebuild.provenance = writeProvenance(rebuildOutDir, {
      extensionId: id ?? null,
      version: manifest?.version ?? null,
      store: store ?? null,
      crx: crx ?? null,
      signature,
      crxrayVersion: CRXRAY_VERSION,
    });
  }

  if (opts.map || opts.audit) {
    result.map = buildEntryPointMap(outDir, manifest);
  }

  if (opts.audit) {
    result.audit = auditExtension(outDir, manifest, summary);
    if (crx && id) {
      result.audit.signature = verifyCrxSignature(crx, id);
    }
    writeFileSync(path.join(outDir, '.crxray-audit.json'), JSON.stringify(result.audit, null, 2));
  }

  return result;
}

export function finalizeOutputDir(extractDir, outDir, force) {
  if (existsSync(outDir)) {
    if (!force) {
      rmSync(extractDir, { recursive: true });
      throw new Error(
        `${path.relative(process.cwd(), outDir) || outDir} already exists. ` +
          'Pass --out <other-dir> to pick a different location, or --force to overwrite it.'
      );
    }
    rmSync(outDir, { recursive: true });
  }
  renameSync(extractDir, outDir);
}

function defaultDirName(manifest, id) {
  if (!manifest?.name) return id;
  const slug = manifest.name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
  if (!slug) return id;
  return manifest.version ? `${slug}-${manifest.version}` : slug;
}
