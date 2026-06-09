import { writeFileSync, rmSync, existsSync, renameSync } from 'node:fs';
import path from 'node:path';
import { parseExtensionRef } from './parse.js';
import { downloadCrx } from './download.js';
import { crxToZip } from './crx.js';
import { extractZip } from './zip.js';
import { readManifest, summarizeManifest } from './manifest.js';
import { auditExtension } from './audit.js';
import { buildEntryPointMap } from './map.js';
import { beautifyDirectory } from './beautify.js';
import { deobfuscateDirectory } from './deobfuscate.js';
import { diffExtensions } from './diff.js';
import { isDirectory } from './walk.js';

export { parseExtensionRef } from './parse.js';
export { downloadCrx, crxUrl } from './download.js';
export { crxToZip } from './crx.js';
export { extractZip, readZipEntries } from './zip.js';
export { readManifest, summarizeManifest } from './manifest.js';
export { auditExtension, formatAuditReport } from './audit.js';
export { buildEntryPointMap } from './map.js';
export { beautifyDirectory } from './beautify.js';
export { deobfuscateDirectory } from './deobfuscate.js';
export { diffExtensions, formatDiffReport } from './diff.js';

/**
 * Download and unpack an extension.
 *
 * @param {string} input - store URL or extension ID
 * @param {object} [opts]
 * @param {string} [opts.out] - output directory (default: ./<name>-<version> or ./<id>)
 * @param {string} [opts.store] - store for bare IDs ('chrome' | 'edge')
 * @param {boolean} [opts.crxOnly] - save the .crx and skip unpacking
 * @param {boolean} [opts.keepCrx] - also save the .crx next to the unpacked dir
 * @param {boolean} [opts.audit] - run security audit after unpack
 * @param {boolean} [opts.map] - include entry-point map (always included with audit)
 * @param {boolean} [opts.deobfuscate] - deobfuscate all JS via webcrack
 * @param {boolean} [opts.beautify] - beautify all JS via js-beautify
 * @param {boolean} [opts.quiet] - suppress post-process logs
 * @returns {Promise<object>}
 */
export async function crxray(input, opts = {}) {
  const { id, store } = parseExtensionRef(input, opts.store ?? 'chrome');
  const crx = await downloadCrx(id, store);

  if (opts.crxOnly) {
    const crxPath = path.resolve(opts.out ?? `${id}.crx`);
    writeFileSync(crxPath, crx);
    return { id, store, outDir: null, crxPath, fileCount: 0, manifest: null, summary: null };
  }

  const zip = crxToZip(crx);

  let outDir = opts.out ? path.resolve(opts.out) : null;
  const extractDir = outDir ?? path.resolve(`.crxray-tmp-${id}`);
  const fileCount = extractZip(zip, extractDir);

  const manifest = readManifest(extractDir);
  const summary = summarizeManifest(manifest);

  if (!outDir) {
    outDir = path.resolve(defaultDirName(manifest, id));
    if (existsSync(outDir)) rmSync(outDir, { recursive: true });
    renameSync(extractDir, outDir);
  }

  let crxPath = null;
  if (opts.keepCrx) {
    crxPath = path.join(path.dirname(outDir), `${path.basename(outDir)}.crx`);
    writeFileSync(crxPath, crx);
  }

  const postProcess = await runPostProcess(outDir, manifest, summary, opts);

  return {
    id,
    store,
    outDir,
    crxPath,
    fileCount,
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
  const postProcess = await runPostProcess(outDir, manifest, summary, opts);
  return { outDir, manifest, summary, ...postProcess };
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
  const result = await crxray(input, { store: opts.store, quiet: true });
  return result.outDir;
}

async function runPostProcess(outDir, manifest, summary, opts) {
  const result = {};

  if (opts.deobfuscate) {
    result.deobfuscate = await deobfuscateDirectory(outDir, { quiet: opts.quiet });
  }

  if (opts.beautify) {
    result.beautify = beautifyDirectory(outDir, { quiet: opts.quiet });
  }

  if (opts.map || opts.audit) {
    result.map = buildEntryPointMap(outDir, manifest);
  }

  if (opts.audit) {
    result.audit = auditExtension(outDir, manifest, summary);
    writeFileSync(path.join(outDir, '.crxray-audit.json'), JSON.stringify(result.audit, null, 2));
  }

  return result;
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
