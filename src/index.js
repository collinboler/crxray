import { writeFileSync, rmSync, existsSync, renameSync } from 'node:fs';
import path from 'node:path';
import { parseExtensionRef } from './parse.js';
import { downloadCrx } from './download.js';
import { crxToZip } from './crx.js';
import { extractZip } from './zip.js';
import { readManifest, summarizeManifest } from './manifest.js';

export { parseExtensionRef } from './parse.js';
export { downloadCrx, crxUrl } from './download.js';
export { crxToZip } from './crx.js';
export { extractZip, readZipEntries } from './zip.js';
export { readManifest, summarizeManifest } from './manifest.js';

/**
 * Download and unpack an extension.
 *
 * @param {string} input - store URL or extension ID
 * @param {object} [opts]
 * @param {string} [opts.out] - output directory (default: ./<name>-<version> or ./<id>)
 * @param {string} [opts.store] - store for bare IDs ('chrome' | 'edge')
 * @param {boolean} [opts.crxOnly] - save the .crx and skip unpacking
 * @param {boolean} [opts.keepCrx] - also save the .crx next to the unpacked dir
 * @returns {Promise<{id, store, outDir, crxPath, fileCount, manifest, summary}>}
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

  // Unpack to a temp name first so we can rename based on the manifest.
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

  return { id, store, outDir, crxPath, fileCount, manifest, summary };
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
