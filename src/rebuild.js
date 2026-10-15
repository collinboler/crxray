import { mkdirSync, cpSync, existsSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { isDirectory, relPath, walkFiles, isWakaruOutput, isHumanifyOutput } from './walk.js';

/**
 * Reassemble a clean, loadable copy of an extension from an unpacked (and
 * optionally deobfuscated/wakaru'd/humanify'd) source directory.
 *
 * File selection, per referenced path, in priority order:
 *  1. A `<name>.unpacked/` or `<name>.wakaru/` sibling directory (a bundle a
 *     prior deobfuscate/wakaru step decomposed into multiple readable
 *     modules) -- the ORIGINAL file is copied as-is (it is what the
 *     manifest actually loads and still functions exactly as the store
 *     served it), and the decomposition travels alongside it as read-only
 *     reference material. No attempt is made to splice the decomposition
 *     back into a single replacement script: recon ahead of this feature
 *     (2026-10-10) found no tool that does this reliably -- the one that
 *     tries end-to-end (JSimplifier) silently corrupted a return value on a
 *     trivial, non-adversarial test, and the one that partially works
 *     (retidy) only covers pre-webpack5 bundles. Shipping a "duplicate"
 *     that might silently behave differently is worse than shipping the
 *     original plus honest reference material.
 *  2. A `<name>.humanify.js` sibling (a behavior-preserving, AST-level
 *     rename -- see src/humanify.js) when no bundle decomposition exists.
 *  3. The file itself, which may already be deobfuscated in place by a
 *     prior non-bundle webcrack pass.
 *
 * A manifest-referenced file that does not exist on disk (e.g. injected as
 * an inline string rather than shipped as a static file) is reported in
 * `missing`, never silently dropped.
 */
export function rebuildExtension(dir, outDir, manifest, { quiet = false } = {}) {
  const results = { copied: 0, renamed: 0, referenceOnly: [], missing: [], errors: [] };

  if (!manifest) {
    results.errors.push('no manifest.json found in source directory -- cannot rebuild');
    return results;
  }

  mkdirSync(outDir, { recursive: true });
  copyInto(path.join(dir, 'manifest.json'), path.join(outDir, 'manifest.json'));
  results.copied++;

  const localesDir = path.join(dir, '_locales');
  if (isDirectory(localesDir)) {
    cpSync(localesDir, path.join(outDir, '_locales'), { recursive: true });
  }

  for (const ref of collectReferencedFiles(manifest)) {
    const matches = isGlobPattern(ref) ? expandGlob(dir, ref) : [ref];
    if (matches.length === 0) {
      results.missing.push(ref);
      continue;
    }

    for (const rel of matches) copyReferencedFile(dir, outDir, rel, results);
  }

  if (results.missing.length && !quiet) {
    console.error(`rebuild: ${results.missing.length} manifest-referenced file(s) missing: ${results.missing.join(', ')}`);
  }

  return results;
}

function copyReferencedFile(dir, outDir, rel, results) {
  const srcPath = path.join(dir, rel);
  if (!existsSync(srcPath)) {
    results.missing.push(rel);
    return;
  }

  const bundleDir = findBundleOutputDir(srcPath);
  if (bundleDir) {
    copyInto(srcPath, path.join(outDir, rel));
    cpSync(bundleDir, path.join(outDir, relPath(dir, bundleDir)), { recursive: true });
    results.referenceOnly.push(rel);
    results.copied++;
    return;
  }

  const humanifyPath = humanifySiblingOf(srcPath);
  if (humanifyPath) {
    copyInto(humanifyPath, path.join(outDir, rel));
    results.renamed++;
  } else {
    copyInto(srcPath, path.join(outDir, rel));
  }
  results.copied++;
}

/**
 * Write REBUILD-PROVENANCE.json into a rebuilt directory: a chain-of-custody
 * record tying the rebuild back to the original download it was derived
 * from. Every field comes from values the caller already computed earlier
 * in the same run (the crx buffer already in memory, the signature check
 * already run) -- no new network call and no new trust assumption is
 * introduced by this step, it only serializes what's already known. A field
 * with nothing to report (no crx bytes available, e.g. a --rebuild run
 * against an already-unpacked directory with no .crx in memory) is recorded
 * as null, never fabricated.
 */
export function writeProvenance(outDir, { extensionId, version, store, crx, signature, crxrayVersion }) {
  const provenance = {
    extensionId: extensionId ?? null,
    version: version ?? null,
    store: store ?? null,
    originalCrxSha256: crx ? createHash('sha256').update(crx).digest('hex') : null,
    signature: signature ?? null,
    crxrayVersion: crxrayVersion ?? null,
    generatedAt: new Date().toISOString(),
  };
  writeFileSync(path.join(outDir, 'REBUILD-PROVENANCE.json'), JSON.stringify(provenance, null, 2));
  return provenance;
}

function copyInto(src, dest) {
  mkdirSync(path.dirname(dest), { recursive: true });
  cpSync(src, dest);
}

function findBundleOutputDir(srcPath) {
  if (!srcPath.endsWith('.js')) return null;
  const base = srcPath.slice(0, -'.js'.length);
  for (const suffix of ['.unpacked', '.wakaru']) {
    const candidate = base + suffix;
    if (isDirectory(candidate)) return candidate;
  }
  return null;
}

function humanifySiblingOf(srcPath) {
  if (!srcPath.endsWith('.js')) return null;
  const candidate = srcPath.slice(0, -'.js'.length) + '.humanify.js';
  return existsSync(candidate) ? candidate : null;
}

// web_accessible_resources.resources commonly ships glob patterns, e.g. the
// real React Developer Tools extension ships "build/*.js" -- confirmed
// running --rebuild against it for real (2026-10-10), not a hypothetical.
function isGlobPattern(ref) {
  return ref.includes('*');
}

// `*` matches any run of characters, including `/` -- simple and sufficient
// for the one real case found (a flat build output directory); a pattern
// language beyond single-star globbing is not something crxray's own
// manifest reading has needed anywhere else.
function expandGlob(dir, pattern) {
  const re = new RegExp('^' + pattern.split('*').map(escapeRegex).join('.*') + '$');
  return walkFiles(dir, {})
    .filter((file) => !isWakaruOutput(file) && !isHumanifyOutput(file) && !isInsideUnpackedDir(file))
    .map((file) => relPath(dir, file))
    .filter((rel) => re.test(rel));
}

// webcrack's `<name>.unpacked/` output (unlike wakaru's `.wakaru/`, which
// isWakaruOutput already identifies) has no existing helper in walk.js --
// its contents must not be matched as if they were independently shipped
// resources a glob pattern happens to also match.
function isInsideUnpackedDir(file) {
  return file.split(path.sep).some((seg) => seg.endsWith('.unpacked'));
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Every manifest field that points at a file crxray knows how to read,
 * across MV2 and MV3 shapes. Returns deduplicated relative paths.
 */
function collectReferencedFiles(manifest) {
  const refs = new Set();
  const add = (p) => {
    if (typeof p === 'string' && p) refs.add(p.replace(/^\/+/, ''));
  };
  const addAll = (arr) => {
    if (Array.isArray(arr)) arr.forEach(add);
  };
  const addIconMap = (icons) => {
    if (icons && typeof icons === 'object') Object.values(icons).forEach(add);
  };

  if (manifest.background?.service_worker) add(manifest.background.service_worker);
  addAll(manifest.background?.scripts);
  if (manifest.background?.page) add(manifest.background.page);

  for (const cs of manifest.content_scripts ?? []) {
    addAll(cs.js);
    addAll(cs.css);
  }

  addIconMap(manifest.icons);
  for (const key of ['action', 'browser_action', 'page_action']) {
    const a = manifest[key];
    if (!a) continue;
    if (a.default_popup) add(a.default_popup);
    if (typeof a.default_icon === 'string') add(a.default_icon);
    else addIconMap(a.default_icon);
  }

  if (manifest.options_page) add(manifest.options_page);
  if (manifest.options_ui?.page) add(manifest.options_ui.page);
  if (manifest.devtools_page) add(manifest.devtools_page);
  addIconMap(manifest.chrome_url_overrides); // values are page paths, same {key: path} shape as an icon map
  addAll(manifest.sandbox?.pages);

  for (const war of manifest.web_accessible_resources ?? []) {
    if (typeof war === 'string') add(war); // MV2: flat strings
    else addAll(war.resources); // MV3: { resources: [...], matches: [...] }
  }

  return [...refs];
}
