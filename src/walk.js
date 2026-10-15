import { readdirSync, statSync, existsSync } from 'node:fs';
import path from 'node:path';

// Chrome/Edge extensions are shallow, small trees. These caps catch a
// pathological input (deep nesting, huge file count) before it can
// stack-overflow or run away during audit/map/diff.
const MAX_FILES = 50_000;
const MAX_DEPTH = 64;

/**
 * Recursively list files under dir, optionally filtered by extension.
 */
export function walkFiles(dir, { extensions = null, maxFiles = MAX_FILES, maxDepth = MAX_DEPTH } = {}) {
  const results = [];
  walk(dir, extensions, 0, results, maxFiles, maxDepth);
  return results;
}

function walk(dir, extensions, depth, results, maxFiles, maxDepth) {
  if (depth > maxDepth) {
    throw new Error(`walkFiles: directory nesting exceeds ${maxDepth} levels under ${dir} — refusing to recurse further.`);
  }
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, extensions, depth + 1, results, maxFiles, maxDepth);
    } else if (!extensions || extensions.some((ext) => entry.name.endsWith(ext))) {
      if (results.length >= maxFiles) {
        throw new Error(`walkFiles: more than ${maxFiles} files under ${dir} — refusing to continue.`);
      }
      results.push(full);
    }
  }
}

export function isDirectory(p) {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

export function relPath(root, file) {
  return path.relative(root, file).replaceAll('\\', '/');
}

/**
 * True when `file` (a .js file) was split into readable modules by
 * deobfuscateDirectory's bundle-unpack step — its sibling `<name>.unpacked/`
 * directory exists. Callers that aggregate findings/stats across .js files
 * should skip a superseded original so its minified content isn't counted
 * twice alongside the readable modules that replaced it.
 */
export function isSupersededByUnpack(file) {
  const unpackedDir = path.join(path.dirname(file), `${path.basename(file, '.js')}.unpacked`);
  return isDirectory(unpackedDir);
}

/**
 * True when `file` lives directly inside a `<name>.wakaru/` directory AND
 * a sibling `<name>.js` exists next to that directory — wakaru's unpack
 * output for that original file. audit/map treat this output as read-only
 * reference material and never scan it (unlike webcrack's
 * `<name>.unpacked/`, whose contents ARE scanned in place of the
 * superseded original).
 *
 * Deliberately checks only the immediate parent, not every ancestor
 * segment: matching any ancestor let an unrelated host path component
 * (e.g. extracting under a directory that happens to be named
 * `cases.wakaru`) zero out an entire audit by accident. Requiring the
 * sibling `.js` raises the bar for a lookalike directory shipped inside
 * an extension's own zip, at the same risk level this codebase already
 * accepts for isSupersededByUnpack's sibling-`.unpacked` check above.
 */
export function isWakaruOutput(file) {
  const parentDir = path.dirname(file);
  const parentName = path.basename(parentDir);
  if (!parentName.endsWith('.wakaru')) return false;

  const siblingJs = path.join(path.dirname(parentDir), `${parentName.slice(0, -'.wakaru'.length)}.js`);
  return existsSync(siblingJs);
}

/**
 * True when `file` is renameWithHumanify's own output for another file --
 * its name ends in `.humanify.js` AND the original it renamed
 * (`<name>.js`, same directory) still exists. audit/map treat this output
 * as read-only reference material and never scan it, the same role
 * isWakaruOutput plays for wakaru's module directories.
 */
export function isHumanifyOutput(file) {
  if (!file.endsWith('.humanify.js')) return false;
  const original = file.slice(0, -'.humanify.js'.length) + '.js';
  return existsSync(original);
}
