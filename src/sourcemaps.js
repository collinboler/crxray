import { readFileSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { walkFiles, relPath } from './walk.js';

/**
 * For each .map file under dir, recover original sources from its
 * sourcesContent (when present) into a sibling `<file>.sources/` directory.
 * Returns what was recovered/skipped so callers (CLI/audit) can report it.
 * Does not remove anything — pair with removeSourceMaps for the full
 * recover-then-delete pipeline.
 */
export function recoverFromSourceMaps(dir) {
  const recovered = [];
  const skipped = [];

  for (const file of walkFiles(dir, { extensions: ['.map'] })) {
    const rel = relPath(dir, file);
    let map;
    try {
      map = JSON.parse(readFileSync(file, 'utf8'));
    } catch (err) {
      skipped.push({ file: rel, reason: `invalid JSON: ${err.message}` });
      continue;
    }

    if (!Array.isArray(map.sourcesContent) || !map.sourcesContent.some((c) => typeof c === 'string')) {
      skipped.push({ file: rel, reason: 'no sourcesContent in map' });
      continue;
    }

    const outDir = path.join(path.dirname(file), `${path.basename(file, '.map')}.sources`);
    mkdirSync(outDir, { recursive: true });

    const sources = map.sources ?? [];
    let count = 0;
    for (let i = 0; i < map.sourcesContent.length; i++) {
      const content = map.sourcesContent[i];
      if (typeof content !== 'string') continue;
      const name = sanitizeSourceName(sources[i] ?? `source-${i}.js`, i);
      writeFileSync(path.join(outDir, name), content);
      count++;
    }

    recovered.push({ map: rel, outDir: relPath(dir, outDir), fileCount: count });
  }

  return { recovered, skipped };
}

function sanitizeSourceName(sourcePath, index) {
  const base = sourcePath.replace(/^webpack:\/\/\/?/, '').replace(/^\.\.?\//, '');
  const safe = base.split(/[/\\]/).filter(Boolean).join('__') || `source-${index}.js`;
  return safe.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 150);
}

/**
 * Remove .map source map files. They contain megabytes of VLQ mappings
 * that are useless for security audits and clutter the editor. Run
 * recoverFromSourceMaps first if you want any recoverable original
 * sources kept.
 */
export function removeSourceMaps(dir) {
  const removed = [];
  for (const file of walkFiles(dir, { extensions: ['.map'] })) {
    rmSync(file);
    removed.push(relPath(dir, file));
  }
  return removed;
}
