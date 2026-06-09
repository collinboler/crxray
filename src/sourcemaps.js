import { rmSync } from 'node:fs';
import { walkFiles, relPath } from './walk.js';

/**
 * Remove .map source map files. They contain megabytes of VLQ mappings
 * that are useless for security audits and clutter the editor.
 */
export function removeSourceMaps(dir) {
  const removed = [];
  for (const file of walkFiles(dir, { extensions: ['.map'] })) {
    rmSync(file);
    removed.push(relPath(dir, file));
  }
  return removed;
}
