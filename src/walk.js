import { readdirSync, statSync } from 'node:fs';
import path from 'node:path';

/**
 * Recursively list files under dir, optionally filtered by extension.
 */
export function walkFiles(dir, { extensions = null } = {}) {
  const results = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkFiles(full, { extensions }));
    } else if (!extensions || extensions.some((ext) => entry.name.endsWith(ext))) {
      results.push(full);
    }
  }
  return results;
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
