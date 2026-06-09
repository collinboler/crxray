import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { walkFiles, relPath } from './walk.js';

async function loadWebcrack() {
  try {
    const mod = await import('webcrack');
    return mod.webcrack;
  } catch {
    throw new Error(
      '--deobfuscate requires webcrack. If install failed, retry with: npm install -g crxray --ignore-scripts ' +
        '(Node 18–22 LTS recommended)'
    );
  }
}

const MIN_SIZE = 80;
const MAX_SIZE = 5 * 1024 * 1024;

/**
 * Deobfuscate and unpack every .js file using webcrack.
 * Best-effort: obfuscator.io, webpack, and browserify bundles.
 */
export async function deobfuscateDirectory(dir, { quiet = false } = {}) {
  const webcrack = await loadWebcrack();
  const jsFiles = walkFiles(dir, { extensions: ['.js'] });
  const results = { processed: 0, changed: 0, unpacked: 0, skipped: 0, errors: [] };

  for (const file of jsFiles) {
    results.processed++;
    const rel = relPath(dir, file);
    const original = readFileSync(file, 'utf8');

    if (original.length < MIN_SIZE) {
      results.skipped++;
      continue;
    }
    if (original.length > MAX_SIZE) {
      results.skipped++;
      results.errors.push({ file: rel, error: 'file too large (>5MB)' });
      continue;
    }

    try {
      const result = await webcrack(original, {
        deobfuscate: true,
        unpack: true,
        unminify: true,
        jsx: false,
      });

      if (result.bundle) {
        const outDir = path.join(path.dirname(file), `${path.basename(file, '.js')}.unpacked`);
        await result.save(outDir);
        results.unpacked++;
        results.changed++;
        if (!quiet) console.error(`unpacked bundle ${rel} → ${relPath(dir, outDir)}/`);
        continue;
      }

      if (result.code && result.code !== original) {
        writeFileSync(file, result.code);
        results.changed++;
        if (!quiet) console.error(`deobfuscated ${rel}`);
      }
    } catch (err) {
      results.skipped++;
      results.errors.push({ file: rel, error: err.message });
    }
  }

  return results;
}
