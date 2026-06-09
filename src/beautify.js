import { readFileSync, writeFileSync } from 'node:fs';
import beautifyPkg from 'js-beautify';

const beautifyJs = beautifyPkg.js;
import { walkFiles, relPath } from './walk.js';

/**
 * Beautify every .js file in an unpacked extension directory.
 */
export function beautifyDirectory(dir, { quiet = false } = {}) {
  const jsFiles = walkFiles(dir, { extensions: ['.js'] });
  const results = { processed: 0, changed: 0, skipped: 0, errors: [] };

  for (const file of jsFiles) {
    results.processed++;
    const rel = relPath(dir, file);
    try {
      const original = readFileSync(file, 'utf8');
      const formatted = beautifyJs(original, {
        indent_size: 2,
        wrap_line_length: 100,
        end_with_newline: true,
        preserve_newlines: true,
        max_preserve_newlines: 2,
      });
      if (formatted !== original) {
        writeFileSync(file, formatted);
        results.changed++;
        if (!quiet) console.error(`beautified ${rel}`);
      }
    } catch (err) {
      results.skipped++;
      results.errors.push({ file: rel, error: err.message });
    }
  }

  return results;
}
