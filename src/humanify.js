import { readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { walkFiles, relPath, isSupersededByUnpack, isHumanifyOutput } from './walk.js';

const MIN_SIZE = 80;
// humanify makes one LLM call per identifier (its own README: a ~500-identifier
// file runs $0.10-$1.00 on hosted providers and is noticeably slower even on a
// free local Ollama model) -- capped well below wakaru's 5MB bundle limit so a
// large file doesn't turn a `--humanify` run into an hours-long per-file wait.
const MAX_SIZE = 500 * 1024;
const HUMANIFY_TIMEOUT_MS = 120_000;

/**
 * Rename minified identifiers to meaningful names using humanify (a separate
 * Rust binary, github.com/jehna/humanify -- not an npm package, so unlike
 * wakaru this is never invoked via `npx`; it must already be on PATH).
 * Runs independently of deobfuscateDirectory/unpackWithWakaru: same candidate
 * files, no shared state, no data handoff. Output lands in a `<file>.humanify.js`
 * sibling that audit/map never scan (see isHumanifyOutput in walk.js).
 *
 * Default provider is 'ollama' (local, free, no API key) -- matches crxray's
 * existing no-network-credentials posture for optional tooling. Recon ahead of
 * this feature (2026-10-10) confirmed a capable local model (llama3.1:8b)
 * produces genuinely good names while a small ~1.5B model produces unusable
 * ones; it did not test humanify's own documented default Ollama model
 * (qwen3.5:4b), so crxray does not silently trust that default -- callers are
 * expected to pass an explicit `model` sized at least in the 8B class.
 */
export async function renameWithHumanify(
  dir,
  { provider = 'ollama', model, quiet = false, exec = defaultExec } = {}
) {
  // isWakaruOutput(file) is deliberately NOT excluded here, unlike wakaru.js's
  // own candidate filter: wakaru's module output is exactly where renaming
  // matters most, so those files ARE candidates. What's excluded instead is
  // the ORIGINAL bundle a successful wakaru/webcrack unpack has already
  // superseded -- renaming both the raw bundle and the modules it was split
  // into would be redundant work on the same logical content twice.
  const jsFiles = walkFiles(dir, { extensions: ['.js'] }).filter(
    (file) =>
      !isHumanifyOutput(file) &&
      !isInsideSourcesDir(file) &&
      !hasWakaruOutput(file) &&
      !isSupersededByUnpack(file)
  );
  const results = { processed: 0, renamed: 0, skipped: 0, errors: [] };

  const candidates = [];
  for (const file of jsFiles) {
    const rel = relPath(dir, file);
    const size = statSync(file).size;

    if (size < MIN_SIZE) {
      results.processed++;
      results.skipped++;
      continue;
    }
    if (size > MAX_SIZE) {
      results.processed++;
      results.skipped++;
      results.errors.push({ file: rel, error: `file too large for per-identifier renaming (>${MAX_SIZE} bytes)` });
      continue;
    }
    candidates.push(file);
  }

  if (candidates.length === 0) return results;

  // One preflight attempt, not one per candidate file -- a missing binary
  // would otherwise cost a full subprocess timeout PER FILE before the user
  // sees a single error, same rationale as wakaru.js's own preflight check.
  try {
    exec('humanify', ['--help'], { timeout: HUMANIFY_TIMEOUT_MS, encoding: 'utf8' });
  } catch (err) {
    results.errors.push({
      file: '(preflight)',
      error: `humanify is not available: ${err.message}. Install from https://github.com/jehna/humanify/releases/latest (it is a standalone binary, not an npm package).`,
    });
    return results;
  }

  for (const file of candidates) {
    results.processed++;
    const rel = relPath(dir, file);
    const outFile = path.join(path.dirname(file), `${path.basename(file, '.js')}.humanify.js`);
    const args = [provider, file, '-o', outFile];
    if (model) args.push('-m', model);

    try {
      exec('humanify', args, { timeout: HUMANIFY_TIMEOUT_MS, encoding: 'utf8' });
    } catch (err) {
      results.skipped++;
      results.errors.push({ file: rel, error: `humanify failed: ${err.message}` });
      continue;
    }

    // humanify writes its result straight to -o and exits 0 on success --
    // an exit code alone is not evidence the file exists or has content, so
    // both are checked explicitly rather than trusted.
    if (!existsSync(outFile)) {
      results.skipped++;
      results.errors.push({ file: rel, error: 'humanify exited without error but wrote no output file' });
      continue;
    }
    if (statSync(outFile).size === 0) {
      results.skipped++;
      results.errors.push({ file: rel, error: 'humanify produced an empty output file' });
      continue;
    }

    results.renamed++;
    if (!quiet) {
      console.error(`renamed identifiers in ${rel} with humanify -> ${relPath(dir, outFile)}`);
    }
  }

  return results;
}

// recoverFromSourceMaps writes already-readable original sources here;
// feeding them to humanify as if they were still minified wastes a slow
// per-identifier LLM pass on code that is already named.
function isInsideSourcesDir(file) {
  return file.split(path.sep).some((seg) => seg.endsWith('.sources'));
}

// True when `file` is the original bundle a prior `unpackWithWakaru` run
// already split into a `<name>.wakaru/` sibling directory -- the mirror image
// of isWakaruOutput (which identifies the module files inside that
// directory). Checking existence directly rather than reusing isWakaruOutput
// because that function identifies output files, not the original each one
// supersedes.
function hasWakaruOutput(file) {
  const wakaruDir = path.join(path.dirname(file), `${path.basename(file, '.js')}.wakaru`);
  return existsSync(wakaruDir) && statSync(wakaruDir).isDirectory();
}

function defaultExec(cmd, args, opts) {
  return execFileSync(cmd, args, opts);
}
