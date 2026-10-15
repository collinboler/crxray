import { readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { walkFiles, relPath, isWakaruOutput } from './walk.js';

const MIN_SIZE = 80;
const MAX_SIZE = 5 * 1024 * 1024;
const WAKARU_TIMEOUT_MS = 30_000;

/**
 * Structurally unpack/unminify every .js file using wakaru — a separate npm
 * package, invoked via `npx wakaru` and never added as a crxray dependency.
 * Runs independently of deobfuscateDirectory/webcrack: same candidate files,
 * no shared state, no data handoff. Output lands in a `<file>.wakaru/`
 * sibling that audit/map never scan (see isWakaruOutput in walk.js).
 */
export async function unpackWithWakaru(dir, { quiet = false, exec = defaultExec } = {}) {
  const jsFiles = walkFiles(dir, { extensions: ['.js'] }).filter(
    (file) => !isWakaruOutput(file) && !isInsideUnpackedDir(file) && !isInsideSourcesDir(file)
  );
  const results = { processed: 0, unpacked: 0, skipped: 0, errors: [] };

  const candidates = [];
  for (const file of jsFiles) {
    const rel = relPath(dir, file);
    const size = readFileSync(file).length;

    if (size < MIN_SIZE) {
      results.processed++;
      results.skipped++;
      continue;
    }
    if (size > MAX_SIZE) {
      results.processed++;
      results.skipped++;
      results.errors.push({ file: rel, error: 'file too large (>5MB)' });
      continue;
    }
    candidates.push(file);
  }

  if (candidates.length === 0) return results;

  // One availability check before any per-file work: without it, a missing
  // or network-blocked `npx wakaru` costs one full subprocess timeout PER
  // FILE — on a 100-file extension that's the worst-case timeout x 100
  // before the user sees a single error.
  try {
    exec('npx', ['wakaru', '--version'], { timeout: WAKARU_TIMEOUT_MS, encoding: 'utf8' });
  } catch (err) {
    results.errors.push({ file: '(preflight)', error: `wakaru is not available: ${err.message}` });
    return results;
  }

  for (const file of candidates) {
    results.processed++;
    const rel = relPath(dir, file);
    const outDir = path.join(path.dirname(file), `${path.basename(file, '.js')}.wakaru`);
    // wakaru refuses to write into a non-empty output directory, so a
    // second run against an already-unpacked bundle must clear its own
    // prior output first.
    rmSync(outDir, { recursive: true, force: true });

    let stdout;
    try {
      stdout = exec('npx', ['wakaru', file, '--unpack', '-o', outDir, '--json'], {
        timeout: WAKARU_TIMEOUT_MS,
        encoding: 'utf8',
      });
    } catch (err) {
      const partial = tryParsePartialSuccess(err.stdout);
      if (partial) {
        results.unpacked++;
        results.errors.push({ file: rel, error: `wakaru: ${partial.failed ?? 0} module(s) failed` });
        continue;
      }
      results.skipped++;
      results.errors.push({ file: rel, error: `wakaru failed: ${err.message}` });
      continue;
    }

    let report;
    try {
      report = parseWakaruJson(stdout);
    } catch (err) {
      results.skipped++;
      results.errors.push({ file: rel, error: `could not parse wakaru output: ${err.message}` });
      continue;
    }

    if (!report.total) {
      results.skipped++;
      if (!quiet) console.error(`no recognized bundle format in ${rel}`);
      continue;
    }

    results.unpacked++;
    if (!quiet) {
      console.error(`unpacked ${rel} with wakaru → ${relPath(dir, outDir)}/ (${report.total} modules)`);
    }
  }

  return results;
}

function isInsideUnpackedDir(file) {
  return file.split(path.sep).some((seg) => seg.endsWith('.unpacked'));
}

// recoverFromSourceMaps writes already-readable original sources here;
// feeding them to wakaru as if they were bundles wastes a spawn per file
// and can misreport a readable file as an "unpacked bundle".
function isInsideSourcesDir(file) {
  return file.split(path.sep).some((seg) => seg.endsWith('.sources'));
}

function defaultExec(cmd, args, opts) {
  return execFileSync(cmd, args, opts);
}

// wakaru's --json output is a JSON object, but CLIs commonly interleave
// progress lines on stdout ahead of their final result — parse only the
// last non-empty line so a stray log line doesn't look like malformed JSON.
// Validates the shape so a bare `null`/number/string on the last line is
// treated as a parse failure, not a crash on `report.total`.
function parseWakaruJson(stdout) {
  const lines = stdout.trim().split('\n');
  const report = JSON.parse(lines[lines.length - 1]);
  if (report === null || typeof report !== 'object' || typeof report.total !== 'number') {
    throw new Error('unexpected wakaru JSON shape');
  }
  return report;
}

// wakaru exits non-zero when any module had an error-class warning, but
// still writes every module it recovered and prints the JSON report on
// stdout — counting that as a full failure would hide real, already-written
// output. Returns the parsed report only when it looks like a genuine
// partial success (total > 0); otherwise null, so the caller falls back to
// the plain failure path.
function tryParsePartialSuccess(stdout) {
  if (!stdout) return null;
  try {
    const report = parseWakaruJson(stdout);
    return report.total > 0 ? report : null;
  } catch {
    return null;
  }
}
