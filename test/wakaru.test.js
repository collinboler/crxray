import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { unpackWithWakaru } from '../src/wakaru.js';

function makeDir() {
  return mkdtempSync(path.join(tmpdir(), 'crxray-wakaru-'));
}

function bigEnough(content) {
  return content.padEnd(100, '/* pad */');
}

test('unpackWithWakaru counts a file wakaru successfully unpacks', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){/* webpack bundle */})();'));

  const exec = () =>
    JSON.stringify({ detected_formats: ['webpack'], modules: ['a.js', 'b.js'], total: 2, failed: 0, warnings: [] });
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(results.processed, 1);
  assert.equal(results.unpacked, 1);
  assert.equal(results.errors.length, 0);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru records a per-file subprocess failure without throwing', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){})();'));

  const exec = (cmd, args) => {
    if (args[1] === '--version') return 'ok'; // preflight succeeds
    throw new Error('spawn npx ENOENT');
  };
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(results.unpacked, 0);
  assert.equal(results.errors.length, 1);
  assert.match(results.errors[0].error, /wakaru failed/);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru records malformed JSON output without throwing', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){})();'));

  const exec = () => 'not json';
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(results.errors.length, 1);
  assert.match(results.errors[0].error, /could not parse wakaru output/);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru parses JSON even with progress lines ahead of it', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){})();'));

  const exec = () =>
    'Resolving modules...\nDone.\n' +
    JSON.stringify({ detected_formats: ['esbuild'], modules: ['a.js'], total: 1, failed: 0, warnings: [] });
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(results.unpacked, 1);
  assert.equal(results.errors.length, 0);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru treats a zero-module result as skipped, not an error', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'plain.js'), bigEnough('console.log("not a bundle");'));

  const exec = () => JSON.stringify({ detected_formats: [], modules: [], total: 0, failed: 0, warnings: [] });
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(results.unpacked, 0);
  assert.equal(results.skipped, 1);
  assert.equal(results.errors.length, 0);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru skips tiny files without calling wakaru', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'tiny.js'), 'x');
  let called = false;
  const exec = () => {
    called = true;
    return '{}';
  };

  const results = await unpackWithWakaru(dir, { quiet: true, exec });
  assert.equal(called, false);
  assert.equal(results.skipped, 1);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru does not re-process its own or webcrack output', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){})();'));
  mkdirSync(path.join(dir, 'bundle.unpacked'));
  writeFileSync(path.join(dir, 'bundle.unpacked', 'module-0.js'), bigEnough('export const a = 1;'));
  writeFileSync(path.join(dir, 'other.js'), bigEnough('(function(){})();'));
  mkdirSync(path.join(dir, 'other.wakaru'));
  writeFileSync(path.join(dir, 'other.wakaru', 'module-0.js'), bigEnough('export const b = 2;'));

  let callCount = 0;
  const exec = () => {
    callCount++;
    return JSON.stringify({ detected_formats: [], modules: [], total: 0, failed: 0, warnings: [] });
  };

  await unpackWithWakaru(dir, { quiet: true, exec });
  assert.equal(callCount, 3); // 1 preflight + bundle.js + other.js — not the .unpacked or .wakaru contents
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru clears a stale output directory before invoking wakaru again', async () => {
  // Real wakaru refuses to write into a non-empty output directory, so a
  // second run against an already-unpacked bundle would turn every file
  // into a "wakaru failed" error unless the stale output is cleared first.
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){})();'));
  mkdirSync(path.join(dir, 'bundle.wakaru'));
  writeFileSync(path.join(dir, 'bundle.wakaru', 'stale-module.js'), 'old output from a prior run');

  const exec = () =>
    JSON.stringify({ detected_formats: ['webpack'], modules: ['module-0.js'], total: 1, failed: 0, warnings: [] });
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(results.unpacked, 1);
  assert.equal(results.errors.length, 0);
  assert.equal(existsSync(path.join(dir, 'bundle.wakaru', 'stale-module.js')), false);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru passes a timeout to the subprocess call', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){})();'));

  let capturedOpts;
  const exec = (cmd, args, opts) => {
    capturedOpts = opts;
    return JSON.stringify({ detected_formats: [], modules: [], total: 0, failed: 0, warnings: [] });
  };
  await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(typeof capturedOpts.timeout, 'number');
  assert.ok(capturedOpts.timeout > 0);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru records an unexpected (non-object) JSON shape without throwing', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){})();'));

  const exec = (cmd, args) => (args[1] === '--version' ? 'ok' : 'null');
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(results.errors.length, 1);
  assert.match(results.errors[0].error, /unexpected wakaru JSON shape/);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru counts a partial-success exit (non-zero but modules written) as unpacked', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'bundle.js'), bigEnough('(function(){})();'));

  const partialErr = new Error('Command failed: npx wakaru ...');
  partialErr.stdout = JSON.stringify({
    detected_formats: ['webpack'],
    modules: ['a.js'],
    total: 1,
    failed: 1,
    warnings: ['one module had a parse warning'],
  });
  const exec = (cmd, args) => {
    if (args[1] === '--version') return 'ok';
    throw partialErr;
  };
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(results.unpacked, 1);
  assert.equal(results.errors.length, 1);
  assert.match(results.errors[0].error, /1 module\(s\) failed/);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru runs a preflight check and short-circuits with one error if wakaru is unavailable', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'a.js'), bigEnough('(function(){})();'));
  writeFileSync(path.join(dir, 'b.js'), bigEnough('(function(){})();'));

  let callCount = 0;
  const exec = (cmd, args) => {
    callCount++;
    if (args[1] === '--version') throw new Error('spawn npx ENOENT');
    return JSON.stringify({ total: 0 });
  };
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(callCount, 1); // only the preflight call — no per-file attempts after it fails
  assert.equal(results.processed, 0);
  assert.equal(results.errors.length, 1);
  assert.match(results.errors[0].error, /wakaru is not available/);
  rmSync(dir, { recursive: true });
});

test('unpackWithWakaru skips files recovered into a <name>.sources directory', async () => {
  // recoverFromSourceMaps writes already-readable original sources here;
  // feeding them to wakaru as if they were bundles wastes a spawn per file
  // and can misreport a readable file as an "unpacked bundle".
  const dir = makeDir();
  mkdirSync(path.join(dir, 'bundle.sources'));
  writeFileSync(path.join(dir, 'bundle.sources', 'original.js'), bigEnough('export function readable() { return 1; }'));

  let called = false;
  const exec = (cmd, args) => {
    called = true;
    return args[1] === '--version' ? 'ok' : JSON.stringify({ total: 0 });
  };
  const results = await unpackWithWakaru(dir, { quiet: true, exec });

  assert.equal(called, false);
  assert.equal(results.processed, 0);
  rmSync(dir, { recursive: true });
});
