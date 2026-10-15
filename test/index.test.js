import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { finalizeOutputDir } from '../src/index.js';

test('finalizeOutputDir refuses to overwrite an existing directory without force', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'crxray-out-'));
  const extractDir = path.join(root, 'extracted');
  const outDir = path.join(root, 'target');
  mkdirSync(extractDir);
  writeFileSync(path.join(extractDir, 'new.js'), 'new');
  mkdirSync(outDir);
  writeFileSync(path.join(outDir, 'stale.js'), 'stale');

  assert.throws(() => finalizeOutputDir(extractDir, outDir, false), /already exists/);
  assert.equal(existsSync(path.join(outDir, 'stale.js')), true);
  assert.equal(existsSync(extractDir), false); // cleaned up on refusal
  rmSync(root, { recursive: true });
});

test('finalizeOutputDir overwrites cleanly with force, no stale files survive', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'crxray-out-'));
  const extractDir = path.join(root, 'extracted');
  const outDir = path.join(root, 'target');
  mkdirSync(extractDir);
  writeFileSync(path.join(extractDir, 'new.js'), 'new');
  mkdirSync(outDir);
  writeFileSync(path.join(outDir, 'stale.js'), 'stale');

  finalizeOutputDir(extractDir, outDir, true);
  assert.equal(existsSync(path.join(outDir, 'stale.js')), false);
  assert.equal(existsSync(path.join(outDir, 'new.js')), true);
  rmSync(root, { recursive: true });
});

test('finalizeOutputDir moves extracted files into a fresh target', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'crxray-out-'));
  const extractDir = path.join(root, 'extracted');
  const outDir = path.join(root, 'target');
  mkdirSync(extractDir);
  writeFileSync(path.join(extractDir, 'new.js'), 'new');

  finalizeOutputDir(extractDir, outDir, false);
  assert.equal(existsSync(path.join(outDir, 'new.js')), true);
  rmSync(root, { recursive: true });
});
