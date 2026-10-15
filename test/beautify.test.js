import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { beautifyDirectory } from '../src/beautify.js';

test('beautifyDirectory never processes files inside a <name>.wakaru directory', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-beautify-'));
  writeFileSync(path.join(dir, 'bundle.js'), 'function f(){return 1}');
  mkdirSync(path.join(dir, 'bundle.wakaru'));
  writeFileSync(path.join(dir, 'bundle.wakaru', 'module-0.js'), 'function g(){return 2}');
  writeFileSync(path.join(dir, 'clean.js'), 'function h(){return 3}');

  const results = beautifyDirectory(dir, { quiet: true });
  assert.equal(results.processed, 2); // bundle.js + clean.js, not the wakaru module
  rmSync(dir, { recursive: true });
});

test('beautifyDirectory never processes a file that is humanify\'s own output for another file', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-beautify-'));
  writeFileSync(path.join(dir, 'min.js'), 'function f(){return 1}');
  writeFileSync(path.join(dir, 'min.humanify.js'), 'function add(a,b){return a+b}');
  writeFileSync(path.join(dir, 'clean.js'), 'function h(){return 3}');

  const results = beautifyDirectory(dir, { quiet: true });
  assert.equal(results.processed, 2); // min.js + clean.js, not min.humanify.js
  rmSync(dir, { recursive: true });
});
