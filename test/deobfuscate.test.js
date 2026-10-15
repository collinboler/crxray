import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { deobfuscateDirectory } from '../src/deobfuscate.js';

test('deobfuscateDirectory never processes files inside a <name>.wakaru directory', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-deobf-'));
  // Both real candidates are kept under MIN_SIZE so webcrack is never
  // actually invoked on them — this test is only about which files make
  // it into the candidate set, not what webcrack does with them.
  writeFileSync(path.join(dir, 'bundle.js'), 'x');
  mkdirSync(path.join(dir, 'bundle.wakaru'));
  writeFileSync(path.join(dir, 'bundle.wakaru', 'module-0.js'), 'y');
  writeFileSync(path.join(dir, 'clean.js'), 'z');

  const results = await deobfuscateDirectory(dir, { quiet: true });
  assert.equal(results.processed, 2); // bundle.js + clean.js, not the wakaru module
  rmSync(dir, { recursive: true });
});
