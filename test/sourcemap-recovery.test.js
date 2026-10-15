import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { recoverFromSourceMaps } from '../src/sourcemaps.js';

test('recoverFromSourceMaps writes out sourcesContent when present', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-maps-'));
  writeFileSync(
    path.join(dir, 'bundle.js.map'),
    JSON.stringify({
      version: 3,
      sources: ['webpack:///./src/background.js'],
      sourcesContent: ['console.log("original source");'],
    })
  );

  const result = recoverFromSourceMaps(dir);
  assert.equal(result.recovered.length, 1);
  assert.equal(result.recovered[0].fileCount, 1);
  const recoveredFile = path.join(dir, 'bundle.js.sources', 'src__background.js');
  assert.equal(existsSync(recoveredFile), true);
  assert.equal(readFileSync(recoveredFile, 'utf8'), 'console.log("original source");');
  rmSync(dir, { recursive: true });
});

test('recoverFromSourceMaps skips a map with no sourcesContent', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-maps-'));
  writeFileSync(path.join(dir, 'bundle.js.map'), JSON.stringify({ version: 3, sources: ['a.js'] }));

  const result = recoverFromSourceMaps(dir);
  assert.equal(result.recovered.length, 0);
  assert.equal(result.skipped.length, 1);
  assert.match(result.skipped[0].reason, /no sourcesContent/);
  rmSync(dir, { recursive: true });
});

test('recoverFromSourceMaps skips invalid JSON without throwing', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-maps-'));
  writeFileSync(path.join(dir, 'broken.js.map'), '{not valid json');

  const result = recoverFromSourceMaps(dir);
  assert.equal(result.skipped.length, 1);
  assert.match(result.skipped[0].reason, /invalid JSON/);
  rmSync(dir, { recursive: true });
});
