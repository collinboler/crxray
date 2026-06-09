import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { removeSourceMaps } from '../src/sourcemaps.js';

test('removeSourceMaps deletes .map files only', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-maps-'));
  writeFileSync(path.join(dir, 'app.js'), 'console.log(1);');
  writeFileSync(path.join(dir, 'app.js.map'), '{"mappings":"AAAA;"}');
  mkdirSync(path.join(dir, 'nested'));
  writeFileSync(path.join(dir, 'nested', 'x.js.map'), '{}');

  const removed = removeSourceMaps(dir);
  assert.equal(removed.length, 2);
  assert.ok(removed.includes('app.js.map'));
  assert.ok(removed.includes('nested/x.js.map'));
  assert.ok(existsSync(path.join(dir, 'app.js')));
  assert.equal(existsSync(path.join(dir, 'app.js.map')), false);

  rmSync(dir, { recursive: true });
});
