import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { walkFiles, isSupersededByUnpack, isWakaruOutput, isHumanifyOutput } from '../src/walk.js';

test('walkFiles finds files recursively, filtered by extension', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-walk-'));
  mkdirSync(path.join(dir, 'sub'));
  writeFileSync(path.join(dir, 'a.js'), '');
  writeFileSync(path.join(dir, 'a.css'), '');
  writeFileSync(path.join(dir, 'sub', 'b.js'), '');

  const files = walkFiles(dir, { extensions: ['.js'] }).map((f) => path.relative(dir, f)).sort();
  assert.deepEqual(files, ['a.js', path.join('sub', 'b.js')].sort());
  rmSync(dir, { recursive: true });
});

test('walkFiles refuses directory nesting beyond the depth cap', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-walk-'));
  let current = dir;
  for (let i = 0; i < 10; i++) {
    current = path.join(current, `d${i}`);
    mkdirSync(current);
  }
  writeFileSync(path.join(current, 'deep.js'), '');

  assert.throws(
    () => walkFiles(dir, { extensions: ['.js'], maxDepth: 5 }),
    /nesting exceeds 5 levels/
  );
  rmSync(dir, { recursive: true });
});

test('walkFiles refuses more files than the limit', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-walk-'));
  for (let i = 0; i < 5; i++) {
    writeFileSync(path.join(dir, `f${i}.js`), '');
  }
  assert.throws(
    () => walkFiles(dir, { extensions: ['.js'], maxFiles: 3 }),
    /more than 3 files/
  );
  rmSync(dir, { recursive: true });
});

test('isSupersededByUnpack is true when a sibling .unpacked directory exists', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-walk-'));
  writeFileSync(path.join(dir, 'bundle.js'), 'minified');
  mkdirSync(path.join(dir, 'bundle.unpacked'));
  writeFileSync(path.join(dir, 'bundle.unpacked', 'index.js'), 'readable');

  assert.equal(isSupersededByUnpack(path.join(dir, 'bundle.js')), true);
  assert.equal(isSupersededByUnpack(path.join(dir, 'other.js')), false);
  rmSync(dir, { recursive: true });
});

test('isWakaruOutput is true for a file inside a <name>.wakaru directory with a sibling <name>.js', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-walk-'));
  writeFileSync(path.join(dir, 'bundle.js'), 'minified');
  mkdirSync(path.join(dir, 'bundle.wakaru'));
  writeFileSync(path.join(dir, 'bundle.wakaru', 'module-0.js'), 'readable');

  assert.equal(isWakaruOutput(path.join(dir, 'bundle.wakaru', 'module-0.js')), true);
  assert.equal(isWakaruOutput(path.join(dir, 'bundle.js')), false);
  rmSync(dir, { recursive: true });
});

test('isWakaruOutput is false for a .wakaru-named directory with no sibling .js (not provably our output)', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-walk-'));
  mkdirSync(path.join(dir, 'evil.wakaru'));
  writeFileSync(path.join(dir, 'evil.wakaru', 'payload.js'), 'eval("danger")');

  assert.equal(isWakaruOutput(path.join(dir, 'evil.wakaru', 'payload.js')), false);
  rmSync(dir, { recursive: true });
});

test('isWakaruOutput only checks the immediate parent directory, not every ancestor', () => {
  // A file whose immediate parent is NOT a .wakaru dir must not match just
  // because some ancestor further up the path happens to be named that way
  // (e.g. the extraction root itself sitting under a host path like
  // /tmp/cases.wakaru/...). Matching any ancestor previously zeroed out an
  // entire audit by accident.
  const root = mkdtempSync(path.join(tmpdir(), 'crxray-walk-'));
  const ancestor = path.join(root, 'cases.wakaru');
  const extracted = path.join(ancestor, 'extracted');
  mkdirSync(extracted, { recursive: true });
  writeFileSync(path.join(extracted, 'clean.js'), 'console.log("fine");');

  assert.equal(isWakaruOutput(path.join(extracted, 'clean.js')), false);
  rmSync(root, { recursive: true });
});

test('isHumanifyOutput is true for a *.humanify.js file with a sibling <name>.js', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-walk-'));
  writeFileSync(path.join(dir, 'min.js'), 'minified');
  writeFileSync(path.join(dir, 'min.humanify.js'), 'renamed');

  assert.equal(isHumanifyOutput(path.join(dir, 'min.humanify.js')), true);
  assert.equal(isHumanifyOutput(path.join(dir, 'min.js')), false);
  rmSync(dir, { recursive: true });
});

test('isHumanifyOutput is false for a *.humanify.js file with no sibling <name>.js (not provably our output)', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-walk-'));
  writeFileSync(path.join(dir, 'evil.humanify.js'), 'eval("danger")');

  assert.equal(isHumanifyOutput(path.join(dir, 'evil.humanify.js')), false);
  rmSync(dir, { recursive: true });
});
