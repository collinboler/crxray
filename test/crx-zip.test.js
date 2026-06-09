import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { crxToZip } from '../src/crx.js';
import { readZipEntries, extractZip } from '../src/zip.js';

// --- minimal ZIP builder for fixtures (deflate, no CRC verification) ---

function buildZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const [name, content] of files) {
    const nameBuf = Buffer.from(name, 'utf8');
    const isDir = name.endsWith('/');
    const data = isDir ? Buffer.alloc(0) : deflateRawSync(Buffer.from(content, 'utf8'));
    const uncompSize = isDir ? 0 : Buffer.byteLength(content, 'utf8');
    const method = isDir ? 0 : 8;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(uncompSize, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    locals.push(local, nameBuf, data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(uncompSize, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(Buffer.concat([central, nameBuf]));

    offset += 30 + nameBuf.length + data.length;
  }

  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);

  return Buffer.concat([...locals, cd, eocd]);
}

function buildCrx3(zip) {
  const header = Buffer.from('fake-signature-header');
  const prefix = Buffer.alloc(12);
  prefix.write('Cr24', 0, 'latin1');
  prefix.writeUInt32LE(3, 4);
  prefix.writeUInt32LE(header.length, 8);
  return Buffer.concat([prefix, header, zip]);
}

function buildCrx2(zip) {
  const key = Buffer.from('fake-public-key!');
  const sig = Buffer.from('fake-signature');
  const prefix = Buffer.alloc(16);
  prefix.write('Cr24', 0, 'latin1');
  prefix.writeUInt32LE(2, 4);
  prefix.writeUInt32LE(key.length, 8);
  prefix.writeUInt32LE(sig.length, 12);
  return Buffer.concat([prefix, key, sig, zip]);
}

const FIXTURE = [
  ['manifest.json', '{"name":"Test","version":"1.0"}'],
  ['js/', ''],
  ['js/app.js', 'console.log("hi")'],
];

// --- crxToZip ---

test('strips a CRX3 header', () => {
  const zip = buildZip(FIXTURE);
  assert.deepEqual(crxToZip(buildCrx3(zip)), zip);
});

test('strips a CRX2 header', () => {
  const zip = buildZip(FIXTURE);
  assert.deepEqual(crxToZip(buildCrx2(zip)), zip);
});

test('passes through a plain ZIP unchanged', () => {
  const zip = buildZip(FIXTURE);
  assert.equal(crxToZip(zip), zip);
});

test('rejects non-CRX data', () => {
  assert.throws(() => crxToZip(Buffer.from('<html>error page</html>'.repeat(4))), /missing Cr24 magic/);
});

test('rejects unsupported CRX versions', () => {
  const bad = buildCrx3(buildZip(FIXTURE));
  bad.writeUInt32LE(9, 4);
  assert.throws(() => crxToZip(bad), /Unsupported CRX version/);
});

// --- zip ---

test('reads entries and inflates contents', () => {
  const entries = readZipEntries(buildZip(FIXTURE));
  assert.deepEqual(
    entries.map((e) => e.name),
    ['manifest.json', 'js/', 'js/app.js']
  );
  assert.equal(entries[0].data().toString(), '{"name":"Test","version":"1.0"}');
  assert.equal(entries[2].data().toString(), 'console.log("hi")');
  assert.equal(entries[1].isDirectory, true);
});

test('extracts to disk', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-'));
  const count = extractZip(buildZip(FIXTURE), dir);
  assert.equal(count, 2);
  assert.equal(readFileSync(path.join(dir, 'manifest.json'), 'utf8'), '{"name":"Test","version":"1.0"}');
  assert.equal(readFileSync(path.join(dir, 'js', 'app.js'), 'utf8'), 'console.log("hi")');
});

test('blocks zip-slip path traversal', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-'));
  const evil = buildZip([['../evil.txt', 'pwned']]);
  assert.throws(() => extractZip(evil, dir), /zip-slip/);
  assert.equal(existsSync(path.join(dir, '..', 'evil.txt')), false);
});

test('rejects buffers without an EOCD record', () => {
  assert.throws(() => readZipEntries(Buffer.alloc(100)), /end-of-central-directory/);
});
