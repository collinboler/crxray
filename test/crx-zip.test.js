import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { crxToZip } from '../src/crx.js';
import { readZipEntries, extractZip, crc32 } from '../src/zip.js';

// --- minimal ZIP builder for fixtures (deflate, no CRC verification) ---

function buildZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const [name, content, opts = {}] of files) {
    const nameBuf = Buffer.from(name, 'utf8');
    const isDir = name.endsWith('/');
    const data = isDir ? Buffer.alloc(0) : opts.rawCompressed ?? deflateRawSync(Buffer.from(content, 'utf8'));
    const uncompSize = opts.uncompressedSize ?? (isDir ? 0 : Buffer.byteLength(content, 'utf8'));
    // Real zip writers always store the entry's real CRC32, so default to
    // the actual value (like a real file would have) unless a test
    // deliberately overrides it to simulate corruption/tampering.
    const crc = opts.crc ?? (isDir || opts.rawCompressed ? 0 : crc32(Buffer.from(content, 'utf8')));
    const method = isDir ? 0 : 8;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(uncompSize, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    locals.push(local, nameBuf, data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc, 16);
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

// --- resource-exhaustion & integrity guards ---

test('rejects a ZIP claiming more entries than the limit', () => {
  const zip = buildZip(FIXTURE);
  const eocdOffset = zip.length - 22;
  zip.writeUInt16LE(60000, eocdOffset + 10);
  assert.throws(() => readZipEntries(zip), /entries exceeds/);
});

test('rejects a single entry declaring an oversized uncompressed size', () => {
  const zip = buildZip([['big.bin', 'x', { uncompressedSize: 300_000_000 }]]);
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-'));
  assert.throws(() => extractZip(zip, dir), /byte limit/);
});

test('rejects entries whose combined declared size exceeds the aggregate cap', () => {
  const zip = buildZip([
    ['a.bin', 'x', { uncompressedSize: 180_000_000 }],
    ['b.bin', 'x', { uncompressedSize: 180_000_000 }],
    ['c.bin', 'x', { uncompressedSize: 180_000_000 }],
  ]);
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-'));
  assert.throws(() => extractZip(zip, dir), /total uncompressed size exceeds/);
});

test('rejects an entry whose inflated size does not match its declared size', () => {
  const zip = buildZip([['lie.js', 'hello', { uncompressedSize: 999 }]]);
  const [entry] = readZipEntries(zip);
  assert.throws(() => entry.data(), /not the declared 999/);
});

test('rejects an entry whose content does not match its stored CRC32', () => {
  const zip = buildZip([['tampered.js', 'hello', { crc: 0xdeadbeef }]]);
  const [entry] = readZipEntries(zip);
  assert.throws(() => entry.data(), /CRC mismatch/);
});

test('rejects tampered content even when the stored CRC is exactly 0', () => {
  // A declared CRC of 0 is not a "no CRC" sentinel in the zip format — a
  // same-length tamper that also zeroes the CRC field must still be caught.
  const zip = buildZip([['tampered-zero-crc.js', 'hello', { crc: 0 }]]);
  const [entry] = readZipEntries(zip);
  assert.throws(() => entry.data(), /CRC mismatch/);
});

test('accepts an entry whose content matches its stored CRC32', () => {
  const content = 'hello';
  const crc = crc32(Buffer.from(content, 'utf8'));
  const zip = buildZip([['ok.js', content, { crc }]]);
  const [entry] = readZipEntries(zip);
  assert.equal(entry.data().toString(), content);
});

test('rejects an entry whose real inflated output would exceed the per-entry cap, without fully allocating it first', () => {
  // Declare a small, in-bounds size (lie) but supply real compressed bytes
  // that actually inflate to 250MB. This proves the cap is enforced during
  // inflate (maxOutputLength) rather than only by comparing lengths after
  // zlib has already allocated the full oversized buffer.
  const rawCompressed = deflateRawSync(Buffer.alloc(250 * 1024 * 1024, 0));
  const zip = buildZip([['bomb.bin', 'x', { uncompressedSize: 1000, rawCompressed }]]);
  const [entry] = readZipEntries(zip);
  assert.throws(() => entry.data(), /decompression bomb/);
});

test('blocks a zip-slip entry using an absolute path instead of ../', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-'));
  const evil = buildZip([['/etc/evil.txt', 'pwned']]);
  assert.throws(() => extractZip(evil, dir), /zip-slip/);
});
