import test from 'node:test';
import assert from 'node:assert/strict';
import { readFields } from '../src/protobuf-lite.js';

function encodeVarint(n) {
  const bytes = [];
  let v = n;
  do {
    let byte = v & 0x7f;
    v >>>= 7;
    if (v) byte |= 0x80;
    bytes.push(byte);
  } while (v);
  return Buffer.from(bytes);
}
function encodeTag(fieldNumber, wireType) {
  return encodeVarint((fieldNumber << 3) | wireType);
}

test('readFields decodes a length-delimited field', () => {
  const payload = Buffer.from('hi', 'utf8');
  const msg = Buffer.concat([encodeTag(1, 2), encodeVarint(payload.length), payload]);
  const fields = readFields(msg);
  assert.equal(fields[1][0].toString(), 'hi');
});

test('readFields decodes a varint field', () => {
  const msg = Buffer.concat([encodeTag(2, 0), encodeVarint(300)]);
  const fields = readFields(msg);
  assert.equal(fields[2][0], 300);
});

test('readFields collects repeated fields with the same number, in order', () => {
  const a = Buffer.concat([encodeTag(1, 2), encodeVarint(1), Buffer.from('a')]);
  const b = Buffer.concat([encodeTag(1, 2), encodeVarint(1), Buffer.from('b')]);
  const fields = readFields(Buffer.concat([a, b]));
  assert.equal(fields[1].length, 2);
  assert.equal(fields[1][0].toString(), 'a');
  assert.equal(fields[1][1].toString(), 'b');
});

test('readFields handles a multi-byte (large) field number', () => {
  // CRX3's signed_header_data is field 10000 — the tag varint needs 3 bytes.
  const payload = Buffer.from('id-bytes');
  const msg = Buffer.concat([encodeTag(10000, 2), encodeVarint(payload.length), payload]);
  const fields = readFields(msg);
  assert.equal(fields[10000][0].toString(), 'id-bytes');
});

test('readFields throws on an unsupported wire type', () => {
  const msg = encodeTag(1, 3); // start-group, deprecated, unsupported
  assert.throws(() => readFields(msg), /unsupported wire type/);
});

test('readFields throws on a truncated varint instead of silently reading garbage', () => {
  // Continuation bit set on the final byte, then the buffer just ends.
  const msg = Buffer.from([0x80]);
  assert.throws(() => readFields(msg), /truncated/);
});

test('readFields throws when a length-delimited field claims more bytes than remain', () => {
  const msg = Buffer.concat([encodeTag(1, 2), encodeVarint(100), Buffer.from('short')]);
  assert.throws(() => readFields(msg), /past end of buffer/);
});
