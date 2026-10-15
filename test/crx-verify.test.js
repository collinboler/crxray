import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createSign, createHash } from 'node:crypto';
import { verifyCrx3Signature } from '../src/crx.js';

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
function protoField(fieldNumber, bytes) {
  return Buffer.concat([encodeVarint((fieldNumber << 3) | 2), encodeVarint(bytes.length), bytes]);
}
function bytesToId(bytes) {
  const alphabet = 'abcdefghijklmnop';
  let id = '';
  for (const b of bytes) {
    id += alphabet[(b >> 4) & 0xf];
    id += alphabet[b & 0xf];
  }
  return id;
}

// signed_header_data is field 10000 of CrxFileHeader (confirmed against
// crxviewer's crx-to-zip.js, which checks `key === 80002` i.e. (10000<<3)|2).
function buildSignedCrx3(zip, { tamperSignature = false, tamperId = false } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });

  const idBytes = createHash('sha256').update(publicKeyDer).digest().subarray(0, 16);
  const signedHeaderData = protoField(1, idBytes); // SignedData { crx_id = field 1 }

  // "CRX3 SignedData\x00" + signed_header_size (4 bytes LE) + signed_header_data + archive.
  const magic = Buffer.from('CRX3 SignedData\0', 'ascii');
  const sizeField = Buffer.alloc(4);
  sizeField.writeUInt32LE(signedHeaderData.length, 0);
  const signer = createSign('RSA-SHA256');
  signer.update(Buffer.concat([magic, sizeField, signedHeaderData, zip]));
  let signature = signer.sign(privateKey);
  if (tamperSignature) signature = Buffer.from(signature).fill(0);

  const proof = Buffer.concat([protoField(1, publicKeyDer), protoField(2, signature)]);
  const header = Buffer.concat([protoField(2, proof), protoField(10000, signedHeaderData)]);

  const prefix = Buffer.alloc(12);
  prefix.write('Cr24', 0, 'latin1');
  prefix.writeUInt32LE(3, 4);
  prefix.writeUInt32LE(header.length, 8);

  const crx = Buffer.concat([prefix, header, zip]);
  const expectedId = tamperId ? 'a'.repeat(32) : bytesToId(idBytes);
  return { crx, expectedId };
}

test('verifyCrx3Signature accepts a correctly self-signed CRX3', () => {
  const zip = Buffer.from('fake zip bytes for this test');
  const { crx, expectedId } = buildSignedCrx3(zip);
  const result = verifyCrx3Signature(crx, expectedId);
  assert.equal(result.verified, true);
  assert.equal(result.extensionId, expectedId);
});

test('verifyCrx3Signature rejects a tampered signature', () => {
  const zip = Buffer.from('fake zip bytes for this test');
  const { crx, expectedId } = buildSignedCrx3(zip, { tamperSignature: true });
  const result = verifyCrx3Signature(crx, expectedId);
  assert.equal(result.verified, false);
});

test('verifyCrx3Signature rejects a signature that does not match the expected extension ID', () => {
  const zip = Buffer.from('fake zip bytes for this test');
  const { crx } = buildSignedCrx3(zip);
  const result = verifyCrx3Signature(crx, 'p'.repeat(32)); // wrong expected ID
  assert.equal(result.verified, false);
});

test('verifyCrx3Signature skips a malformed proof and still finds a later valid one', () => {
  // Real CRX3s often carry 2+ sha256_with_rsa proofs. A malformed first
  // proof (bad DER key) must not crash verification of a good later one.
  const zip = Buffer.from('fake zip bytes for this test');
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const idBytes = createHash('sha256').update(publicKeyDer).digest().subarray(0, 16);
  const signedHeaderData = protoField(1, idBytes);

  const magic = Buffer.from('CRX3 SignedData\0', 'ascii');
  const sizeField = Buffer.alloc(4);
  sizeField.writeUInt32LE(signedHeaderData.length, 0);
  const signer = createSign('RSA-SHA256');
  signer.update(Buffer.concat([magic, sizeField, signedHeaderData, zip]));
  const signature = signer.sign(privateKey);

  const goodProof = Buffer.concat([protoField(1, publicKeyDer), protoField(2, signature)]);
  const badProof = Buffer.concat([protoField(1, Buffer.from('not a valid DER key')), protoField(2, Buffer.alloc(256))]);

  const header = Buffer.concat([
    protoField(2, badProof), // malformed, comes first
    protoField(2, goodProof), // valid, comes second
    protoField(10000, signedHeaderData),
  ]);

  const prefix = Buffer.alloc(12);
  prefix.write('Cr24', 0, 'latin1');
  prefix.writeUInt32LE(3, 4);
  prefix.writeUInt32LE(header.length, 8);
  const crx = Buffer.concat([prefix, header, zip]);

  const expectedId = bytesToId(idBytes);
  const result = verifyCrx3Signature(crx, expectedId);
  assert.equal(result.verified, true);
  assert.equal(result.extensionId, expectedId);
});

test('verifyCrx3Signature reports a non-CRX3 buffer as unverifiable, not a crash', () => {
  const result = verifyCrx3Signature(Buffer.from('not a crx'), 'a'.repeat(32));
  assert.equal(result.verified, false);
  assert.match(result.reason, /not a CRX3/);
});
