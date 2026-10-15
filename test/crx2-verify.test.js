import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createSign, createHash } from 'node:crypto';
import { verifyCrx2Signature, verifyCrx3Signature, verifyCrxSignature } from '../src/crx.js';

function bytesToId(bytes) {
  const alphabet = 'abcdefghijklmnop';
  let id = '';
  for (const b of bytes) {
    id += alphabet[(b >> 4) & 0xf];
    id += alphabet[b & 0xf];
  }
  return id;
}

// Per the authoritative Chromium CRX2 format doc (crx.html, confirmed
// 2026-10-11): the signature is RSA-SHA1 over the raw ZIP bytes -- no
// CRX3-style wrapping prefix -- and the public key is an X509
// SubjectPublicKeyInfo DER block, same as CRX3's. Only one key/signature
// pair exists (unlike CRX3's repeated proof list), so there is nothing to
// iterate: a CRX2 either has one valid proof or it does not.
function buildSignedCrx2(zip, { tamperSignature = false } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });

  const signer = createSign('RSA-SHA1');
  signer.update(zip);
  let signature = signer.sign(privateKey);
  if (tamperSignature) signature = Buffer.from(signature).fill(0);

  const prefix = Buffer.alloc(16);
  prefix.write('Cr24', 0, 'latin1');
  prefix.writeUInt32LE(2, 4);
  prefix.writeUInt32LE(publicKeyDer.length, 8);
  prefix.writeUInt32LE(signature.length, 12);

  const crx = Buffer.concat([prefix, publicKeyDer, signature, zip]);
  const idBytes = createHash('sha256').update(publicKeyDer).digest().subarray(0, 16);
  return { crx, expectedId: bytesToId(idBytes) };
}

test('verifyCrx2Signature accepts a correctly self-signed CRX2', () => {
  const zip = Buffer.from('fake zip bytes for this test');
  const { crx, expectedId } = buildSignedCrx2(zip);
  const result = verifyCrx2Signature(crx, expectedId);
  assert.equal(result.verified, true);
  assert.equal(result.extensionId, expectedId);
});

test('verifyCrx2Signature rejects a tampered signature', () => {
  const zip = Buffer.from('fake zip bytes for this test');
  const { crx, expectedId } = buildSignedCrx2(zip, { tamperSignature: true });
  const result = verifyCrx2Signature(crx, expectedId);
  assert.equal(result.verified, false);
});

test('verifyCrx2Signature rejects a signature that does not match the expected extension ID', () => {
  const zip = Buffer.from('fake zip bytes for this test');
  const { crx } = buildSignedCrx2(zip);
  const result = verifyCrx2Signature(crx, 'p'.repeat(32)); // wrong expected ID
  assert.equal(result.verified, false);
});

test('verifyCrx2Signature rejects a signature valid for different zip bytes, not just a byte-flip', () => {
  const { crx, expectedId } = buildSignedCrx2(Buffer.from('original zip content'));
  const keyLen = crx.readUInt32LE(8);
  const sigLen = crx.readUInt32LE(12);
  const zipStart = 16 + keyLen + sigLen;
  const swapped = Buffer.concat([crx.subarray(0, zipStart), Buffer.from('a completely different zip payload')]);
  const result = verifyCrx2Signature(swapped, expectedId);
  assert.equal(result.verified, false);
});

test('verifyCrx2Signature returns a reason and null extensionId for a non-CRX2 file', () => {
  const result = verifyCrx2Signature(Buffer.from('not a crx at all'), 'a'.repeat(32));
  assert.equal(result.verified, false);
  assert.equal(result.extensionId, null);
  assert.match(result.reason, /not a CRX2 file/);
});

test('verifyCrx2Signature returns a reason for a truncated header', () => {
  const buf = Buffer.alloc(10);
  buf.write('Cr24', 0, 'latin1');
  buf.writeUInt32LE(2, 4);
  const result = verifyCrx2Signature(buf, 'a'.repeat(32));
  assert.equal(result.verified, false);
  assert.match(result.reason, /not a CRX2 file|truncated|corrupt/i);
});

test('verifyCrxSignature dispatches a real CRX2 to the CRX2 path and tags the result with version 2', () => {
  const zip = Buffer.from('fake zip bytes for this test');
  const { crx, expectedId } = buildSignedCrx2(zip);
  const result = verifyCrxSignature(crx, expectedId);
  assert.equal(result.version, 2);
  assert.equal(result.verified, true);
  assert.equal(result.extensionId, expectedId);
});

test('verifyCrxSignature falls back to the CRX3 path (and its exact failure reason) for anything not CRX2', () => {
  const garbage = Buffer.from('not a crx at all, and not version 2 either');
  const viaDispatch = verifyCrxSignature(garbage, 'a'.repeat(32));
  const viaDirect = verifyCrx3Signature(garbage, 'a'.repeat(32));
  assert.equal(viaDispatch.version, 3);
  assert.equal(viaDispatch.verified, viaDirect.verified);
  assert.equal(viaDispatch.reason, viaDirect.reason);
});
