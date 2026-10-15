import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyCrx3Signature } from '../src/crx.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Real CRX3 from the Chrome Web Store (React Developer Tools, downloaded
// 2026-10-09 via `crxray fmkadmapgofadopljbjfkapdkoienihi --keep-crx`).
// This is the regression test for the signed-payload construction itself:
// the synthetic self-signed tests in crx-verify.test.js only prove internal
// consistency (sign with key A, verify with key A) — this proves the byte
// layout actually matches what Chrome signs.
test('verifyCrx3Signature verifies a real extension downloaded from the Chrome Web Store', () => {
  const crx = readFileSync(path.join(__dirname, 'fixtures', 'react-devtools.crx'));
  const result = verifyCrx3Signature(crx, 'fmkadmapgofadopljbjfkapdkoienihi');
  assert.equal(result.verified, true);
  assert.equal(result.extensionId, 'fmkadmapgofadopljbjfkapdkoienihi');
});

test('verifyCrx3Signature rejects the real extension against the wrong expected ID', () => {
  const crx = readFileSync(path.join(__dirname, 'fixtures', 'react-devtools.crx'));
  const result = verifyCrx3Signature(crx, 'a'.repeat(32));
  assert.equal(result.verified, false);
});
