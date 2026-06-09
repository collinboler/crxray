import test from 'node:test';
import assert from 'node:assert/strict';
import { parseExtensionRef } from '../src/parse.js';

const ID = 'cjpalhdlnbpafiamejdnhcphjbkeiagm';

test('parses new Chrome Web Store URL', () => {
  const ref = parseExtensionRef(`https://chromewebstore.google.com/detail/ublock-origin/${ID}`);
  assert.deepEqual(ref, { id: ID, store: 'chrome' });
});

test('parses new Chrome Web Store URL without slug', () => {
  const ref = parseExtensionRef(`https://chromewebstore.google.com/detail/${ID}`);
  assert.deepEqual(ref, { id: ID, store: 'chrome' });
});

test('parses legacy Chrome Web Store URL', () => {
  const ref = parseExtensionRef(`https://chrome.google.com/webstore/detail/ublock-origin/${ID}`);
  assert.deepEqual(ref, { id: ID, store: 'chrome' });
});

test('parses URL with query string and trailing path', () => {
  const ref = parseExtensionRef(`https://chromewebstore.google.com/detail/ublock-origin/${ID}?hl=en&pli=1`);
  assert.deepEqual(ref, { id: ID, store: 'chrome' });
});

test('parses Edge Add-ons URL', () => {
  const edgeId = 'odfafepnkmbhccpbejgmiehpchacaeak';
  const ref = parseExtensionRef(`https://microsoftedge.microsoft.com/addons/detail/ublock-origin/${edgeId}`);
  assert.deepEqual(ref, { id: edgeId, store: 'edge' });
});

test('parses bare extension ID, defaulting to chrome', () => {
  assert.deepEqual(parseExtensionRef(ID), { id: ID, store: 'chrome' });
});

test('bare ID respects defaultStore', () => {
  assert.deepEqual(parseExtensionRef(ID, 'edge'), { id: ID, store: 'edge' });
});

test('trims surrounding whitespace', () => {
  assert.deepEqual(parseExtensionRef(`  ${ID}\n`), { id: ID, store: 'chrome' });
});

test('rejects garbage input', () => {
  assert.throws(() => parseExtensionRef('not-an-extension'), /Could not find an extension ID/);
});

test('rejects too-short IDs', () => {
  assert.throws(() => parseExtensionRef('abcdef'), /Could not find an extension ID/);
});
