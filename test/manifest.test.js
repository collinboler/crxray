import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { readManifest, summarizeManifest } from '../src/manifest.js';

function writeManifest(dir, manifest) {
  writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest));
}

test('summarizeManifest reads optional_host_permissions', () => {
  const summary = summarizeManifest({
    name: 'Ext', version: '1.0', manifest_version: 3,
    optional_host_permissions: ['<all_urls>'],
  });
  assert.deepEqual(summary.optionalHostPermissions, ['<all_urls>']);
});

test('summarizeManifest reads CSP, externally_connectable, oauth2, update_url, declarative_net_request', () => {
  const summary = summarizeManifest({
    name: 'Ext', version: '1.0', manifest_version: 3,
    content_security_policy: { extension_pages: "script-src 'self' 'unsafe-eval'" },
    externally_connectable: { ids: ['*'] },
    oauth2: { client_id: 'abc', scopes: ['email'] },
    update_url: 'https://example.com/update.xml',
    declarative_net_request: { rule_resources: [{ id: 'r1' }, { id: 'r2' }] },
  });
  assert.equal(summary.contentSecurityPolicy.extension_pages, "script-src 'self' 'unsafe-eval'");
  assert.deepEqual(summary.externallyConnectable, { ids: ['*'] });
  assert.deepEqual(summary.oauth2, { clientId: 'abc', scopes: ['email'] });
  assert.equal(summary.updateUrl, 'https://example.com/update.xml');
  assert.equal(summary.declarativeNetRequestRulesets, 2);
});

test('summarizeManifest handles a near-empty manifest without throwing', () => {
  const summary = summarizeManifest({});
  assert.equal(summary.name, null);
  assert.equal(summary.manifestVersion, null);
  assert.deepEqual(summary.permissions, []);
  assert.deepEqual(summary.optionalHostPermissions, []);
  assert.equal(summary.contentSecurityPolicy, null);
  assert.equal(summary.oauth2, null);
  assert.equal(summary.declarativeNetRequestRulesets, 0);
});

test('readManifest resolves __MSG_*__ placeholders from _locales', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-manifest-'));
  writeManifest(dir, { name: '__MSG_appName__', version: '1.0', default_locale: 'en' });
  mkdirSync(path.join(dir, '_locales', 'en'), { recursive: true });
  writeFileSync(path.join(dir, '_locales', 'en', 'messages.json'), JSON.stringify({ appName: { message: 'My Extension' } }));

  const manifest = readManifest(dir);
  assert.equal(manifest.name, 'My Extension');
  rmSync(dir, { recursive: true });
});

test('readManifest falls back to "en" when the declared default_locale is missing on disk', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-manifest-'));
  writeManifest(dir, { name: '__MSG_appName__', version: '1.0', default_locale: 'fr' }); // fr/ doesn't exist
  mkdirSync(path.join(dir, '_locales', 'en'), { recursive: true });
  writeFileSync(path.join(dir, '_locales', 'en', 'messages.json'), JSON.stringify({ appName: { message: 'Fallback Name' } }));

  const manifest = readManifest(dir);
  assert.equal(manifest.name, 'Fallback Name');
  rmSync(dir, { recursive: true });
});
