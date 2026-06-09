import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { auditExtension, collectEndpointsFromContent } from '../src/audit.js';
import { buildEntryPointMap } from '../src/map.js';
import { diffExtensions } from '../src/diff.js';

function makeExtension(dir, { manifest, files }) {
  writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
}

test('buildEntryPointMap finds background and content scripts', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-map-'));
  const manifest = {
    name: 'Test Ext',
    version: '1.0.0',
    manifest_version: 3,
    background: { service_worker: 'bg.js' },
    action: { default_popup: 'popup.html' },
    content_scripts: [{ matches: ['https://*/*'], js: ['content.js'] }],
  };
  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': 'console.log("bg");\n',
      'content.js': 'const x=1;',
      'popup.html': '<script src="popup.js"></script>',
      'popup.js': 'console.log("popup");',
    },
  });

  const map = buildEntryPointMap(dir, manifest);
  assert.equal(map.entryPoints.background, 'bg.js');
  assert.equal(map.entryPoints.popup.html, 'popup.html');
  assert.deepEqual(map.entryPoints.popup.scripts, ['popup.js']);
  assert.equal(map.entryPoints.contentScripts.length, 1);
  assert.ok(map.startHere.includes('manifest.json'));
  assert.ok(map.startHere.includes('bg.js'));
  rmSync(dir, { recursive: true });
});

test('auditExtension flags risky permissions and patterns', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = {
    name: 'Spy Ext',
    version: '2.0.0',
    manifest_version: 3,
    permissions: ['cookies', 'storage'],
    host_permissions: ['<all_urls>'],
    background: { service_worker: 'bg.js' },
  };
  const summary = {
    name: 'Spy Ext',
    version: '2.0.0',
    permissions: ['cookies', 'storage'],
    optionalPermissions: [],
    hostPermissions: ['<all_urls>'],
    contentScripts: [],
    background: 'bg.js',
  };
  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': 'eval("bad"); fetch("https://evil.example.com/track");',
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  assert.ok(['high', 'critical'].includes(audit.risk.level));
  assert.ok(audit.permissions.high.includes('cookies'));
  assert.ok(audit.findings.some((f) => f.pattern === 'eval()'));
  assert.ok(audit.endpoints.includes('https://evil.example.com/track'));
  rmSync(dir, { recursive: true });
});

test('collectEndpointsFromContent extracts URLs', () => {
  const eps = collectEndpointsFromContent('fetch("https://api.example.com/v1")');
  assert.deepEqual(eps, ['https://api.example.com/v1']);
});

test('diffExtensions detects permission and file changes', () => {
  const left = mkdtempSync(path.join(tmpdir(), 'crxray-left-'));
  const right = mkdtempSync(path.join(tmpdir(), 'crxray-right-'));

  makeExtension(left, {
    manifest: {
      name: 'Ext',
      version: '1.0.0',
      manifest_version: 3,
      permissions: ['storage'],
    },
    files: { 'a.js': 'const a = 1;', 'old.js': 'x' },
  });

  makeExtension(right, {
    manifest: {
      name: 'Ext',
      version: '1.1.0',
      manifest_version: 3,
      permissions: ['storage', 'tabs'],
      host_permissions: ['https://*/*'],
    },
    files: { 'a.js': 'const a = 2;', 'new.js': 'y' },
  });

  const diff = diffExtensions(left, right);
  assert.equal(diff.left.version, '1.0.0');
  assert.equal(diff.right.version, '1.1.0');
  assert.deepEqual(diff.permissionChanges.added, ['tabs']);
  assert.deepEqual(diff.permissionChanges.hostAdded, ['https://*/*']);
  assert.deepEqual(diff.files.added, ['new.js']);
  assert.deepEqual(diff.files.removed, ['old.js']);
  const modifiedPaths = diff.files.modified.map((m) => m.path);
  assert.ok(modifiedPaths.includes('a.js'));
  assert.ok(modifiedPaths.includes('manifest.json'));

  rmSync(left, { recursive: true });
  rmSync(right, { recursive: true });
});
