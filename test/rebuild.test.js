import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { rebuildExtension, writeProvenance } from '../src/rebuild.js';
import { createHash } from 'node:crypto';

function makeDir() {
  return mkdtempSync(path.join(tmpdir(), 'crxray-rebuild-'));
}

function writeManifest(dir, manifest) {
  writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest));
}

test('rebuildExtension copies manifest.json and every manifest-referenced file', () => {
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  writeManifest(dir, {
    name: 'Ext', version: '1.0.0', manifest_version: 3,
    background: { service_worker: 'bg.js' },
    action: { default_popup: 'popup.html', default_icon: { 16: 'icon16.png' } },
    content_scripts: [{ matches: ['<all_urls>'], js: ['cs.js'], css: ['cs.css'] }],
  });
  writeFileSync(path.join(dir, 'bg.js'), 'console.log("bg")');
  writeFileSync(path.join(dir, 'popup.html'), '<html></html>');
  writeFileSync(path.join(dir, 'icon16.png'), 'fake-png-bytes');
  writeFileSync(path.join(dir, 'cs.js'), 'console.log("cs")');
  writeFileSync(path.join(dir, 'cs.css'), 'body{}');

  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const results = rebuildExtension(dir, outDir, manifest, { quiet: true });

  assert.equal(results.missing.length, 0);
  assert.equal(results.errors.length, 0);
  for (const f of ['manifest.json', 'bg.js', 'popup.html', 'icon16.png', 'cs.js', 'cs.css']) {
    assert.ok(existsSync(path.join(outDir, f)), `expected ${f} in rebuilt output`);
  }
  rmSync(dir, { recursive: true });
});

test('rebuildExtension reports a manifest-referenced file that does not exist as missing, not silently dropped', () => {
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  writeManifest(dir, {
    name: 'Ext', version: '1.0.0', manifest_version: 3,
    background: { service_worker: 'bg.js' },
  });
  // bg.js deliberately not written -- e.g. an extension that injects it
  // dynamically rather than shipping it as a static file.

  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const results = rebuildExtension(dir, outDir, manifest, { quiet: true });

  assert.deepEqual(results.missing, ['bg.js']);
  assert.ok(!existsSync(path.join(outDir, 'bg.js')));
  rmSync(dir, { recursive: true });
});

test('rebuildExtension prefers a *.humanify.js sibling over the original file', () => {
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  writeManifest(dir, {
    name: 'Ext', version: '1.0.0', manifest_version: 3,
    background: { service_worker: 'bg.js' },
  });
  writeFileSync(path.join(dir, 'bg.js'), 'function a(b){return b}');
  writeFileSync(path.join(dir, 'bg.humanify.js'), 'function double(n){return n}');

  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const results = rebuildExtension(dir, outDir, manifest, { quiet: true });

  assert.equal(results.renamed, 1);
  assert.match(readFileSync(path.join(outDir, 'bg.js'), 'utf8'), /double/);
  rmSync(dir, { recursive: true });
});

test('rebuildExtension ships the original bundle plus its unpacked decomposition as reference material, not a reconstructed replacement', () => {
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  writeManifest(dir, {
    name: 'Ext', version: '1.0.0', manifest_version: 3,
    background: { service_worker: 'bundle.js' },
  });
  writeFileSync(path.join(dir, 'bundle.js'), 'webpackBootstrap(...)');
  mkdirSync(path.join(dir, 'bundle.unpacked'));
  writeFileSync(path.join(dir, 'bundle.unpacked', 'index.js'), 'readable entry');
  writeFileSync(path.join(dir, 'bundle.unpacked', 'module-0.js'), 'readable module');

  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const results = rebuildExtension(dir, outDir, manifest, { quiet: true });

  assert.deepEqual(results.referenceOnly, ['bundle.js']);
  // the original, still-functioning bundle is what the manifest actually loads
  assert.equal(readFileSync(path.join(outDir, 'bundle.js'), 'utf8'), 'webpackBootstrap(...)');
  // the readable decomposition travels alongside it for a human to read
  assert.ok(existsSync(path.join(outDir, 'bundle.unpacked', 'index.js')));
  assert.ok(existsSync(path.join(outDir, 'bundle.unpacked', 'module-0.js')));
  rmSync(dir, { recursive: true });
});

test('rebuildExtension prefers a wakaru decomposition the same reference-only way as a webcrack .unpacked one', () => {
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  writeManifest(dir, {
    name: 'Ext', version: '1.0.0', manifest_version: 3,
    background: { service_worker: 'bundle.js' },
  });
  writeFileSync(path.join(dir, 'bundle.js'), 'minified bundle');
  mkdirSync(path.join(dir, 'bundle.wakaru'));
  writeFileSync(path.join(dir, 'bundle.wakaru', 'module-0.js'), 'readable module');

  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const results = rebuildExtension(dir, outDir, manifest, { quiet: true });

  assert.deepEqual(results.referenceOnly, ['bundle.js']);
  assert.ok(existsSync(path.join(outDir, 'bundle.wakaru', 'module-0.js')));
  rmSync(dir, { recursive: true });
});

test('rebuildExtension copies the whole _locales directory when present', () => {
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  writeManifest(dir, { name: '__MSG_appName__', version: '1.0.0', manifest_version: 3, default_locale: 'en' });
  mkdirSync(path.join(dir, '_locales', 'en'), { recursive: true });
  writeFileSync(path.join(dir, '_locales', 'en', 'messages.json'), '{"appName":{"message":"Ext"}}');

  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  rebuildExtension(dir, outDir, manifest, { quiet: true });

  assert.ok(existsSync(path.join(outDir, '_locales', 'en', 'messages.json')));
  rmSync(dir, { recursive: true });
});

test('rebuildExtension handles MV2 shapes: browser_action, background.scripts array, flat web_accessible_resources', () => {
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  writeManifest(dir, {
    name: 'Ext', version: '1.0.0', manifest_version: 2,
    background: { scripts: ['bg1.js', 'bg2.js'] },
    browser_action: { default_popup: 'popup.html' },
    web_accessible_resources: ['injected.js'],
  });
  for (const f of ['bg1.js', 'bg2.js', 'popup.html', 'injected.js']) {
    writeFileSync(path.join(dir, f), 'content');
  }

  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const results = rebuildExtension(dir, outDir, manifest, { quiet: true });

  assert.equal(results.missing.length, 0);
  for (const f of ['bg1.js', 'bg2.js', 'popup.html', 'injected.js']) {
    assert.ok(existsSync(path.join(outDir, f)));
  }
  rmSync(dir, { recursive: true });
});

test('rebuildExtension handles MV3 web_accessible_resources objects with a resources array', () => {
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  writeManifest(dir, {
    name: 'Ext', version: '1.0.0', manifest_version: 3,
    web_accessible_resources: [{ resources: ['injected.js', 'asset.png'], matches: ['<all_urls>'] }],
  });
  writeFileSync(path.join(dir, 'injected.js'), 'content');
  writeFileSync(path.join(dir, 'asset.png'), 'content');

  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const results = rebuildExtension(dir, outDir, manifest, { quiet: true });

  assert.equal(results.missing.length, 0);
  assert.ok(existsSync(path.join(outDir, 'injected.js')));
  assert.ok(existsSync(path.join(outDir, 'asset.png')));
  rmSync(dir, { recursive: true });
});

test('rebuildExtension preserves nested directory structure for referenced paths', () => {
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  writeManifest(dir, {
    name: 'Ext', version: '1.0.0', manifest_version: 3,
    background: { service_worker: 'scripts/bg.js' },
  });
  mkdirSync(path.join(dir, 'scripts'));
  writeFileSync(path.join(dir, 'scripts', 'bg.js'), 'content');

  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  rebuildExtension(dir, outDir, manifest, { quiet: true });

  assert.ok(existsSync(path.join(outDir, 'scripts', 'bg.js')));
  rmSync(dir, { recursive: true });
});

test('rebuildExtension refuses to run without a manifest rather than producing an empty directory silently', () => {
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  const results = rebuildExtension(dir, outDir, null, { quiet: true });

  assert.equal(results.errors.length, 1);
  assert.match(results.errors[0], /no manifest/);
  rmSync(dir, { recursive: true });
});

test('rebuildExtension expands a glob pattern in web_accessible_resources.resources against real files on disk', () => {
  // Found for real running this against React Developer Tools
  // (fmkadmapgofadopljbjfkapdkoienihi): its manifest ships
  // web_accessible_resources: [{ resources: ["main.html", "build/*.js"], ... }]
  // -- a real, documented MV3 manifest feature, not an edge case.
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  writeManifest(dir, {
    name: 'Ext', version: '1.0.0', manifest_version: 3,
    web_accessible_resources: [{ resources: ['main.html', 'build/*.js'], matches: ['<all_urls>'] }],
  });
  writeFileSync(path.join(dir, 'main.html'), '<html></html>');
  mkdirSync(path.join(dir, 'build'));
  writeFileSync(path.join(dir, 'build', 'a.js'), 'content a');
  writeFileSync(path.join(dir, 'build', 'b.js'), 'content b');
  writeFileSync(path.join(dir, 'build', 'c.css'), 'not matched by *.js');

  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const results = rebuildExtension(dir, outDir, manifest, { quiet: true });

  assert.equal(results.missing.length, 0);
  assert.ok(existsSync(path.join(outDir, 'main.html')));
  assert.ok(existsSync(path.join(outDir, 'build', 'a.js')));
  assert.ok(existsSync(path.join(outDir, 'build', 'b.js')));
  assert.ok(!existsSync(path.join(outDir, 'build', 'c.css'))); // not referenced, * only matched .js
  rmSync(dir, { recursive: true });
});

test('rebuildExtension reports a glob pattern that matches nothing as missing, not silently dropped', () => {
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  writeManifest(dir, {
    name: 'Ext', version: '1.0.0', manifest_version: 3,
    web_accessible_resources: [{ resources: ['build/*.js'], matches: ['<all_urls>'] }],
  });
  // no build/ directory at all

  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const results = rebuildExtension(dir, outDir, manifest, { quiet: true });

  assert.deepEqual(results.missing, ['build/*.js']);
  rmSync(dir, { recursive: true });
});

test('rebuildExtension a glob expansion still prefers a *.humanify.js sibling for each matched file', () => {
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  writeManifest(dir, {
    name: 'Ext', version: '1.0.0', manifest_version: 3,
    web_accessible_resources: [{ resources: ['build/*.js'], matches: ['<all_urls>'] }],
  });
  mkdirSync(path.join(dir, 'build'));
  writeFileSync(path.join(dir, 'build', 'a.js'), 'function x(y){return y}');
  writeFileSync(path.join(dir, 'build', 'a.humanify.js'), 'function identity(value){return value}');

  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const results = rebuildExtension(dir, outDir, manifest, { quiet: true });

  assert.equal(results.renamed, 1);
  assert.match(readFileSync(path.join(outDir, 'build', 'a.js'), 'utf8'), /identity/);
  rmSync(dir, { recursive: true });
});

test('rebuildExtension glob expansion does not match wakaru/webcrack output as independent resources', () => {
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  writeManifest(dir, {
    name: 'Ext', version: '1.0.0', manifest_version: 3,
    web_accessible_resources: [{ resources: ['build/*.js'], matches: ['<all_urls>'] }],
  });
  mkdirSync(path.join(dir, 'build'));
  writeFileSync(path.join(dir, 'build', 'bundle.js'), 'minified bundle');
  mkdirSync(path.join(dir, 'build', 'bundle.wakaru'));
  writeFileSync(path.join(dir, 'build', 'bundle.wakaru', 'module-0.js'), 'readable module');
  mkdirSync(path.join(dir, 'build', 'other.unpacked'));
  writeFileSync(path.join(dir, 'build', 'other.unpacked', 'index.js'), 'readable');

  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const results = rebuildExtension(dir, outDir, manifest, { quiet: true });

  // only the real top-level bundle.js is a matched resource (shipped
  // reference-only, with its .wakaru/ decomposition alongside it) -- the
  // module files inside .wakaru/.unpacked are not independently "matched"
  assert.deepEqual(results.referenceOnly, [path.join('build', 'bundle.js')]);
  assert.equal(results.missing.length, 0);
  rmSync(dir, { recursive: true });
});

test('rebuildExtension does not double-count the same referenced path twice (e.g. content_scripts.js and web_accessible_resources overlap)', () => {
  const dir = makeDir();
  const outDir = path.join(dir, 'out');
  writeManifest(dir, {
    name: 'Ext', version: '1.0.0', manifest_version: 3,
    content_scripts: [{ matches: ['<all_urls>'], js: ['shared.js'] }],
    web_accessible_resources: [{ resources: ['shared.js'], matches: ['<all_urls>'] }],
  });
  writeFileSync(path.join(dir, 'shared.js'), 'content');

  const manifest = JSON.parse(readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const results = rebuildExtension(dir, outDir, manifest, { quiet: true });

  assert.equal(results.copied, 2); // manifest.json + shared.js, once each
  rmSync(dir, { recursive: true });
});

test('writeProvenance writes a REBUILD-PROVENANCE.json recording the crx hash, signature result, and crxray version', () => {
  const dir = makeDir();
  const crx = Buffer.from('fake crx bytes for this test');
  const signature = { verified: true, extensionId: 'a'.repeat(32), reason: null, version: 3 };

  const provenance = writeProvenance(dir, {
    extensionId: 'a'.repeat(32), version: '1.2.3', store: 'chrome', crx, signature, crxrayVersion: '0.2.12',
  });

  const onDisk = JSON.parse(readFileSync(path.join(dir, 'REBUILD-PROVENANCE.json'), 'utf8'));
  assert.deepEqual(onDisk, provenance);
  assert.equal(onDisk.extensionId, 'a'.repeat(32));
  assert.equal(onDisk.version, '1.2.3');
  assert.equal(onDisk.store, 'chrome');
  assert.equal(onDisk.originalCrxSha256, createHash('sha256').update(crx).digest('hex'));
  assert.deepEqual(onDisk.signature, signature);
  assert.equal(onDisk.crxrayVersion, '0.2.12');
  assert.match(onDisk.generatedAt, /^\d{4}-\d{2}-\d{2}T/);
  rmSync(dir, { recursive: true });
});

test('writeProvenance records a null signature/hash honestly rather than fabricating one when no crx bytes are available', () => {
  // e.g. --rebuild run against an already-unpacked directory (crxray audit
  // <dir> --rebuild) with no original .crx in memory for this run.
  const dir = makeDir();
  const provenance = writeProvenance(dir, { extensionId: 'a'.repeat(32), version: null, store: null, crx: null, signature: null, crxrayVersion: '0.2.12' });

  assert.equal(provenance.originalCrxSha256, null);
  assert.equal(provenance.signature, null);
  rmSync(dir, { recursive: true });
});
