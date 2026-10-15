import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { buildHandlerCallGraph, collectMessagePassing } from '../src/audit.js';

function makeFiles(dir, files) {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
}

function listenerIndex(source) {
  const m = /\b(?:chrome|browser)\.runtime\.(?:onMessage|onConnect)\.addListener\s*\(/.exec(source);
  if (!m) throw new Error('fixture has no addListener call -- test fixture bug, not a real failure');
  return m.index;
}

test('buildHandlerCallGraph finds a direct chrome.* API call inside the listener', () => {
  const source = `
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  chrome.storage.local.set({ seen: true });
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'chrome.storage.local.set', kind: 'chrome-api', path: ['(anonymous)', 'chrome.storage.local.set'] },
  ]);
});

test('buildHandlerCallGraph returns an empty array for a handler with no calls at all', () => {
  const source = `chrome.runtime.onMessage.addListener(() => {});\n`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, []);
});

test('buildHandlerCallGraph degrades to unparseable on a malformed file, without throwing', () => {
  const source = `chrome.runtime.onMessage.addListener((msg) => { this is not valid JS at all (((`;
  assert.doesNotThrow(() => buildHandlerCallGraph(source, listenerIndex(source)));
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [{ kind: 'unparseable' }]);
});

test('collectMessagePassing attaches calls to a listener entry end-to-end', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-callgraph-'));
  makeFiles(dir, {
    'sw.js': `
chrome.runtime.onMessage.addListener((msg) => {
  chrome.storage.local.get('x');
});
`,
  });
  const map = collectMessagePassing(dir);
  const entry = map.find((c) => c.listener);
  assert.ok(entry, 'the listener-only candidate exists');
  assert.deepEqual(entry.listener.calls, [
    { name: 'chrome.storage.local.get', kind: 'chrome-api', path: ['(anonymous)', 'chrome.storage.local.get'] },
  ]);
});

test('collectMessagePassing degrades gracefully on an unparseable file without affecting other files', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-callgraph-'));
  makeFiles(dir, {
    'broken.js': `chrome.runtime.onMessage.addListener((msg) => { ((( not valid`,
    'fine.js': `
chrome.runtime.onMessage.addListener((msg) => {
  chrome.storage.local.set({ ok: true });
});
`,
  });
  const map = collectMessagePassing(dir);
  const broken = map.find((c) => c.listener?.file === 'broken.js');
  const fine = map.find((c) => c.listener?.file === 'fine.js');
  assert.deepEqual(broken.listener.calls, [{ kind: 'unparseable' }]);
  assert.deepEqual(fine.listener.calls, [
    { name: 'chrome.storage.local.set', kind: 'chrome-api', path: ['(anonymous)', 'chrome.storage.local.set'] },
  ]);
});

test('buildHandlerCallGraph classifies a bare fetch() call as network', () => {
  const source = `
chrome.runtime.onMessage.addListener((msg) => {
  fetch('https://api.example.com/sync', { method: 'POST' });
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [{ name: 'fetch', kind: 'network', path: ['(anonymous)', 'fetch'] }]);
});

test('buildHandlerCallGraph classifies new XMLHttpRequest()/new WebSocket() as network', () => {
  const source = `
chrome.runtime.onMessage.addListener((msg) => {
  new XMLHttpRequest();
  new WebSocket('wss://example.com');
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'XMLHttpRequest', kind: 'network', path: ['(anonymous)', 'XMLHttpRequest'] },
    { name: 'WebSocket', kind: 'network', path: ['(anonymous)', 'WebSocket'] },
  ]);
});

test('buildHandlerCallGraph reports an arbitrary member-expression call as unresolved, not recursed into', () => {
  const source = `
chrome.runtime.onMessage.addListener((msg) => {
  someLocalObject.doSomething(msg);
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'someLocalObject.doSomething', kind: 'unresolved', path: ['(anonymous)', 'someLocalObject.doSomething'] },
  ]);
});

test('buildHandlerCallGraph does not report an uninteresting constructor call at all (not even as unresolved)', () => {
  const source = `
chrome.runtime.onMessage.addListener((msg) => {
  const m = new Map();
  chrome.storage.local.set({ size: m.size });
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'chrome.storage.local.set', kind: 'chrome-api', path: ['(anonymous)', 'chrome.storage.local.set'] },
  ]);
});

test('buildHandlerCallGraph follows a call into a local top-level function (multi-hop)', () => {
  const source = `
function processRequest(msg) {
  fetch('https://api.example.com/x');
}
chrome.runtime.onMessage.addListener((msg) => {
  processRequest(msg);
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'fetch', kind: 'network', path: ['(anonymous)', 'processRequest', 'fetch'] },
  ]);
});

test('buildHandlerCallGraph follows a call into a const-assigned arrow function', () => {
  const source = `
const processRequest = (msg) => {
  chrome.storage.local.set({ last: msg });
};
chrome.runtime.onMessage.addListener((msg) => {
  processRequest(msg);
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'chrome.storage.local.set', kind: 'chrome-api', path: ['(anonymous)', 'processRequest', 'chrome.storage.local.set'] },
  ]);
});

test('buildHandlerCallGraph reports a call to an unresolvable bare identifier as unresolved', () => {
  const source = `
chrome.runtime.onMessage.addListener((msg) => {
  doSomethingUndefined(msg);
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'doSomethingUndefined', kind: 'unresolved', path: ['(anonymous)', 'doSomethingUndefined'] },
  ]);
});

test('buildHandlerCallGraph detects direct self-recursion as a cycle, not an infinite loop', () => {
  const source = `
function a() { a(); }
chrome.runtime.onMessage.addListener((msg) => {
  a();
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [{ name: 'a', kind: 'cycle', path: ['(anonymous)', 'a', 'a'] }]);
});

test('buildHandlerCallGraph detects mutual recursion (A calls B calls A) as a cycle', () => {
  const source = `
function a() { b(); }
function b() { a(); }
chrome.runtime.onMessage.addListener((msg) => {
  a();
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [{ name: 'a', kind: 'cycle', path: ['(anonymous)', 'a', 'b', 'a'] }]);
});

test('buildHandlerCallGraph stops at the 4-hop depth cap, naming it, rather than silently truncating', () => {
  const source = `
function f1() { f2(); }
function f2() { f3(); }
function f3() { f4(); }
function f4() { f5(); }
function f5() { fetch('https://x'); }
chrome.runtime.onMessage.addListener((msg) => {
  f1();
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].kind, 'depth-limit');
  assert.deepEqual(calls[0].path, ['(anonymous)', 'f1', 'f2', 'f3', 'f4'], 'pins CALL_GRAPH_MAX_DEPTH at exactly 4');
  assert.ok(!calls.some((c) => c.name === 'fetch'), 'f5/fetch is never reached -- the cap actually stopped recursion');
});

test('buildHandlerCallGraph resolves a listener registered by named function reference', () => {
  const source = `
function myHandler(msg) {
  chrome.storage.local.get('x');
}
chrome.runtime.onMessage.addListener(myHandler);
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'chrome.storage.local.get', kind: 'chrome-api', path: ['myHandler', 'chrome.storage.local.get'] },
  ]);
});

test('buildHandlerCallGraph reports unresolved when the listener reference has no matching declaration', () => {
  const source = `chrome.runtime.onMessage.addListener(someImportedHandler);\n`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [{ kind: 'unresolved', name: 'someImportedHandler', path: ['someImportedHandler'] }]);
});

test('collectMessagePassing parses an ES module service worker without choking on import/export', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-callgraph-'));
  makeFiles(dir, {
    'sw.js': `
import { helper } from './helper.js';
chrome.runtime.onMessage.addListener((msg) => {
  chrome.storage.local.set({ ok: true });
});
export const unused = 1;
`,
  });
  const map = collectMessagePassing(dir, { background: { type: 'module' } });
  const entry = map.find((c) => c.listener);
  assert.deepEqual(entry.listener.calls, [
    { name: 'chrome.storage.local.set', kind: 'chrome-api', path: ['(anonymous)', 'chrome.storage.local.set'] },
  ]);
});

test('collectMessagePassing defaults to script sourceType when manifest has no background key at all', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-callgraph-'));
  makeFiles(dir, {
    // A top-level with statement is legal in a classic script but a SyntaxError in a module, so
    // this only parses (and yields the chrome-api entry below) if the default really is 'script'.
    'content.js': `
with (this) {
  chrome.runtime.onMessage.addListener((msg) => {
    chrome.storage.local.set({ ok: true });
  });
}
`,
  });
  assert.doesNotThrow(() => collectMessagePassing(dir, {}));
  const map = collectMessagePassing(dir, {});
  const entry = map.find((c) => c.listener);
  assert.deepEqual(entry.listener.calls, [
    { name: 'chrome.storage.local.set', kind: 'chrome-api', path: ['(anonymous)', 'chrome.storage.local.set'] },
  ]);
});

// Fix 1 (final review): a densely interconnected flat-bundle call graph must not explode
// into one output entry per path. 3 layers x 10 functions, each calling all 10 in the next
// layer: per-path enumeration yields 10*10*10 paths x 2 leaves = 2000 entries.
function denseLayeredFixture() {
  const layers = 3;
  const width = 10;
  const lines = [];
  for (let l = 0; l < layers; l++) {
    for (let i = 0; i < width; i++) {
      const body =
        l < layers - 1
          ? Array.from({ length: width }, (_, j) => `L${l + 1}_${j}();`).join(' ')
          : `chrome.cookies.getAll({}); fetch('https://x');`;
      lines.push(`function L${l}_${i}() { ${body} }`);
    }
  }
  const listenerBody = Array.from({ length: width }, (_, j) => `L0_${j}();`).join(' ');
  lines.push(`chrome.runtime.onMessage.addListener((msg) => { ${listenerBody} });`);
  return lines.join('\n');
}

test('buildHandlerCallGraph stays bounded on a densely interconnected call graph (dedup + memoization)', () => {
  const source = denseLayeredFixture();
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.ok(calls.length < 50, `expected a small bounded result, got ${calls.length} entries`);
  assert.ok(calls.some((c) => c.kind === 'chrome-api' && c.name === 'chrome.cookies.getAll'), 'the real chrome-api leaf is still reported');
  assert.ok(calls.some((c) => c.kind === 'network' && c.name === 'fetch'), 'the real network leaf is still reported');
});

test('buildHandlerCallGraph memoization does not hide leaves first cut off by the depth cap on a deeper path', () => {
  // x is first expanded via f1 -> f2 -> x, where its callee y sits past the depth cap. The
  // listener then calls x directly, with depth budget to spare: y's chrome.cookies.getAll
  // must still be found on that shallower path, as it was before memoization existed.
  const source = `
function f1() { f2(); }
function f2() { x(); }
function x() { y(); }
function y() { chrome.cookies.getAll({}); }
chrome.runtime.onMessage.addListener((msg) => {
  f1();
  x();
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.ok(
    calls.some((c) => c.kind === 'chrome-api' && c.name === 'chrome.cookies.getAll'),
    `chrome.cookies.getAll must be reachable via the shallow path; got ${JSON.stringify(calls)}`
  );
});

// Fix 2 (final review): a listener's own (minifier-renamed) parameter must not resolve to an
// unrelated top-level function that happens to share its name.
test('buildHandlerCallGraph does not resolve a call to the function own parameter against a same-named top-level function', () => {
  const source = `
function t(x) { chrome.cookies.getAll({}); }
chrome.runtime.onMessage.addListener((e, n, t) => {
  t({ ok: true });
});
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [{ name: 't', kind: 'unresolved', path: ['(anonymous)', 't'] }]);
});

test('buildHandlerCallGraph emits exactly one truncated sentinel once CALL_GRAPH_MAX_RESULTS distinct leaves are reached', () => {
  const body = Array.from({ length: 250 }, (_, i) => `u${i}();`).join(' ');
  const source = `chrome.runtime.onMessage.addListener((msg) => { ${body} });\n`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.equal(calls.length, 201);
  assert.deepEqual(calls[200], { kind: 'truncated' });
  assert.equal(calls.filter((c) => c.kind === 'truncated').length, 1);
});

// Fix 5 (final review): only the addListener call itself matches, not an outer chained call
// whose callee starts at the same offset.
test('buildHandlerCallGraph matches the addListener call, not an outer chained call starting at the same offset', () => {
  const source = `chrome.runtime.onMessage.addListener((msg) => { chrome.storage.local.set({}); }).x(() => { fetch('https://x'); });\n`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [
    { name: 'chrome.storage.local.set', kind: 'chrome-api', path: ['(anonymous)', 'chrome.storage.local.set'] },
  ]);
});

// Fix 6 (final review): exported top-level functions in a module service worker resolve.
test('collectMessagePassing resolves an exported top-level function registered by reference in a module', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-callgraph-'));
  makeFiles(dir, {
    'sw.js': `
export function handler(msg) { chrome.storage.local.get('x'); }
chrome.runtime.onMessage.addListener(handler);
`,
  });
  const map = collectMessagePassing(dir, { background: { type: 'module' } });
  const entry = map.find((c) => c.listener);
  assert.deepEqual(entry.listener.calls, [
    { name: 'chrome.storage.local.get', kind: 'chrome-api', path: ['handler', 'chrome.storage.local.get'] },
  ]);
});

test('buildHandlerCallGraph resolves export const arrow and export default function declarations', () => {
  const source = `
export const helper = () => { fetch('https://x'); };
export default function main(msg) { helper(); }
chrome.runtime.onMessage.addListener(main);
`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source), 'module');
  assert.deepEqual(calls, [{ name: 'fetch', kind: 'network', path: ['main', 'helper', 'fetch'] }]);
});

// Fix 7 (final review): a member-expression listener reference reports its real dotted name.
test('buildHandlerCallGraph names an unresolved member-expression listener reference by its dotted chain', () => {
  const source = `chrome.runtime.onMessage.addListener(obj.handler);\n`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [{ kind: 'unresolved', name: 'obj.handler', path: ['obj.handler'] }]);
});

test('buildHandlerCallGraph keeps the anonymous fallback when the listener argument has no dotted name', () => {
  const source = `chrome.runtime.onMessage.addListener(this.h.bind(this));\n`;
  const calls = buildHandlerCallGraph(source, listenerIndex(source));
  assert.deepEqual(calls, [{ kind: 'unresolved', name: undefined, path: ['(anonymous)'] }]);
});

// Fix 9.1 (final review): calls is attached on the paired (exact/probable) path too.
test('collectMessagePassing attaches calls to the listener of an exact-paired candidate', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-callgraph-'));
  makeFiles(dir, {
    'background.js': "chrome.runtime.sendMessage({type: 'PING', value: 1});\n",
    'content.js':
      "chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {\n  if (msg.type === 'PING') chrome.storage.local.set({ ping: true });\n});\n",
  });
  const map = collectMessagePassing(dir);
  const exact = map.filter((c) => c.confidence === 'exact');
  assert.equal(exact.length, 1);
  assert.deepEqual(exact[0].discriminants, ['PING']);
  assert.deepEqual(exact[0].listener.calls, [
    { name: 'chrome.storage.local.set', kind: 'chrome-api', path: ['(anonymous)', 'chrome.storage.local.set'] },
  ]);
});

// Fix 9.2 (final review): senders in an unparseable file are still collected and paired.
test('collectMessagePassing still collects and pairs senders in an unparseable file', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-callgraph-'));
  makeFiles(dir, {
    // Padding keeps the broken listener outside the sender's 150-char discriminant window, so
    // it does not also claim 'SYNC' (which would correctly downgrade the pairing to probable).
    'broken.js':
      "chrome.runtime.sendMessage({type: 'SYNC'});\n" +
      `/* ${'x'.repeat(200)} */\n` +
      'chrome.runtime.onMessage.addListener((msg) => { ((( not valid',
    'fine.js': "chrome.runtime.onMessage.addListener((msg) => {\n  if (msg.type === 'SYNC') chrome.storage.local.set({ ok: true });\n});\n",
  });
  const map = collectMessagePassing(dir);
  const paired = map.find((c) => c.sender?.file === 'broken.js' && c.listener?.file === 'fine.js');
  assert.ok(paired, 'the sender in the broken file paired with the listener in the fine file');
  assert.equal(paired.confidence, 'exact');
  assert.deepEqual(paired.discriminants, ['SYNC']);
  assert.deepEqual(paired.listener.calls, [
    { name: 'chrome.storage.local.set', kind: 'chrome-api', path: ['(anonymous)', 'chrome.storage.local.set'] },
  ]);
  const brokenListener = map.find((c) => c.listener?.file === 'broken.js');
  assert.deepEqual(brokenListener.listener.calls, [{ kind: 'unparseable' }]);
});

// Fix 9.3 (final review): a regex match with no CallExpression at that offset (a comment)
// degrades to unresolved instead of throwing.
test('buildHandlerCallGraph degrades to unresolved when the matched addListener text is inside a comment', () => {
  const source = `// chrome.runtime.onMessage.addListener(h)\nconst x = 1;\n`;
  assert.doesNotThrow(() => buildHandlerCallGraph(source, listenerIndex(source)));
  assert.deepEqual(buildHandlerCallGraph(source, listenerIndex(source)), [{ kind: 'unresolved' }]);
});
