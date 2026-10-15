# Message-Handler Call Graph Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `collectMessagePassing()` a real call graph for the listener (callee) side of each `onMessage`/`onConnect` handler — what `chrome.*`/network calls it can reach, and the local-function chain that leads to each one.

**Architecture:** One new pure function, `buildHandlerCallGraph` (exported) backed by an internal `buildCallGraphFromProgram`, both in `src/audit.js`. `collectMessagePassing()` parses each JS file once with `acorn`, locates each regex-matched listener's callback node by character offset, and walks its call sites up to 4 hops with cycle detection. Output is additive: one new `calls` array field on each existing `messagePassing` listener entry.

**Tech Stack:** `acorn` (new real dependency, `^8.19.0`) for AST parsing; a hand-rolled recursive walker (no `acorn-walk`) for traversal.

**Spec:** `docs/superpowers/specs/2026-10-12-message-handler-call-graph-design.md` — read it in full before starting; this plan argues from it and does not repeat its rationale.

## Global Constraints

- Max recursion depth: **4 hops** of local-function calls (spec, "Walk calls from the listener, bounded").
- `collectMessagePassing(dir, manifest = {})` — `manifest` is an **optional** second parameter defaulting to `{}`, so all 3 existing calls in `test/audit-messagemap.test.js` (which call it with just `dir`) keep working unchanged.
- `sourceType` for parsing is `'module'` only when `manifest.background?.type === 'module'`, else `'script'` (spec, step 1).
- New dependency `acorn@^8.19.0` goes in `package.json`'s real `dependencies` (not `devDependencies`, not npx-shelled).
- No `acorn-walk` — a hand-rolled recursive walker only (spec, "New dependency").
- A parse failure degrades to `calls: [{ kind: 'unparseable' }]` for every listener in that file; it must never throw out of `collectMessagePassing()` or affect any other file's results (spec, step 1).
- `src/index.js` and `bin/crxray.js` get zero diff from this plan — only `src/audit.js` and `package.json`/`package-lock.json` change in `src/`.

## Review Focus

- **A handler with an empty body** (`addListener(() => {})`, a bare acknowledgment-only listener) — common in real extensions. Must return `[]`, not throw, not omit the field. Owned by Task 1.
- **Direct self-recursion** (`function a() { a(); }`), not just mutual A→B→A — must resolve as `cycle` on the first re-entry, not infinite-loop/stack-overflow. Owned by Task 4.
- **A real, large, deeply-nested minified bundle** — the hand-rolled recursive AST walker must not stack-overflow on a genuinely-sized real file, not just small synthetic fixtures. Owned by Task 7 (real-download check against `test/fixtures/react-devtools.crx`'s actual background bundle).
- **Backward compatibility**: `collectMessagePassing(dir)` called with no second argument (all 3 pre-existing tests in `test/audit-messagemap.test.js`) must keep passing unchanged. Owned by Task 1 (re-run that file as part of verification).
- **A manifest with no `background` key at all** (a content-script-only extension) — `manifest.background?.type` must not throw, must default to `'script'`. Owned by Task 6.

---

## Task 1: Parse, locate, chrome-api leaf — the foundational vertical slice

**Files:**
- Modify: `package.json` (add `acorn` dependency)
- Modify: `src/audit.js` (new imports, new functions, `collectMessagePassing` signature + body change)
- Create: `test/audit-callgraph.test.js`

**Interfaces:**
- Produces: `export function buildHandlerCallGraph(content, matchIndex, sourceType = 'script')` → `Array<{ name?, kind, path? }>`. Convenience wrapper for direct unit testing — parses `content` itself.
- Produces (internal, not exported): `buildCallGraphFromProgram(program, matchIndex)` → same return shape, operates on an already-parsed `acorn` `Program` node. Used by `collectMessagePassing` to avoid re-parsing per listener.
- Produces: `collectMessagePassing(dir, manifest = {})` — same export name, now takes an optional second parameter; every object in its returned array's `listener` sub-object (when non-null) gains `calls`.
- Consumes (from existing code, unchanged): `walkFiles`, `isSupersededByUnpack`, `isWakaruOutput`, `isHumanifyOutput`, `relPath`, `lineOf`, `extractDiscriminants`, `ADD_LISTENER_RE`, `SEND_MESSAGE_CALL_RE` — all already in `src/audit.js`.

- [ ] **Step 1: Add the acorn dependency**

```bash
cd /private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-untrusted/repo
npm install acorn@^8.19.0
```

Confirm `package.json`'s `dependencies` now includes `"acorn": "^8.19.0"` and `package-lock.json` changed.

- [ ] **Step 2: Write the failing tests**

Create `test/audit-callgraph.test.js`:

```js
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
```

- [ ] **Step 3: Run the new tests to verify they fail**

Run: `node --test test/audit-callgraph.test.js`
Expected: FAIL — `buildHandlerCallGraph is not a function` (it doesn't exist yet), or an import error.

- [ ] **Step 4: Implement `buildHandlerCallGraph`/`buildCallGraphFromProgram` and wire into `collectMessagePassing`**

Add near the top of `src/audit.js`, with the other imports:

```js
import * as acorn from 'acorn';
```

Add after the existing `collectMessagePassing`-related constants (after `MESSAGE_DISCRIMINANT_PROXIMITY_CHARS`, before `extractDiscriminants`), this whole new block:

```js
// R16: a real call graph for the listener (callee) side of a message handler -- what
// chrome.*/network calls it can reach, and the local-function chain leading to each one.
// Deliberately NOT the sender side (see design spec). Bounded to 4 hops of local-function
// calls, same-file only -- see the spec's "Known limitations" for exactly what this does
// not attempt (alias tracking, nested-closure resolution, cross-file resolution).
const CALL_GRAPH_MAX_DEPTH = 4;
const NETWORK_CALLEE_NAMES = new Set(['fetch']);
const NETWORK_CONSTRUCTOR_NAMES = new Set(['XMLHttpRequest', 'WebSocket']);

// Generic deep walk: finds every CallExpression/NewExpression anywhere in a subtree,
// including inside nested function literals (an inline listener IS a nested function
// literal relative to the file's top level, and a .then()/setTimeout() callback inside it
// is itself nested further -- all of that is genuinely "what this function body does").
// Does not stop at function boundaries; only the hop-by-hop resolution in
// buildCallGraphFromProgram decides what counts as a new hop vs. the same hop's flat list.
function deepCollectCallSites(root) {
  const calls = [];
  function visit(node) {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      for (const item of node) visit(item);
      return;
    }
    if (node.type === 'CallExpression' || node.type === 'NewExpression') calls.push(node);
    for (const key of Object.keys(node)) {
      if (key === 'start' || key === 'end' || key === 'loc' || key === 'range' || key === 'type') continue;
      const value = node[key];
      if (value && typeof value === 'object') visit(value);
    }
  }
  visit(root);
  return calls;
}

// Reconstructs a clean MemberExpression chain rooted at a plain Identifier into a dotted
// string (e.g. "chrome.storage.local.set"). Returns null for anything that isn't a clean
// chain -- computed/bracket access, a call in the middle -- so chrome-api classification
// below only matches the literal dotted-call shape the spec defines, nothing looser.
function dottedChain(node) {
  const parts = [];
  let current = node;
  while (current.type === 'MemberExpression') {
    if (current.computed) return null;
    if (current.property.type !== 'Identifier') return null;
    parts.unshift(current.property.name);
    current = current.object;
  }
  if (current.type !== 'Identifier') return null;
  parts.unshift(current.name);
  return parts.join('.');
}

// Finds every top-level (file-scope) named function this file declares, by the two shapes
// that matter: `function foo() {}` and `const foo = function/(...)=>{}`. Deliberately not
// recursive into nested scopes -- see the spec's "No nested-closure scope resolution".
function collectTopLevelFunctions(programBody) {
  const map = new Map();
  for (const stmt of programBody) {
    if (stmt.type === 'FunctionDeclaration' && stmt.id) {
      map.set(stmt.id.name, stmt);
    } else if (stmt.type === 'VariableDeclaration') {
      for (const decl of stmt.declarations) {
        if (
          decl.id?.type === 'Identifier' &&
          decl.init &&
          (decl.init.type === 'FunctionExpression' || decl.init.type === 'ArrowFunctionExpression')
        ) {
          map.set(decl.id.name, decl.init);
        }
      }
    }
  }
  return map;
}

// Classifies one CallExpression/NewExpression. Returns null for a NewExpression that isn't
// a recognized network constructor (new Map(), new Date(), etc.) -- those aren't calls this
// analysis tracks at all, not even as 'unresolved'.
function classifyCall(node) {
  if (node.type === 'NewExpression') {
    if (node.callee.type === 'Identifier' && NETWORK_CONSTRUCTOR_NAMES.has(node.callee.name)) {
      return { kind: 'network', name: node.callee.name };
    }
    return null;
  }
  const callee = node.callee;
  if (callee.type === 'Identifier') {
    if (NETWORK_CALLEE_NAMES.has(callee.name)) return { kind: 'network', name: callee.name };
    return { kind: 'identifier', name: callee.name };
  }
  if (callee.type === 'MemberExpression') {
    const dotted = dottedChain(callee);
    if (dotted && (dotted.startsWith('chrome.') || dotted.startsWith('browser.'))) {
      return { kind: 'chrome-api', name: dotted };
    }
    return { kind: 'unresolved', name: dotted ?? '(complex member expression)' };
  }
  return { kind: 'unresolved', name: '(non-identifier callee)' };
}

/**
 * The call graph for one already-located listener function, walked from an already-parsed
 * acorn Program. See the design spec (docs/superpowers/specs/2026-10-12-message-handler-call-graph-design.md)
 * for the full algorithm description; this is its direct implementation.
 */
function buildCallGraphFromProgram(program, matchIndex) {
  const allCalls = deepCollectCallSites(program);
  const callExprAtMatch = allCalls.find((n) => n.type === 'CallExpression' && n.callee.start === matchIndex);
  if (!callExprAtMatch) return [{ kind: 'unresolved' }];

  const topLevelFns = collectTopLevelFunctions(program.body);

  const firstArg = callExprAtMatch.arguments[0];
  let startNode = null;
  let startName = '(anonymous)';
  if (firstArg?.type === 'Identifier') {
    startName = firstArg.name;
    startNode = topLevelFns.get(firstArg.name) ?? null;
  } else if (firstArg?.type === 'FunctionExpression' || firstArg?.type === 'ArrowFunctionExpression') {
    startNode = firstArg;
    startName = firstArg.id?.name ?? '(anonymous)';
  }
  if (!startNode) return [{ kind: 'unresolved', name: firstArg?.name, path: [startName] }];

  const results = [];
  function walk(fnNode, path, visited) {
    for (const callNode of deepCollectCallSites(fnNode.body)) {
      const classified = classifyCall(callNode);
      if (!classified) continue;

      if (classified.kind !== 'identifier') {
        results.push({ name: classified.name, kind: classified.kind, path: [...path, classified.name] });
        continue;
      }

      const target = topLevelFns.get(classified.name);
      if (!target) {
        results.push({ name: classified.name, kind: 'unresolved', path: [...path, classified.name] });
      } else if (visited.has(target)) {
        results.push({ name: classified.name, kind: 'cycle', path: [...path, classified.name] });
      } else if (path.length >= CALL_GRAPH_MAX_DEPTH) {
        results.push({ name: classified.name, kind: 'depth-limit', path: [...path, classified.name] });
      } else {
        walk(target, [...path, classified.name], new Set([...visited, target]));
      }
    }
  }

  walk(startNode, [startName], new Set([startNode]));
  return results;
}

/**
 * Convenience wrapper for direct unit testing: parses `content` itself and delegates to
 * buildCallGraphFromProgram. Production code (collectMessagePassing below) calls
 * buildCallGraphFromProgram directly instead, so a file with multiple listeners is only
 * parsed once.
 */
export function buildHandlerCallGraph(content, matchIndex, sourceType = 'script') {
  let program;
  try {
    program = acorn.parse(content, { ecmaVersion: 'latest', sourceType, allowReturnOutsideFunction: true });
  } catch {
    return [{ kind: 'unparseable' }];
  }
  return buildCallGraphFromProgram(program, matchIndex);
}
```

Now modify `collectMessagePassing` itself. Change the signature and the per-file loop body:

```js
export function collectMessagePassing(dir, manifest = {}) {
  const senders = [];
  const listeners = [];
  const jsFiles = walkFiles(dir, { extensions: ['.js'] });
  const sourceType = manifest.background?.type === 'module' ? 'module' : 'script';

  for (const file of jsFiles) {
    if (isSupersededByUnpack(file) || isWakaruOutput(file) || isHumanifyOutput(file)) continue;
    const rel = relPath(dir, file);
    const content = readFileSync(file, 'utf8');

    let program = null;
    try {
      program = acorn.parse(content, { ecmaVersion: 'latest', sourceType, allowReturnOutsideFunction: true });
    } catch {
      program = null;
    }

    SEND_MESSAGE_CALL_RE.lastIndex = 0;
    let m;
    while ((m = SEND_MESSAGE_CALL_RE.exec(content)) !== null) {
      senders.push({ file: rel, line: lineOf(content, m.index), kind: m[1], discriminants: extractDiscriminants(content, m.index) });
    }

    ADD_LISTENER_RE.lastIndex = 0;
    while ((m = ADD_LISTENER_RE.exec(content)) !== null) {
      const calls = program ? buildCallGraphFromProgram(program, m.index) : [{ kind: 'unparseable' }];
      listeners.push({ file: rel, line: lineOf(content, m.index), kind: m[1], discriminants: extractDiscriminants(content, m.index), calls });
    }
  }

  const senderCounts = countByDiscriminant(senders);
  const listenerCounts = countByDiscriminant(listeners);
  const candidates = [];
  const matchedSenders = new Set();
  const matchedListeners = new Set();

  senders.forEach((sender, si) => {
    listeners.forEach((listener, li) => {
      const shared = sender.discriminants.filter((d) => listener.discriminants.includes(d));
      if (shared.length === 0) return;
      const unique = shared.every((d) => senderCounts.get(d) === 1 && listenerCounts.get(d) === 1);
      candidates.push({
        sender: { file: sender.file, line: sender.line, kind: sender.kind },
        listener: { file: listener.file, line: listener.line, kind: listener.kind, calls: listener.calls },
        discriminants: shared,
        confidence: unique ? 'exact' : 'probable',
      });
      matchedSenders.add(si);
      matchedListeners.add(li);
    });
  });

  senders.forEach((sender, si) => {
    if (matchedSenders.has(si)) return;
    candidates.push({
      sender: { file: sender.file, line: sender.line, kind: sender.kind },
      listener: null,
      discriminants: sender.discriminants,
      confidence: 'ambiguous',
    });
  });
  listeners.forEach((listener, li) => {
    if (matchedListeners.has(li)) return;
    candidates.push({
      sender: null,
      listener: { file: listener.file, line: listener.line, kind: listener.kind, calls: listener.calls },
      discriminants: listener.discriminants,
      confidence: 'ambiguous',
    });
  });

  return candidates;
}
```

This is the ENTIRE function body — replace the existing `collectMessagePassing` function (currently spanning from `export function collectMessagePassing(dir) {` to its closing `}` just before the `// R2: endpoint method/shape capture` comment) with this version in full. Every line outside the `program`/`calls` additions is byte-identical to the existing code — do not restructure anything else.

Update the one production call site in `auditExtension` (around line 445):

```js
  const messagePassing = collectMessagePassing(dir, manifest);
```

(Change from `collectMessagePassing(dir)` — `manifest` is already in scope in `auditExtension`.)

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `node --test test/audit-callgraph.test.js`
Expected: PASS, all 5 tests.

- [ ] **Step 6: Confirm backward compatibility**

Run: `node --test test/audit-messagemap.test.js`
Expected: PASS, all 3 pre-existing tests unchanged (they call `collectMessagePassing(dir)` with no second argument).

- [ ] **Step 7: Run the full suite**

Run: `npm test`
Expected: PASS, every test (the pre-existing 203 plus the 5 new ones in this task).

- [ ] **Step 8: Commit**

```bash
git add package.json package-lock.json src/audit.js test/audit-callgraph.test.js
git commit -m "feat: add a real call graph for message-handler listeners

collectMessagePassing() already pairs sendMessage/addListener call sites
by discriminant, but said nothing about what a listener actually does once
it receives a message. New buildHandlerCallGraph (+ internal
buildCallGraphFromProgram), both in src/audit.js: parses the file with
acorn, locates the regex-matched listener's callback node by character
offset, and reports every direct chrome.* API call it can reach -- the
foundation this piece's later tasks build multi-hop/network/cycle handling
onto.

New real dependency: acorn. Unlike wakaru/humanify, a real call graph
needs a real AST, not a shelled-out CLI.

collectMessagePassing(dir, manifest = {}) -- manifest is optional, so all
existing callers (including every test in audit-messagemap.test.js) are
unaffected. A parse failure degrades to calls: [{kind: 'unparseable'}] for
every listener in that file, verified not to affect any other file's
results."
```

---

## Task 2: Network leaf classification + unresolved member-expression leaf

**Files:**
- Modify: `src/audit.js` (no new functions — `classifyCall` from Task 1 already handles this; this task is tests only, confirming existing logic)
- Modify: `test/audit-callgraph.test.js`

**Interfaces:**
- Consumes: `buildHandlerCallGraph` (Task 1, unchanged signature).
- Produces: nothing new — this task is verification that Task 1's `classifyCall` already correctly handles `network` and generic `unresolved` member-expression cases, which it does by construction, but was not yet tested directly.

- [ ] **Step 1: Write the failing tests**

Add to `test/audit-callgraph.test.js`:

```js
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
```

- [ ] **Step 2: Run tests to verify they fail or pass**

Run: `node --test test/audit-callgraph.test.js`
Expected: these 4 should already PASS, since `classifyCall` (Task 1) already implements this logic — this task exists to pin it down with explicit tests, not to add new behavior. If any fails, that reveals a Task 1 bug to fix now, not a missing feature.

- [ ] **Step 3: If all pass, commit the tests alone**

```bash
git add test/audit-callgraph.test.js
git commit -m "test: pin network/unresolved call-graph classification explicitly

classifyCall (Task 1) already handles fetch/XMLHttpRequest/WebSocket and
generic unresolved member-expressions correctly; these tests make that
explicit and regression-proof rather than leaving it as untested
incidental behavior."
```

If any test fails, fix `classifyCall`/`deepCollectCallSites` in `src/audit.js` first, re-run, then commit both files together with a `fix:` message describing what was wrong.

---

## Task 3: Multi-hop local-function resolution + unresolved identifier

**Files:**
- Modify: `test/audit-callgraph.test.js`

**Interfaces:**
- Consumes: `buildHandlerCallGraph`, `collectTopLevelFunctions`, `classifyCall`, the `walk()` recursion inside `buildCallGraphFromProgram` (all Task 1).
- Produces: nothing new in source — same situation as Task 2, this task adds the tests that exercise the *recursive* branch of `walk()` (an `identifier` call that resolves to a top-level function), which Tasks 1-2's tests never triggered (their fixtures only had depth-1 calls).

- [ ] **Step 1: Write the failing tests**

Add to `test/audit-callgraph.test.js`:

```js
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
```

- [ ] **Step 2: Run to verify current state**

Run: `node --test test/audit-callgraph.test.js`
Expected: PASS. The `walk()` recursion and the `identifier`/unresolved branches were already written in Task 1; this task's tests are the first to actually exercise them. If any fails, fix `buildCallGraphFromProgram` in `src/audit.js` now.

- [ ] **Step 3: Run the full suite**

Run: `npm test`
Expected: PASS, no regressions.

- [ ] **Step 4: Commit**

```bash
git add test/audit-callgraph.test.js
git commit -m "test: pin multi-hop local-function call-graph resolution

Tasks 1-2's fixtures only ever reached depth 1; these tests are the first
to exercise walk()'s recursive branch (a bare-identifier call resolving to
a top-level function, extending path and continuing one hop deeper) and
the unresolved-identifier fallback when no top-level declaration matches."
```

---

## Task 4: Cycle detection + depth cap

**Files:**
- Modify: `test/audit-callgraph.test.js`

**Interfaces:**
- Consumes: the `visited` set and `path.length >= CALL_GRAPH_MAX_DEPTH` check inside `walk()` (Task 1).
- Produces: nothing new in source — same pattern as Tasks 2-3.

- [ ] **Step 1: Write the failing tests**

Add to `test/audit-callgraph.test.js`:

```js
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
  assert.ok(!calls.some((c) => c.name === 'fetch'), 'f5/fetch is never reached -- the cap actually stopped recursion');
});
```

- [ ] **Step 2: Run to verify current state**

Run: `node --test test/audit-callgraph.test.js`
Expected: PASS — the `visited` set and depth check were written in Task 1. If the depth-cap test fails, check the exact `path.length` comparison against `CALL_GRAPH_MAX_DEPTH` in `walk()` and adjust if the off-by-one doesn't match (the test asserts a `depth-limit` entry exists and `fetch` is never reached — it does not assert which exact function name triggers it, so a one-hop shift in exactly where the cap fires does not need a test change, only a `walk()` fix if the cap doesn't fire at all or fires too early to ever reach `f4`).

- [ ] **Step 3: Run the full suite**

Run: `npm test`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add test/audit-callgraph.test.js
git commit -m "test: pin cycle detection (self and mutual recursion) and the 4-hop depth cap

Confirms the visited-set in walk() prevents both direct self-recursion
and mutual A<->B recursion from infinite-looping, and that a chain longer
than CALL_GRAPH_MAX_DEPTH stops with a named depth-limit entry rather than
either crashing or silently truncating with no indication."
```

---

## Task 5: Named-function-reference listener (`addListener(myHandler)`)

**Files:**
- Modify: `test/audit-callgraph.test.js`

**Interfaces:**
- Consumes: the `firstArg?.type === 'Identifier'` branch in `buildCallGraphFromProgram` (Task 1).

- [ ] **Step 1: Write the failing test**

Add to `test/audit-callgraph.test.js`:

```js
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
```

- [ ] **Step 2: Run to verify current state**

Run: `node --test test/audit-callgraph.test.js`
Expected: PASS — this branch was written in Task 1. If it fails, fix the `firstArg?.type === 'Identifier'` branch in `buildCallGraphFromProgram`.

- [ ] **Step 3: Run the full suite**

Run: `npm test`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add test/audit-callgraph.test.js
git commit -m "test: pin named-function-reference listener resolution

addListener(myHandler) -- a listener registered by reference rather than
an inline function literal -- resolves myHandler the same way any other
bare-identifier call would, including the unresolved case when no
matching top-level declaration exists."
```

---

## Task 6: ES module sourceType plumbing

**Files:**
- Modify: `test/audit-callgraph.test.js`

**Interfaces:**
- Consumes: `collectMessagePassing(dir, manifest)`'s `sourceType` selection (Task 1).

- [ ] **Step 1: Write the failing tests**

Add to `test/audit-callgraph.test.js`:

```js
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
    'content.js': `
chrome.runtime.onMessage.addListener((msg) => {
  chrome.storage.local.set({ ok: true });
});
`,
  });
  assert.doesNotThrow(() => collectMessagePassing(dir, {}));
  const map = collectMessagePassing(dir, {});
  const entry = map.find((c) => c.listener);
  assert.deepEqual(entry.listener.calls, [
    { name: 'chrome.storage.local.set', kind: 'chrome-api', path: ['(anonymous)', 'chrome.storage.local.set'] },
  ]);
});
```

- [ ] **Step 2: Run to verify current state**

Run: `node --test test/audit-callgraph.test.js`
Expected: PASS — `sourceType` selection was written in Task 1 (`manifest.background?.type === 'module' ? 'module' : 'script'`, which already handles a missing `background` key via optional chaining). If the module test fails, check that `acorn.parse` is actually receiving `sourceType: 'module'` for this manifest shape.

- [ ] **Step 3: Run the full suite**

Run: `npm test`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add test/audit-callgraph.test.js
git commit -m "test: pin ES module sourceType selection and the no-background-key default

A module service worker's import/export syntax must not be treated as a
parse failure; a manifest with no background key at all (content-script-
only extension) must not throw and must default to script sourceType."
```

---

## Task 7: Real-download verification + regression check

**Files:**
- No source changes. Verification only.

This task uses a fixed literal scratch path (not `mktemp -d`) because each step below is a separate shell invocation — an exported variable from one step's shell does not survive into the next step's shell in this environment. Every command below reuses the exact same literal path for that reason.

- [ ] **Step 1: Set up a scratch directory and extract the real fixture**

`crxray` has no CLI mode for a local `.crx` file directly — `crxray audit <dir>` takes an already-unpacked directory. Extract the fixture's ZIP payload (stripping the CRX header) using the already-exported `crxToZip`/`extractZip` from `src/crx.js`/`src/zip.js`:

```bash
cd /private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-untrusted/repo
rm -rf /private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-callgraph-verify
mkdir -p /private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-callgraph-verify
node --input-type=module -e "
import { readFileSync } from 'node:fs';
import { crxToZip } from './src/crx.js';
import { extractZip } from './src/zip.js';
const buf = readFileSync('test/fixtures/react-devtools.crx');
extractZip(crxToZip(buf), '/private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-callgraph-verify/extracted');
console.log('extracted to /private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-callgraph-verify/extracted');
"
```

- [ ] **Step 2: Capture the "after" output (current code, with this plan's changes)**

```bash
cd /private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-untrusted/repo
node bin/crxray.js audit /private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-callgraph-verify/extracted --json > /private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-callgraph-verify/after.json
```

- [ ] **Step 3: Capture the "before" output (pre-this-plan code, same extracted directory)**

```bash
cd /private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-untrusted/repo
git stash
node bin/crxray.js audit /private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-callgraph-verify/extracted --json > /private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-callgraph-verify/before.json
git stash pop
```

- [ ] **Step 4: Diff, ignoring only the new field**

```bash
cd /private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-untrusted/repo
node -e "
const before = JSON.parse(require('fs').readFileSync('/private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-callgraph-verify/before.json', 'utf8'));
const after = JSON.parse(require('fs').readFileSync('/private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-callgraph-verify/after.json', 'utf8'));
function stripCalls(obj) {
  if (Array.isArray(obj)) return obj.map(stripCalls);
  if (obj && typeof obj === 'object') {
    const copy = {};
    for (const [k, v] of Object.entries(obj)) {
      if (k === 'calls') continue;
      copy[k] = stripCalls(v);
    }
    return copy;
  }
  return obj;
}
const beforeStripped = JSON.stringify(stripCalls(before));
const afterStripped = JSON.stringify(stripCalls(after));
console.log('Every field except calls is identical:', beforeStripped === afterStripped);
if (beforeStripped !== afterStripped) {
  console.log('MISMATCH -- investigate before proceeding.');
  process.exit(1);
}
const listenersWithCalls = (after.messagePassing ?? []).filter((c) => c.listener?.calls?.length);
console.log('Listeners with non-empty calls:', listenersWithCalls.length);
console.log(JSON.stringify(listenersWithCalls.slice(0, 3), null, 2));
"
```

Expected: `Every field except calls is identical: true`. The printed sample `calls` entries are expected to show real `unresolved`/`depth-limit` entries on this real, likely-bundled extension — that is a correct, honest result on bundled code (per the spec's own testing-plan note), not a bug to chase.

- [ ] **Step 5: Confirm no stack overflow on the real, full-size file**

The audit run in Step 2 either completed (no crash) or it didn't. If it threw a `RangeError: Maximum call stack size exceeded`, that is a real finding from this task (the Review Focus item on large/deeply-nested real files) — stop and fix `deepCollectCallSites`/`walk` to be iterative (an explicit work-stack/queue instead of native recursion) rather than proceeding, since this would mean the feature crashes on real-world input it's specifically meant to handle.

- [ ] **Step 6: Run the full suite one final time**

```bash
cd /private/tmp/claude-501/-Users-chadcrawford-repos-chrome-extensions/20e81405-d1fd-4109-b596-2cc9951605f8/scratchpad/crxray-untrusted/repo
npm test
```

Expected: PASS, every test (pre-existing 203 + all new tests from Tasks 1-6).

- [ ] **Step 7: No commit for this task**

This task is verification only — nothing in the working tree should have changed (the `git stash`/`git stash pop` in Step 3 round-trips cleanly). Confirm with `git status --short` that it's clean before reporting this task done.
