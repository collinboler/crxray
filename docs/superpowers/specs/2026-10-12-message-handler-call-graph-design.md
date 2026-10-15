# Message-handler call graph: design spec

**Status:** Approved in chat, pending written-spec review.
**Depends on:** `src/audit.js`'s existing `collectMessagePassing()` (piece 6 of PR #1).

## Goal

`collectMessagePassing()` already pairs `chrome.runtime.sendMessage`/`connect` call
sites against `onMessage`/`onConnect` listener call sites by inferable discriminant.
It answers *who talks to whom*. It does not answer *what the listener actually does*
once it receives a message — the handler's own downstream calls (another `chrome.*`
API, a network request, a locally-defined helper function) are invisible.

This piece adds a real call graph for the **listener (callee) side only**: starting
from a matched `addListener` callback, follow the calls it makes, recursively, up to
a bounded depth, and report every `chrome.*`/network call it can reach, with the
local-function call chain that leads to it.

**Non-goal, explicit:** the sender side — what leads *up to* a `sendMessage()` call —
is a different, backward-facing question. Not attempted here.

## Where it lives

Inside the default static audit pipeline, in `src/audit.js`, alongside
`collectMessagePassing()` — not behind the opt-in `capture-behavior` flag. A call
graph is static analysis (reading code without running it), the same category as
`collectMessagePassing()` itself, not the dynamic-capture category pieces 7-12 lived
in. It therefore runs on every plain `crxray audit`, and since `captureBehavior()`
already calls `auditExtension()` before launching Chrome (piece 8), the dynamic
`mechanism.js` cross-reference gets this data for free, no extra wiring.

This is the first piece since piece 6 to touch `src/audit.js` — pieces 8-12's own
"zero diff to audit.js/index.js/bin/crxray.js" framing does not apply to this piece,
consistent with pieces 3 and 6, which also modified `audit.js` directly. The
regression check for this piece is instead: every field `collectMessagePassing()`
already produces is unchanged in shape and value; `calls` is a strictly additive new
field on each listener entry.

## New dependency

`acorn` (`^8.x`), added to `package.json`'s real `dependencies` — the first new
runtime dependency this PR has added. `wakaru`/`humanify` were deliberately kept out
of `dependencies` via `npx`/binary shell-out; a real call graph needs a real AST, not
a shelled-out CLI, so this is a different kind of tool and a direct dependency is the
right shape for it.

No `acorn-walk` companion package. The only node shapes this needs to recognize —
`CallExpression`, a top-level `FunctionDeclaration`, a top-level `const` bound to a
`FunctionExpression`/`ArrowFunctionExpression` — don't need a general visitor
framework; a small hand-rolled recursive walker is simpler to read and to bound
(the depth cap below needs to be enforced by the walker itself, which is easier to
reason about without a third-party traversal abstraction in the way).

## Algorithm

### 1. Parse once per file

Inside `collectMessagePassing()`'s existing per-file loop (where `content` is
already read via `readFileSync`), parse `content` once with
`acorn.parse(content, { ecmaVersion: 'latest', sourceType, allowReturnOutsideFunction: true })`.
`sourceType` is `'module'` when the extension's `manifest.background.type === 'module'`
(ES module service worker), else `'script'`.

A parse failure (malformed/truncated file, or a shape acorn can't handle) is caught
per-file: every listener matched by the existing `ADD_LISTENER_RE` regex in that file
gets `calls: [{ kind: 'unparseable' }]`, and the rest of `collectMessagePassing()`'s
existing regex-based matching (senders, listeners, discriminant pairing) proceeds
completely unaffected — this new step can never cause the pre-existing capability to
regress or crash the audit run, same "never let one bad file kill the pass" posture
`walkFiles` and the entropy/secrets scanners already have.

### 2. Locate the listener's callback node

`ADD_LISTENER_RE`'s match gives `m.index`, the character offset where
`chrome.runtime.onMessage.addListener(` (or the `browser.*`/`onConnect` variant)
begins in the raw text — the same offset a `CallExpression` node's `callee` would
start at, since both the regex and acorn tokenize the identical source text from the
identical position.

Walk the parsed `Program` body (top-level statements only, recursing into them to
find nested `CallExpression`s — this walk is separate from, and simpler than, the
call-graph walk in step 3) to find the `CallExpression` whose `callee.start === m.index`
and whose callee is a `MemberExpression` ending in `.addListener`. Its `arguments[0]`
(expected to be a `FunctionExpression` or `ArrowFunctionExpression`) is the call
graph's starting node. If `arguments[0]` isn't a function literal (e.g. a listener
registered by passing a named function reference, `addListener(myHandler)`), resolve
`myHandler` the same way step 3 resolves any bare-identifier call — a top-level
function declaration/const-assigned function in the same file, or `unresolved` if not
found there.

If no matching `CallExpression` is found at that offset at all (should not happen
given the regex/acorn-offset correlation above, but handled defensively), that
listener gets `calls: [{ kind: 'unresolved' }]` rather than throwing.

### 3. Walk calls from the listener, bounded

Starting from the listener's function body, recursively visit every
`CallExpression` reachable within it, up to **4 hops** (a documented, honest budget,
same spirit as this codebase's other proximity constants —
`SAME_SESSION_PROXIMITY_MS`, `ENTROPY_PROXIMITY_CHARS`,
`MESSAGE_DISCRIMINANT_PROXIMITY_CHARS`). A visited-set of function AST nodes already
on the current path prevents infinite recursion on mutual/self recursion — revisiting
a node already on the path stops that branch with `kind: 'cycle'` rather than
recursing again.

Each `CallExpression` classifies as one of:

- **`chrome-api`**: the callee is a `MemberExpression` chain whose innermost `object`
  is a bare `Identifier` named `chrome` or `browser`, and every `object` in the chain
  between that identifier and the final call is itself a plain `MemberExpression`
  (never a `CallExpression`, never a computed/bracket access) — i.e. the chain
  reconstructs cleanly into a dotted string like `chrome.storage.local.set` by
  concatenating each `property.name` from outermost identifier to innermost call.
  **Leaf — never recursed into further** (nothing further to parse for a
  native/external API).
- **`network`**: the callee is a bare `fetch`, `XMLHttpRequest` (as `new XMLHttpRequest()`
  or a method call on one), or `WebSocket` constructor call. **Leaf.**
- **local function call, recursed**: the callee is a *bare identifier* (`foo()`, not
  `obj.foo()`) that resolves to a **top-level** (file-scope) `FunctionDeclaration` or
  a `const`/`let` binding whose initializer is a `FunctionExpression`/
  `ArrowFunctionExpression`. Recurse into that function's body, incrementing the hop
  count and extending `path`. This is name resolution against file scope only — no
  nested-closure scope tracking, no block-scope shadowing, no hoisting edge cases.
  A minifier that reuses a short name across different nested scopes can cause this
  to resolve to the wrong same-named top-level binding, or to find none at all; both
  outcomes degrade to `unresolved`/a wrong-but-harmless path entry, never a crash.
- **`unresolved`**: anything else — a member-expression call that isn't
  `chrome.*`/`browser.*`/a recognized network call (e.g. `obj.method()` on an
  arbitrary local object, a cross-file import, a bundler's module-reference call
  like `n(123)`), or a bare identifier that doesn't resolve to a top-level function
  in this file. **Leaf — never recursed into.** Resolving arbitrary method calls on
  arbitrary objects, or following cross-file/module-bundler references, is a
  materially harder problem (real scope-aware type inference, or a dependency on
  wakaru's own module map) explicitly out of scope for this piece.
- **Hitting the 4-hop cap** with a local function call still unresolved into: reported
  as `kind: 'depth-limit'` rather than silently stopping, naming the boundary instead
  of hiding it.

### 4. Output

Each `messagePassing` listener entry (produced in the existing `candidates.push(...)`
calls inside `collectMessagePassing()`) gains one new field:

```json
"calls": [
  { "name": "fetch", "kind": "network", "path": ["onMessageHandler", "processRequest", "fetch"] },
  { "name": "chrome.storage.local.set", "kind": "chrome-api", "path": ["onMessageHandler", "chrome.storage.local.set"] },
  { "name": "n", "kind": "unresolved", "path": ["onMessageHandler", "n"] }
]
```

`path` always starts with the listener's own name (or `"(anonymous)"` for an inline
arrow/function literal) and ends with the leaf's own call name. Flat array, no nested
tree — consistent with how `mechanism.endpoints`/`mechanism.messages` and
`timeline.edges` are already shaped in this codebase: scannable arrays of flat
objects, not nested graphs.

## Known limitations, named up front

- **No alias tracking.** `const c = chrome; c.storage.local.set(...)` or
  `const f = fetch; f(...)` — a common minification pattern (aliasing a global to a
  short local name) — will not be recognized as `chrome-api`/`network`; the chain's
  innermost identifier is `c`/`f`, not `chrome`/`fetch`, so it falls through to
  `unresolved`. Real, not hypothetical, on minified bundles. Not attempted in v1:
  tracking which local bindings are aliases of which globals is a real (if small)
  extension of the resolution rule, left for a later piece if it turns out to matter
  in practice against real downloads.
- **No nested-closure scope resolution.** Only top-level (file-scope) function
  bindings are resolved; a helper function defined *inside* another function (not at
  the top level) is invisible to the resolver and any call to it is `unresolved`,
  even though a human reader tracing the same code by eye would find it immediately.
- **No cross-file/import resolution.** An ES module `import`, a classic script's
  `importScripts()`-loaded sibling file, or a bundler's own module-reference call
  (`n(123)`) all resolve to `unresolved` — this piece analyzes one file's own AST
  only.
- **Minifier name collisions.** Resolving a bare identifier call against top-level
  bindings by name alone (no real scope analysis) can resolve to the wrong
  same-named top-level binding if a minifier reuses short names across genuinely
  different scopes. Produces a wrong-but-harmless `path` entry, not a crash.

## Schema

`schema/capture-file.schema.json` is unaffected (that schema covers the dynamic
capture file, not the static `audit` JSON output, which has no formal JSON Schema in
this repo today — consistent with how piece 6's own `messagePassing`/`endpointDetails`
fields were added without one).

## Testing plan

Pure unit tests for the new call-graph function, directly (no Chrome needed),
covering:

- A listener that calls a single `chrome.*` API directly (depth-1 `chrome-api` leaf).
- A listener that calls a local helper, which calls `fetch` (multi-hop `network` leaf,
  `path` length 3).
- Mutual recursion between two local functions (`cycle`, not an infinite loop/stack
  overflow).
- A call to an unresolvable member expression (`obj.method()`) — `unresolved` leaf,
  not recursed into.
- A call to an identifier with no matching top-level declaration — `unresolved` leaf.
- A chain of local calls deeper than 4 hops — `depth-limit` at the cap, not silently
  truncated with no indication.
- A deliberately malformed/truncated file — `calls: [{ kind: 'unparseable' }]` for
  every listener in that file, and confirmation the rest of `collectMessagePassing()`
  (senders, other files' listeners, discriminant pairing) is completely unaffected.
- A listener registered via a named function reference (`addListener(myHandler)`)
  rather than an inline function literal — resolves `myHandler` the same way a
  bare-identifier call would.

Plus one real-download check against an extension already used earlier this session
(e.g. React Developer Tools, already confirmed to have a real message-passing `exact`
match in its minified background bundle) — confirming the call graph produces real,
sane output on actual minified code, with real `unresolved`/`depth-limit` entries
expected as a correct, honest result on bundled code, not treated as a bug to chase
away with a wider heuristic.

## R10-equivalent regression check for this piece

Since this piece modifies `audit.js` (unlike pieces 8-12), the applicable check is:
run `crxray audit` against a real extension already used this session, before and
after this change, and confirm every existing field (`findings`, `endpoints`,
`correlations`, `messagePassing[].sender`/`.listener`/`.discriminants`/`.confidence`,
`endpointDetails`, etc.) is byte-identical except for the new `calls` field being
additively present on each listener entry.
