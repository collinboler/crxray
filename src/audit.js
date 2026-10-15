import { readFileSync } from 'node:fs';
import path from 'node:path';
import * as acorn from 'acorn';
import { buildEntryPointMap } from './map.js';
import { walkFiles, relPath, isSupersededByUnpack, isWakaruOutput, isHumanifyOutput } from './walk.js';

const HIGH_RISK_PERMISSIONS = new Set([
  'webRequest',
  'webRequestBlocking',
  'cookies',
  'nativeMessaging',
  'debugger',
  'proxy',
  'management',
  'desktopCapture',
  'declarativeNetRequestWithHostAccess',
  'browsingData',
  'history',
  'clipboardRead',
  'geolocation',
  'downloads',
  'tabs',
]);

const MEDIUM_RISK_PERMISSIONS = new Set([
  'scripting',
  'activeTab',
  'notifications',
  'identity',
  'privacy',
  'sessions',
  'bookmarks',
]);

const SUSPICIOUS_PATTERNS = [
  { id: 'eval', label: 'eval()', re: /\beval\s*\(/g, severity: 'high' },
  // Matches both `new Function(...)` and a bare `Function(...)` call --
  // the latter runs identically to the former for this purpose and was a
  // confirmed total blind spot (red-team finding) when `new` was required.
  // The optional `new\s+` group means a real `new Function(` still counts
  // once, not twice: the engine consumes it as a single match.
  { id: 'function-constructor', label: 'Function() constructor', re: /\b(?:new\s+)?Function\s*\(/g, severity: 'high' },
  { id: 'atob', label: 'atob() decoding', re: /\batob\s*\(/g, severity: 'medium' },
  // setTimeout(decodedPayload, 0)/setInterval(...) implicitly execute a
  // string argument exactly like eval() does. There was previously zero
  // pattern coverage for either call at all -- a confirmed total blind
  // spot (red-team finding), not just a miss on the entropy-companion
  // pairing below. Low severity: both calls are ubiquitous and almost
  // always benign on their own; the real signal is pairing with a nearby
  // high-entropy literal, same as atob.
  { id: 'settimeout-string', label: 'setTimeout()/setInterval()', re: /\b(?:setTimeout|setInterval)\s*\(/g, severity: 'low' },
  { id: 'document-write', label: 'document.write()', re: /\bdocument\.write\s*\(/g, severity: 'medium' },
  { id: 'chrome-cookies', label: 'chrome.cookies access', re: /\b(?:chrome|browser)\.cookies\b/g, severity: 'high' },
  { id: 'chrome-webRequest', label: 'chrome.webRequest access', re: /\b(?:chrome|browser)\.webRequest\b/g, severity: 'high' },
  { id: 'send-beacon', label: 'navigator.sendBeacon()', re: /\bnavigator\.sendBeacon\s*\(/g, severity: 'medium' },
  { id: 'xhr', label: 'XMLHttpRequest', re: /\bnew\s+XMLHttpRequest\s*\(/g, severity: 'low' },
  { id: 'dynamic-import', label: 'dynamic import()', re: /\bimport\s*\(/g, severity: 'low' },
  { id: 'fetch', label: 'fetch()', re: /\bfetch\s*\(/g, severity: 'low' },
  { id: 'websocket', label: 'new WebSocket()', re: /\bnew\s+WebSocket\s*\(/g, severity: 'medium' },
  {
    id: 'runtime-send-message',
    label: 'chrome.runtime.sendMessage/connect',
    re: /\b(?:chrome|browser)\.runtime\.(sendMessage|connect)\s*\(/g,
    severity: 'low',
  },
  {
    id: 'scripting-execute-script',
    label: 'chrome.scripting.executeScript',
    re: /\b(?:chrome|browser)\.scripting\.executeScript\s*\(/g,
    severity: 'high',
  },
  {
    id: 'tabs-execute-script',
    label: 'chrome.tabs.executeScript',
    re: /\b(?:chrome|browser)\.tabs\.executeScript\s*\(/g,
    severity: 'high',
  },
  {
    id: 'external-script-tag',
    label: 'dynamically-created <script> tag',
    re: /createElement\s*\(\s*['"]script['"]\s*\)/g,
    severity: 'medium',
  },
  {
    id: 'chrome-debugger',
    label: 'chrome.debugger access',
    re: /\b(?:chrome|browser)\.debugger\.(attach|sendCommand)\s*\(/g,
    severity: 'high',
  },
  {
    // \w* on Input.dispatch -- the real CDP methods are dispatchKeyEvent /
    // dispatchMouseEvent / dispatchTouchEvent, never the bare verb. Found by
    // independent review: the bare form never matches a real command and
    // was dead weight. Backtick literals accepted alongside quotes.
    id: 'cdp-dangerous-command',
    label: 'CDP dangerous command',
    re: /["'`](Runtime\.evaluate|Network\.enable|Input\.dispatch\w*|Fetch\.enable|Page\.captureScreenshot)["'`]/g,
    severity: 'high',
  },
  // Secret patterns match a real credential SHAPE (prefix + charset + length),
  // never a variable name -- "a variable named password/apikey" is not a
  // secret, it is a password manager's own domain vocabulary. Confirmed as a
  // real false-positive class in a competing tool's secrets detector before
  // these were written.
  {
    // ASIA = temporary/session AWS credentials, alongside the long-lived AKIA.
    id: 'secret-aws-key',
    label: 'AWS access key',
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    severity: 'high',
  },
  {
    // github_pat_ = fine-grained PATs, alongside the classic gh[pousr]_ prefixes.
    id: 'secret-github-token',
    label: 'GitHub token',
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g,
    severity: 'high',
  },
  {
    // pk_ (publishable) is designed to ship in client code, not a secret --
    // dropped. sk_/rk_ (secret/restricted) are real credentials, kept.
    // Found by independent review: the original pk_ match flagged every
    // extension with ordinary Stripe Checkout as a high-severity finding.
    id: 'secret-stripe-key',
    label: 'Stripe key',
    re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b/g,
    severity: 'high',
  },
  {
    // Requires the numeric workspace-id segment real Slack tokens always
    // have right after the type prefix -- excludes placeholder text like
    // "xoxb-your-token-here", which the un-anchored version matched.
    id: 'secret-slack-token',
    label: 'Slack token',
    re: /\bxox[baprs]-\d{6,}-[A-Za-z0-9-]{10,}\b/g,
    severity: 'high',
  },
  {
    // Requires a real base64 body after the header, not just the header
    // constant -- crypto libraries carry the bare header string for format
    // detection/formatting, which the original (header-only) match flagged.
    id: 'secret-rsa-private-key',
    label: 'RSA/SSH private key block',
    re: /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----[A-Za-z0-9+/=\s]{64,}/g,
    severity: 'high',
  },
  // Dark patterns: user-hostile, not necessarily malicious. Kept to two
  // well-defined, low-noise checks -- notification-spam and fingerprinting
  // both need multi-signal/control-flow analysis to avoid flooding on
  // ordinary, benign single API calls (e.g. canvas.toDataURL() alone is a
  // completely normal screenshot feature), so they're left for later rather
  // than shipped as a noisy single-call regex.
  {
    // =(?!=) excludes ===/== comparisons, which the plain [+=] matched.
    // utm_source dropped (pure analytics, not monetization); tag/affid/
    // aff_id/clickid added -- tag= is Amazon's own affiliate parameter and
    // the single most common real case, which the original pattern missed
    // entirely. \n excluded from the gap so a match can't span statements
    // in code without semicolons. Found by independent review.
    id: 'affiliate-link-injection',
    label: 'Affiliate link injection',
    re: /href\s*(?:\+=|=(?!=))[^;\n]{0,80}?[?&](?:ref|aff|affiliate|affid|aff_id|clickid|tag)=/gi,
    severity: 'medium',
  },
  {
    // {0,200} bounds the gap between the store-URL prefix and "review" --
    // the original unbounded [^"'\s]* backtracks catastrophically with no
    // quote/whitespace anywhere nearby: confirmed quadratic (2.6s on 400KB
    // of adversarial input) by independent review, reproduced directly.
    // A real review URL is a short path segment, never anywhere near 200
    // chars, so this costs no real coverage.
    id: 'review-nagging-url',
    label: 'Review-nagging store URL',
    re: /(?:chromewebstore\.google\.com\/detail|chrome\.google\.com\/webstore\/detail|addons\.mozilla\.org\/[a-z-]+\/addon)\/[^"'\s]{0,200}review/gi,
    severity: 'low',
  },
];

// Entropy is checked per STRING LITERAL, not per file. An earlier whole-file
// version was found by independent review to score high on any file that's
// mostly non-Latin text (a CJK locale bundle measured 11.6 bits/char) while
// missing real obfuscator.io-style JS entirely (hex-escaped/underscore-heavy
// code measured 3.8 -- it never looks like random bytes, because it's still
// syntactically normal JS). Restricting to literals that are base64-alphabet
// end to end fixes the first problem: legitimate non-Latin text isn't
// base64, so it can't match regardless of its own entropy.
const ENTROPY_MIN_LITERAL_LENGTH = 200;
const ENTROPY_THRESHOLD = 6.0;
const BASE64ISH_RE = /^[A-Za-z0-9+/=\s]+$/;

// A high-entropy literal only gets reported when a decode/execute call --
// eval, Function() (with or without new), atob, setTimeout/setInterval, or
// a dynamically-created <script> tag -- appears within this many characters
// of it in the SAME file. A bare embedded blob with no decode step nearby
// is almost always a legitimate asset (a font, an embedded protobuf
// schema); real obfuscated payloads pair the blob with exactly this kind of
// decode-and-run step close to where it's used. An earlier, file-wide
// version of this check (any companion match anywhere in the file) was
// found by independent review to still flag a legitimate embedded font
// sitting anywhere near an unrelated atob() call elsewhere in the same
// bundle -- the same false-positive class the file-wide check was meant to
// fix, just moved rather than closed. This is a real but partial
// mitigation, not an evasion-proof one. A red-team pass measured the actual
// gaps against the real CLI (not just read the code): `Function(x)()`
// without `new` and `setTimeout`/`setInterval` were confirmed TOTAL blind
// spots (no SUSPICIOUS_PATTERNS entry could ever catch them, regardless of
// entropy) and both are now closed above. `(0,eval)(x)` and
// `window["eval"](x)` -- indirect eval via the comma operator or a
// bracket-indexed property lookup -- are confirmed to still slip past,
// judged not worth chasing with a narrower regex (trivially varied around
// by the next indirection). Decoding in one file to execute in another is
// also confirmed real, but narrower than it sounds: it only defeats the
// pairing when the decode call ITSELF also avoids every companion pattern
// id, since `companionPositions` below is rebuilt fresh per file -- pairing
// is architecturally per-file, so no proximity-window tuning could close
// this; it needs real cross-file data-flow tracking (see the
// sandboxed-execution item in the project's own backlog).
const ENTROPY_PROXIMITY_CHARS = 500;
const ENTROPY_COMPANION_PATTERN_IDS = new Set([
  'eval',
  'function-constructor',
  'atob',
  'external-script-tag',
  'settimeout-string',
]);

// Safe against catastrophic backtracking: each alternative's negated class
// excludes backslash, which the escaped-char alternative requires, so the
// two never compete for the same character and the match cost is linear in
// the literal's own length regardless of input shape.
const STRING_LITERAL_RE = /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g;

function shannonEntropy(str) {
  const freq = new Map();
  let len = 0;
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
    len++;
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Permission <-> API-call pairs worth correlating: a permission *declared*
// in the manifest AND a matching call actually found in the source is a
// much stronger signal than either alone. Kept deliberately small --
// each pair here has a real, documented capability link; e.g.
// `webRequestBlocking` and `tabs` were considered and dropped: neither
// actually gates the pattern it would have been paired with
// (`webRequestBlocking` only matters for *blocking* listeners, which the
// bare `chrome.webRequest` regex can't distinguish from an observing one;
// `tabs` gates reading tab properties, not script injection).
const PERMISSION_PATTERN_PAIRS = [
  { permission: 'cookies', patternId: 'chrome-cookies' },
  { permission: 'webRequest', patternId: 'chrome-webRequest' },
  { permission: 'scripting', patternId: 'scripting-execute-script' },
  { permission: 'debugger', patternId: 'chrome-debugger' },
];

const URL_RE = /https?:\/\/[^\s"'`)]+/g;

const EXCLUDED_HOST_SUFFIXES = ['mozilla.org', 'w3.org'];

// R1: message-passing map. Static, regex-based (matches this file's existing style, no AST
// dependency). A discriminant is a literal value chrome.runtime messaging code commonly
// branches on (type/action/cmd/command), found within a bounded window of a call site --
// same proximity-window technique already used above for entropy/decode-call pairing. Two
// sides sharing a discriminant that's unique across the whole scan are an 'exact' match;
// sharing one that's not unique (multiple senders/listeners claim it) is 'probable'; no
// inferable discriminant on either side is 'ambiguous' and never forced into a pair --
// chrome.runtime.sendMessage/onMessage has no general, statically-provable 1:1 contract.
const SEND_MESSAGE_CALL_RE = /\b(?:chrome|browser)\.runtime\.(sendMessage|connect)\s*\(/g;
const ADD_LISTENER_RE = /\b(?:chrome|browser)\.runtime\.(onMessage|onConnect)\.addListener\s*\(/g;
const MESSAGE_DISCRIMINANT_RE =
  /\b(?:type|action|cmd|command)\s*:\s*['"`]([\w.-]+)['"`]|\b(?:type|action|cmd|command)\s*===?\s*['"`]([\w.-]+)['"`]|['"`]([\w.-]+)['"`]\s*===?\s*\w+(?:\.\w+)?\.(?:type|action|cmd|command)\b/g;
const MESSAGE_DISCRIMINANT_PROXIMITY_CHARS = 150;

// R16: a real call graph for the listener (callee) side of a message handler -- what
// chrome.*/network calls it can reach, and the local-function chain leading to each one.
// Deliberately NOT the sender side (see design spec). Bounded to 4 hops of local-function
// calls, same-file only -- see the spec's "Known limitations" for exactly what this does
// not attempt (alias tracking, nested-closure resolution, cross-file resolution).
const CALL_GRAPH_MAX_DEPTH = 4;
// A hard ceiling on output size, independent of the depth cap and the dedup in
// buildCallGraphFromProgram -- in case a shape neither of those anticipates still produces an
// extreme number of distinct leaves.
const CALL_GRAPH_MAX_RESULTS = 200;
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
// `export function foo() {}` / `export const foo = ...` / `export default function foo() {}`
// wrap the same declaration in an Export*Declaration; those are unwrapped and checked the same way.
function collectTopLevelFunctions(programBody) {
  const map = new Map();
  function addDeclaration(stmt) {
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
  for (const stmt of programBody) {
    if ((stmt.type === 'ExportNamedDeclaration' || stmt.type === 'ExportDefaultDeclaration') && stmt.declaration) {
      addDeclaration(stmt.declaration);
    } else {
      addDeclaration(stmt);
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
  const callExprAtMatch = allCalls.find(
    (n) =>
      n.type === 'CallExpression' &&
      n.callee.start === matchIndex &&
      n.callee.type === 'MemberExpression' &&
      n.callee.property?.name === 'addListener'
  );
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
  if (!startNode) {
    // A member-expression reference (addListener(obj.handler)) still has a real name to report.
    const chain = firstArg?.type === 'MemberExpression' ? dottedChain(firstArg) : null;
    if (chain) return [{ kind: 'unresolved', name: chain, path: [chain] }];
    return [{ kind: 'unresolved', name: firstArg?.name, path: [startName] }];
  }

  // Output is bounded by distinct (kind, name) pairs, not by the number of paths through the
  // graph: a flat bundle where every function calls every function in the next layer would
  // otherwise yield one entry per path (measured: millions). seenLeaves dedups entries;
  // fullyExpanded skips re-walking a function whose subtree was already walked to completion.
  // fullyExpanded maps each function to the path length it was walked at: a walk at a deeper
  // point had less depth budget and may have cut callees off at the cap, so it only covers a
  // later call reached at the same depth or deeper. Each function is walked at most once per
  // depth level, which keeps the work bounded without hiding leaves a shallower path reaches.
  const results = [];
  const seenLeaves = new Set();
  const fullyExpanded = new Map();
  let truncated = false;
  function record(entry) {
    if (truncated) return;
    const key = `${entry.kind}:${entry.name}`;
    if (seenLeaves.has(key)) return;
    // Checked after dedup so 'truncated' only appears when a genuinely new entry is dropped.
    if (results.length >= CALL_GRAPH_MAX_RESULTS) {
      results.push({ kind: 'truncated' });
      truncated = true;
      return;
    }
    seenLeaves.add(key);
    results.push(entry);
  }

  function walk(fnNode, path, visited) {
    // A call to one of this function's own parameters (e.g. a minifier-renamed sendResponse)
    // must not resolve to an unrelated same-named top-level function. Identifier params only:
    // narrow by design, not full scope analysis.
    const ownParamNames = new Set(fnNode.params.filter((p) => p.type === 'Identifier').map((p) => p.name));
    for (const callNode of deepCollectCallSites(fnNode.body)) {
      const classified = classifyCall(callNode);
      if (!classified) continue;

      if (classified.kind !== 'identifier') {
        record({ name: classified.name, kind: classified.kind, path: [...path, classified.name] });
        continue;
      }

      const target = ownParamNames.has(classified.name) ? undefined : topLevelFns.get(classified.name);
      if (!target) {
        record({ name: classified.name, kind: 'unresolved', path: [...path, classified.name] });
      } else if (visited.has(target)) {
        record({ name: classified.name, kind: 'cycle', path: [...path, classified.name] });
      } else if (fullyExpanded.has(target) && fullyExpanded.get(target) <= path.length + 1) {
        continue;
      } else if (path.length >= CALL_GRAPH_MAX_DEPTH) {
        record({ name: classified.name, kind: 'depth-limit', path: [...path, classified.name] });
      } else {
        const targetPath = [...path, classified.name];
        walk(target, targetPath, new Set([...visited, target]));
        const prior = fullyExpanded.get(target);
        if (prior === undefined || targetPath.length < prior) fullyExpanded.set(target, targetPath.length);
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

function extractDiscriminants(content, index) {
  const start = Math.max(0, index - MESSAGE_DISCRIMINANT_PROXIMITY_CHARS);
  const end = Math.min(content.length, index + MESSAGE_DISCRIMINANT_PROXIMITY_CHARS);
  const window = content.slice(start, end);
  const found = new Set();
  MESSAGE_DISCRIMINANT_RE.lastIndex = 0;
  let m;
  while ((m = MESSAGE_DISCRIMINANT_RE.exec(window)) !== null) {
    const value = m[1] ?? m[2] ?? m[3];
    if (value) found.add(value);
  }
  return [...found];
}

function lineOf(content, index) {
  return content.slice(0, index).split('\n').length;
}

function countByDiscriminant(entries) {
  const counts = new Map();
  for (const entry of entries) {
    for (const d of entry.discriminants) counts.set(d, (counts.get(d) ?? 0) + 1);
  }
  return counts;
}

/**
 * Message-passing map: sender (sendMessage/connect) call sites grouped against listener
 * (onMessage/onConnect) addListener call sites by inferable discriminant. No forced 1:1
 * pairing -- see module comment above.
 */
export function collectMessagePassing(dir, manifest = {}) {
  const senders = [];
  const listeners = [];
  const jsFiles = walkFiles(dir, { extensions: ['.js'] });
  const sourceType = manifest?.background?.type === 'module' ? 'module' : 'script';

  for (const file of jsFiles) {
    if (isSupersededByUnpack(file) || isWakaruOutput(file) || isHumanifyOutput(file)) continue;
    const rel = relPath(dir, file);
    const content = readFileSync(file, 'utf8');

    // Parse only files that actually register a listener; most vendor bundles don't.
    let program = null;
    ADD_LISTENER_RE.lastIndex = 0;
    const hasListener = ADD_LISTENER_RE.test(content);
    ADD_LISTENER_RE.lastIndex = 0;
    if (hasListener) {
      try {
        program = acorn.parse(content, { ecmaVersion: 'latest', sourceType, allowReturnOutsideFunction: true });
      } catch {
        program = null;
      }
    }

    SEND_MESSAGE_CALL_RE.lastIndex = 0;
    let m;
    while ((m = SEND_MESSAGE_CALL_RE.exec(content)) !== null) {
      senders.push({ file: rel, line: lineOf(content, m.index), kind: m[1], discriminants: extractDiscriminants(content, m.index) });
    }

    ADD_LISTENER_RE.lastIndex = 0;
    while ((m = ADD_LISTENER_RE.exec(content)) !== null) {
      let calls;
      if (!program) {
        calls = [{ kind: 'unparseable' }];
      } else {
        // Never let one pathological listener (e.g. a stack overflow on an extreme AST) kill the pass.
        try {
          calls = buildCallGraphFromProgram(program, m.index);
        } catch {
          calls = [{ kind: 'unparseable' }];
        }
      }
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

// R2: endpoint method/shape capture, alongside the existing bare-URL extraction (unchanged,
// below). `fetch(url, {...})`'s options object can nest further objects (headers), so a
// non-greedy `{...}` regex would stop at the first inner `}` -- captureBalanced does real
// brace counting instead.
const FETCH_CALL_START_RE = /\bfetch\s*\(\s*(['"`])([^'"`]+)\1\s*(,)?/g;
const HTTP_METHOD_RE = /\bmethod\s*:\s*['"`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"`]/i;

function captureBalanced(content, openIndex) {
  let depth = 0;
  for (let i = openIndex; i < content.length; i++) {
    if (content[i] === '{') depth++;
    else if (content[i] === '}') {
      depth--;
      if (depth === 0) return content.slice(openIndex, i + 1);
    }
  }
  return null;
}

function extractHeaderKeys(optionsObj) {
  const headersIdx = optionsObj.search(/\bheaders\s*:\s*\{/);
  if (headersIdx === -1) return [];
  const braceIdx = optionsObj.indexOf('{', headersIdx);
  const headersObj = captureBalanced(optionsObj, braceIdx);
  if (!headersObj) return [];
  const keys = [];
  const keyRe = /['"`]?([A-Za-z0-9-]+)['"`]?\s*:/g;
  let km;
  while ((km = keyRe.exec(headersObj.slice(1, -1))) !== null) keys.push(km[1]);
  return keys;
}

/**
 * Literal-shape fetch() call details: method and header keys, where statically inferable.
 * Supplements collectEndpointsFromContent's bare URL list below -- does not replace it.
 */
export function collectEndpointDetailsFromContent(content) {
  const details = [];
  FETCH_CALL_START_RE.lastIndex = 0;
  let m;
  while ((m = FETCH_CALL_START_RE.exec(content)) !== null) {
    const url = m[2];
    let method = null;
    let headersKeys = [];
    if (m[3] === ',') {
      let idx = m.index + m[0].length;
      while (idx < content.length && /\s/.test(content[idx])) idx++;
      if (content[idx] === '{') {
        const optionsObj = captureBalanced(content, idx);
        if (optionsObj) {
          const methodMatch = optionsObj.match(HTTP_METHOD_RE);
          if (methodMatch) method = methodMatch[1].toUpperCase();
          headersKeys = extractHeaderKeys(optionsObj);
        }
      }
    }
    details.push({ url, method, headersKeys });
  }
  return details;
}

function collectEndpointDetails(dir) {
  const details = [];
  const jsFiles = walkFiles(dir, { extensions: ['.js'] });
  for (const file of jsFiles) {
    if (isSupersededByUnpack(file) || isWakaruOutput(file) || isHumanifyOutput(file)) continue;
    const content = readFileSync(file, 'utf8');
    details.push(...collectEndpointDetailsFromContent(content));
  }
  return details;
}

export function collectEndpointsFromContent(content) {
  const endpoints = [];
  for (const url of content.match(URL_RE) ?? []) {
    const cleaned = url.replace(/[),.;]+$/, '');
    let host;
    try {
      host = new URL(cleaned).hostname;
    } catch {
      continue; // not a well-formed URL (e.g. trailing garbage survived cleanup)
    }
    const excluded = EXCLUDED_HOST_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
    if (!excluded) endpoints.push(cleaned);
  }
  return endpoints;
}

/**
 * Run a security-oriented audit on an unpacked extension directory.
 */
export function auditExtension(dir, manifest, summary) {
  const map = buildEntryPointMap(dir, manifest);
  const permissions = classifyPermissions(summary);
  const findings = scanSource(dir);
  const endpoints = collectEndpoints(dir);
  const endpointDetails = collectEndpointDetails(dir);
  const messagePassing = collectMessagePassing(dir, manifest);
  const flags = manifestFlags(summary);
  const correlations = correlatePermissionsAndFindings(permissions, findings);
  const risk = computeRisk(permissions, findings, summary, flags, correlations);

  return {
    risk,
    permissions,
    findings,
    endpoints,
    endpointDetails,
    messagePassing,
    flags,
    correlations,
    entryPoints: map.entryPoints,
    readability: map.readability,
    startHere: map.startHere,
    version: summary?.version ?? null,
    name: summary?.name ?? null,
  };
}

const OFFICIAL_UPDATE_URL_HOSTS = new Set([
  'clients2.google.com',
  'edge.microsoft.com',
]);

function manifestFlags(summary) {
  const flags = [];
  if (!summary) return flags;

  if (summary.updateUrl) {
    let host = null;
    try {
      host = new URL(summary.updateUrl).hostname;
    } catch {
      // not a parseable URL; treat as non-official below
    }
    if (!host || !OFFICIAL_UPDATE_URL_HOSTS.has(host)) {
      flags.push({
        severity: 'high',
        label: 'custom update_url (bypasses store-managed updates)',
        detail: summary.updateUrl,
      });
    }
  }
  if (summary.contentSecurityPolicy) {
    const csp = JSON.stringify(summary.contentSecurityPolicy);
    if (/unsafe-eval|wasm-unsafe-eval/.test(csp)) {
      flags.push({ severity: 'high', label: 'CSP allows unsafe-eval', detail: csp });
    }
  }
  if (summary.externallyConnectable) {
    flags.push({
      severity: 'medium',
      label: 'externally_connectable: other extensions/sites can message this one',
      detail: JSON.stringify(summary.externallyConnectable),
    });
  }
  if (summary.oauth2) {
    flags.push({ severity: 'low', label: 'requests OAuth2 scopes', detail: (summary.oauth2.scopes ?? []).join(', ') });
  }
  return flags;
}

function classifyPermissions(summary) {
  if (!summary) return { high: [], medium: [], low: [], hostAccess: [] };

  const all = [
    ...(summary.permissions ?? []),
    ...(summary.optionalPermissions ?? []),
    ...(summary.hostPermissions ?? []),
    ...(summary.optionalHostPermissions ?? []),
  ];

  const high = [];
  const medium = [];
  const low = [];
  const hostAccess = [];

  for (const perm of all) {
    if (perm.includes('://') || perm === '<all_urls>' || perm.startsWith('*://')) {
      hostAccess.push(perm);
      if (perm === '<all_urls>' || perm === '*://*/*') high.push(perm);
      continue;
    }
    if (HIGH_RISK_PERMISSIONS.has(perm)) high.push(perm);
    else if (MEDIUM_RISK_PERMISSIONS.has(perm)) medium.push(perm);
    else low.push(perm);
  }

  return { high, medium, low, hostAccess };
}

function scanSource(dir) {
  const findings = [];
  const jsFiles = walkFiles(dir, { extensions: ['.js'] });

  for (const file of jsFiles) {
    if (isSupersededByUnpack(file) || isWakaruOutput(file) || isHumanifyOutput(file)) continue;
    const rel = relPath(dir, file);
    const content = readFileSync(file, 'utf8');
    const lines = content.split('\n');

    const highEntropyLiterals = [];
    STRING_LITERAL_RE.lastIndex = 0;
    let literalMatch;
    while ((literalMatch = STRING_LITERAL_RE.exec(content)) !== null) {
      const inner = literalMatch[0].slice(1, -1);
      if (inner.length < ENTROPY_MIN_LITERAL_LENGTH || !BASE64ISH_RE.test(inner)) continue;
      const entropy = shannonEntropy(inner);
      if (entropy >= ENTROPY_THRESHOLD) {
        highEntropyLiterals.push({
          index: literalMatch.index,
          end: literalMatch.index + literalMatch[0].length,
          entropy,
        });
      }
    }

    const companionPositions = [];

    for (const pattern of SUSPICIOUS_PATTERNS) {
      pattern.re.lastIndex = 0;
      let match;
      while ((match = pattern.re.exec(content)) !== null) {
        if (ENTROPY_COMPANION_PATTERN_IDS.has(pattern.id)) companionPositions.push(match.index);
        const lineStart = content.lastIndexOf('\n', match.index - 1) + 1;
        const line = content.slice(0, match.index).split('\n').length;
        const lineText = lines[line - 1] ?? '';
        const col = match.index - lineStart;
        // Window centered on the match, not just the line's first 120 chars
        // -- a match far past column 120 on a long (often minified) line
        // was previously invisible in the preview even though the finding
        // itself (file/line/pattern) was already correct.
        const windowStart = Math.max(0, col - 40);
        const windowEnd = Math.min(lineText.length, col + match[0].length + 80);
        const snippet = lineText.slice(windowStart, windowEnd).trim();
        findings.push({
          severity: pattern.severity,
          pattern: pattern.label,
          file: rel,
          line,
          snippet,
        });
      }
    }

    for (const lit of highEntropyLiterals) {
      const hasNearbyCompanion = companionPositions.some(
        (pos) => pos >= lit.index - ENTROPY_PROXIMITY_CHARS && pos <= lit.end + ENTROPY_PROXIMITY_CHARS
      );
      if (!hasNearbyCompanion) continue;
      const line = content.slice(0, lit.index).split('\n').length;
      findings.push({
        severity: 'medium',
        pattern: 'High entropy (possible obfuscation)',
        file: rel,
        line,
        snippet: `entropy=${lit.entropy.toFixed(2)}`,
      });
    }
  }

  return findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

function collectEndpoints(dir) {
  const endpoints = new Set();
  const jsFiles = walkFiles(dir, { extensions: ['.js'] });

  for (const file of jsFiles) {
    if (isSupersededByUnpack(file) || isWakaruOutput(file) || isHumanifyOutput(file)) continue;
    const content = readFileSync(file, 'utf8');
    for (const url of collectEndpointsFromContent(content)) endpoints.add(url);
  }

  return [...endpoints].sort().slice(0, 100);
}

/**
 * Correlate declared permissions with matching API-call findings. A
 * permission alone, or a pattern hit alone, is weaker evidence than both
 * together -- this says "and found a matching call", not "granted": these
 * permission arrays include optional permissions the user may never
 * actually grant at runtime, which static analysis of the manifest alone
 * can't resolve.
 */
function correlatePermissionsAndFindings(permissions, findings) {
  const declared = new Set([...permissions.high, ...permissions.medium, ...permissions.low]);
  const patternLabelById = new Map(SUSPICIOUS_PATTERNS.map((p) => [p.id, p.label]));
  const correlations = [];

  for (const { permission, patternId } of PERMISSION_PATTERN_PAIRS) {
    if (!declared.has(permission)) continue;
    const label = patternLabelById.get(patternId);
    const matchingFiles = [...new Set(findings.filter((f) => f.pattern === label).map((f) => f.file))].sort();
    if (matchingFiles.length === 0) continue;
    correlations.push({ permission, pattern: label, files: matchingFiles });
  }

  return correlations;
}

function computeRisk(permissions, findings, summary, flags = [], correlations = []) {
  const distinctHighHits = new Set(
    findings.filter((f) => f.severity === 'high').map((f) => `${f.file}:${f.pattern}`)
  ).size;
  const distinctMediumHits = new Set(
    findings.filter((f) => f.severity === 'medium').map((f) => `${f.file}:${f.pattern}`)
  ).size;

  let score = 0;
  score += permissions.high.length * 3;
  score += permissions.medium.length * 1;
  score += distinctHighHits * 2;
  score += distinctMediumHits;
  score += flags.filter((f) => f.severity === 'high').length * 3;
  score += flags.filter((f) => f.severity === 'medium').length * 1;
  score += correlations.length * 2;

  const hasBroadHost =
    permissions.hostAccess.includes('<all_urls>') ||
    permissions.hostAccess.includes('*://*/*') ||
    summary?.permissions?.includes('<all_urls>');

  if (hasBroadHost) score += 5;

  let level = 'low';
  if (score >= 12) level = 'critical';
  else if (score >= 7) level = 'high';
  else if (score >= 3) level = 'medium';

  return { level, score, hasBroadHost };
}

function severityRank(severity) {
  return { high: 3, medium: 2, low: 1 }[severity] ?? 0;
}

export function formatAuditReport(audit) {
  const lines = [];
  const riskLabel = audit.risk.level.toUpperCase();

  lines.push(`${riskEmoji(audit.risk.level)}  ${riskLabel} RISK (score ${audit.risk.score})`);
  lines.push('');

  if (audit.signature) {
    lines.push(
      `Signature: ${audit.signature.verified ? `✅ verified store-signed CRX${audit.signature.version}` : `⚠️ unverifiable (${audit.signature.reason})`}`
    );
    lines.push('');
  }

  if (audit.name) {
    lines.push(`  ${audit.name}${audit.version ? ` v${audit.version}` : ''}`);
    lines.push('');
  }

  if (audit.flags?.length) {
    lines.push('Manifest flags');
    for (const f of audit.flags) lines.push(`  [${f.severity}] ${f.label}${f.detail ? ` — ${f.detail}` : ''}`);
    lines.push('');
  }

  if (audit.correlations?.length) {
    lines.push('Declared permission + matching API call');
    for (const c of audit.correlations) {
      lines.push(`  ${c.permission} -> ${c.pattern} (${c.files.join(', ')})`);
    }
    lines.push('');
  }

  if (audit.permissions.high.length || audit.permissions.hostAccess.length) {
    lines.push('Permissions & access');
    if (audit.permissions.high.length) lines.push(`  High: ${audit.permissions.high.join(', ')}`);
    if (audit.permissions.medium.length) lines.push(`  Medium: ${audit.permissions.medium.join(', ')}`);
    if (audit.permissions.hostAccess.length) lines.push(`  Host: ${audit.permissions.hostAccess.join(', ')}`);
    lines.push('');
  }

  if (audit.findings.length) {
    lines.push('Suspicious patterns');
    for (const f of audit.findings.slice(0, 15)) {
      lines.push(`  ${f.file}:${f.line}  ${f.pattern}`);
      if (f.snippet) lines.push(`    ${f.snippet}`);
    }
    if (audit.findings.length > 15) {
      lines.push(`  ... and ${audit.findings.length - 15} more`);
    }
    lines.push('');
  }

  if (audit.endpoints.length) {
    lines.push(`Network endpoints (${audit.endpoints.length})`);
    for (const ep of audit.endpoints.slice(0, 10)) lines.push(`  ${ep}`);
    if (audit.endpoints.length > 10) lines.push(`  ... and ${audit.endpoints.length - 10} more`);
    lines.push('');
  }

  lines.push('Start here');
  for (const p of audit.startHere) lines.push(`  ${p}`);

  lines.push('');
  lines.push(
    `Readability: ${audit.readability.readable} readable, ${audit.readability.minified} minified JS files`
  );

  return lines.join('\n');
}

function riskEmoji(level) {
  return { critical: '🔴', high: '⚠️', medium: '🟡', low: '🟢' }[level] ?? '⚪';
}
