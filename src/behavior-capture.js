import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { redactEvent } from './redact.js';
import { auditExtension } from './audit.js';
import { summarizeManifest } from './manifest.js';
import { buildMechanismReport } from './mechanism.js';
import { buildCausalityEdges } from './causality.js';

export const DISCLAIMER =
  'crxray capture-behavior is a verification aid for extensions you have the right to ' +
  'inspect or test. It is not a license to copy a third party\'s copyrighted code, branding, ' +
  'or paid service. A capture reflects only the scenario actually exercised, under one ' +
  'environment and one run -- it is scenario-specific evidence, not a complete record of ' +
  'everything the extension does.';

const SCHEMA_VERSION = 1;
const DEFAULT_TIMEOUT_MS = 60_000;
const RESPONSE_BODY_BYTE_CAP = 100_000;
const CAPTURABLE_MIME_RE = /^(text\/|application\/json)/i;
const CAPTURE_MARKER = '\u0000__CRXRAY_CAPTURE__\u0000';

function findChrome() {
  if (process.env.CRXRAY_CHROME_PATH && existsSync(process.env.CRXRAY_CHROME_PATH)) {
    return process.env.CRXRAY_CHROME_PATH;
  }
  const candidates =
    process.platform === 'darwin'
      ? [
          '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
          '/Applications/Chromium.app/Contents/MacOS/Chromium',
        ]
      : process.platform === 'win32'
        ? [
            'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
          ]
        : ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
  const found = candidates.find((p) => existsSync(p));
  if (!found) {
    throw new Error(
      'No Chrome/Chromium binary found. Set CRXRAY_CHROME_PATH to its full path.'
    );
  }
  return found;
}

/**
 * Minimal CDP client over the pipe transport (NUL-delimited JSON on fd 3/4), not the
 * WebSocket/`/json` port transport crxray's static pipeline would use elsewhere -- pipe
 * transport is required for `Extensions.loadUnpacked` (confirmed: Chrome 126+, requires
 * --remote-debugging-pipe plus --enable-unsafe-extension-debugging; the port transport
 * returns "Method not available" for that one command).
 */
class CdpPipeClient {
  constructor(chromePath, args) {
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map(); // method -> Set<fn>
    this.buf = '';
    this.child = spawn(chromePath, args, { stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe'] });
    this.cmdOut = this.child.stdio[3];
    this.evtIn = this.child.stdio[4];
    this.evtIn.on('data', (chunk) => this._onData(chunk));
  }

  _onData(chunk) {
    this.buf += chunk.toString('utf8');
    let idx;
    while ((idx = this.buf.indexOf('\0')) >= 0) {
      const msg = this.buf.slice(0, idx);
      this.buf = this.buf.slice(idx + 1);
      if (!msg) continue;
      let obj;
      try {
        obj = JSON.parse(msg);
      } catch {
        continue;
      }
      if (obj.id !== undefined && this.pending.has(obj.id)) {
        const { resolve } = this.pending.get(obj.id);
        this.pending.delete(obj.id);
        resolve(obj);
      } else if (obj.method) {
        for (const fn of this.listeners.get(obj.method) ?? []) fn(obj);
      }
    }
  }

  on(method, fn) {
    if (!this.listeners.has(method)) this.listeners.set(method, new Set());
    this.listeners.get(method).add(fn);
  }

  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve) => {
      this.pending.set(id, { resolve });
      this.cmdOut.write(JSON.stringify(payload) + '\0');
    });
  }

  kill() {
    try {
      this.child.kill('SIGKILL');
    } catch {
      // already exited
    }
  }
}

function addLimitation(limitations, entry) {
  limitations.push(entry);
}

/**
 * Kills Chrome and removes the temp profile, waiting for the process to actually exit first.
 * A bare kill()-then-rmSync raced Chrome's own subprocesses (confirmed by a failing test:
 * ENOTEMPTY -- the profile dir wasn't actually free yet), especially under --headless=new,
 * which can leave child/zygote processes briefly holding files open after the main process
 * is signaled. Retries the removal a few times rather than failing outright on that race.
 */
async function killAndCleanup(client, profileDir) {
  await new Promise((resolve) => {
    if (client.child.exitCode !== null || client.child.killed) {
      resolve();
      return;
    }
    client.child.once('exit', resolve);
    client.kill();
    setTimeout(resolve, 3000);
  });

  let lastErr;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      rmSync(profileDir, { recursive: true, force: true });
      return;
    } catch (err) {
      lastErr = err;
      await new Promise((r) => setTimeout(r, 300));
    }
  }
  throw lastErr;
}

const SCRIPT_SRC_RE = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;

/**
 * Every <script src="..."> URL in an HTML page, resolved against that page's own URL. Used to
 * find the real entry script(s) a page-type target will run (see getEntryScriptUrls). Inline
 * <script> blocks are deliberately not covered here -- not an open gap, a dead end: Chrome's
 * extension_pages CSP cannot be relaxed below `script-src 'self' 'wasm-unsafe-eval'` (confirmed
 * via Chrome's own docs and a direct test: a real extension's popup with an inline <script>
 * calling chrome.storage.local.set was blocked outright, console reported a CSP violation, the
 * write never happened). No extension page can ever execute inline JS with access to chrome.*
 * APIs -- the only context that permits inline scripts (a sandboxed page) is also the only
 * context chrome.* APIs are unavailable in. Investigated and closed, not deferred.
 */
function extractScriptSrcUrls(htmlContent, baseUrl) {
  const urls = [];
  SCRIPT_SRC_RE.lastIndex = 0;
  let m;
  while ((m = SCRIPT_SRC_RE.exec(htmlContent)) !== null) {
    try {
      urls.push(new URL(m[1], baseUrl).toString());
    } catch {
      // malformed src attribute; skip rather than throw
    }
  }
  return urls;
}

/**
 * The entry script URL(s) a target will execute, when determinable ahead of time -- lets
 * instrumentAndResume set a real debugger breakpoint at each script's first line before the
 * target ever resumes (R12, see that function's comment for why this closes the one-shot gap
 * a plain post-resume patch attempt cannot). A service worker has exactly one, straight from
 * the manifest. A page target's own URL is its HTML document, not a script -- its <script src>
 * tags are read directly off disk, since extensionDir is already on hand and trusted the same
 * way crxray's static pipeline already reads it. An inline <script> block (no src) is
 * deliberately not covered -- confirmed unreachable for chrome.* calls, not a remaining gap
 * (see extractScriptSrcUrls's own comment above for the CSP evidence). A target with only
 * inline scripts, or whose manifest this parser couldn't read, falls back to the pre-existing
 * post-resume mechanism below.
 */
function getEntryScriptUrls(targetInfo, { extensionDir, extensionId, manifest }) {
  // Target.setAutoAttach catches every new target in the browser, not just this extension's --
  // Chrome's own bundled component extensions (e.g. its internal TTS engine) spin up service
  // workers too. Without this check, a target that isn't ours would get handed OUR sw.js URL,
  // which it will obviously never execute -- harmless (the breakpoint just never resolves,
  // falling back to the pre-existing mechanism below), but wrong, and worth being exact about.
  if (targetInfo.type === 'service_worker' && targetInfo.url?.includes(extensionId ?? '\u0000')) {
    const swFile = manifest.background?.service_worker;
    return swFile ? [`chrome-extension://${extensionId}/${swFile}`] : [];
  }
  if (targetInfo.type === 'page' && targetInfo.url?.startsWith('chrome-extension://')) {
    try {
      const pageUrl = new URL(targetInfo.url);
      const htmlPath = path.join(extensionDir, decodeURIComponent(pageUrl.pathname));
      const html = readFileSync(htmlPath, 'utf8');
      return extractScriptSrcUrls(html, targetInfo.url);
    } catch {
      return []; // page HTML not readable from extensionDir -- breakpoint mechanism skipped
    }
  }
  return [];
}

/**
 * Installs pre-execution instrumentation on a newly-attached, paused target and resumes it.
 *
 * R12 closed the structural one-shot gap documented below, for any target whose entry script
 * URL is determinable (getEntryScriptUrls): a plain `Debugger.setBreakpointByUrl` at that
 * script's line 0, column 0, registered before the target resumes. Confirmed by direct,
 * repeated testing (5/5 identical real-Chrome runs), not assumed -- an EARLIER attempt at the
 * same goal, `Debugger.setInstrumentationBreakpoint({instrumentation: 'beforeScriptExecution'})`,
 * was accepted by the API with no error but never actually fired for either a service worker or
 * a page target in this environment (Chrome 154); a REGULAR line breakpoint, by contrast, fires
 * reliably, and fires in the target's actual, already-materialized execution context -- which
 * also closes the separate page-target injection gap below, since injecting fresh at the pause
 * itself (rather than beforehand, via `Page.addScriptToEvaluateOnNewDocument`, which can land in
 * a context a navigation then replaces) no longer depends on that mechanism working at all.
 *
 * The pre-resume mechanisms below are kept as a second, independent layer -- harmless where the
 * breakpoint above already did the job, and still the only mechanism for a target whose entry
 * script URL could not be determined (a manifest this parser couldn't read; an inline-only page
 * is not actually a live case for chrome.* calls -- see extractScriptSrcUrls's comment above).
 * The honest, fully-understood boundary of what THAT fallback layer can and cannot catch
 * (found by direct testing, not assumed) still applies to such a target:
 *
 * - `chrome.storage`/`chrome.runtime` do not exist on a service worker's global scope at the
 *   instant it is paused pre-resume (confirmed: a bare reference throws ReferenceError there).
 *   They become available at some point during/after resume, not before -- so a one-shot
 *   pre-resume patch attempt has nothing to wrap yet.
 * - A retry timer *scheduled from inside the worker's own injected code* never fires at all in
 *   this environment (confirmed: a 100ms setInterval heartbeat never ticked once over several
 *   seconds) -- MV3 service workers appear to only service their task queue in response to a
 *   genuine browser-dispatched event, not an arbitrary JS timer they scheduled for themselves.
 *   The retry below is therefore driven by Node's own timer instead, re-invoking an idempotent
 *   patch function already installed on the target -- confirmed working.
 * - A `Object.defineProperty` trap on `globalThis.chrome` (installed before `chrome` exists)
 *   catches the moment the real `chrome` object is assigned, and was confirmed to catch a
 *   storage write made in response to a later event (the popup's message round-trip).
 * - What neither mechanism can catch, absent the breakpoint above: a call made synchronously as
 *   part of the target's own top-level script execution, before Node's first follow-up
 *   round-trip completes (confirmed by direct test prior to R12: the extension's very first,
 *   one-time `chrome.storage.local.set` and its one-time `addListener` registration were both
 *   missed; a *later*, repeated call -- made after the patch has had time to land -- was
 *   reliably captured, with correct redaction).
 */
async function instrumentAndResume(client, sessionId, targetInfo, limitations, breakpointCtx) {
  const defineInjectSource = `
    (function() {
      const marker = ${JSON.stringify(CAPTURE_MARKER)};
      function report(entry) { try { console.log(marker + JSON.stringify(entry)); } catch (e) {} }

      function patchStorage() {
        if (!(globalThis.chrome && chrome.storage)) return false;
        for (const area of ['local', 'sync']) {
          const store = chrome.storage[area];
          if (!store || store.__crxrayPatched) continue;
          for (const method of ['get', 'set', 'remove']) {
            const original = store[method];
            if (typeof original !== 'function') continue;
            store[method] = function (...args) {
              report({ kind: 'storage', area, method, value: args[0] });
              return original.apply(store, args);
            };
          }
          store.__crxrayPatched = true;
        }
        return !!(chrome.storage.local && chrome.storage.local.__crxrayPatched);
      }

      function patchRuntime() {
        if (!(globalThis.chrome && chrome.runtime)) return false;
        if (chrome.runtime.sendMessage && !chrome.runtime.sendMessage.__crxrayPatched) {
          const originalSend = chrome.runtime.sendMessage;
          const wrappedSend = function (...args) {
            report({ kind: 'message', direction: 'sent', message: args.find((a) => typeof a !== 'function') });
            return originalSend.apply(chrome.runtime, args);
          };
          wrappedSend.__crxrayPatched = true;
          chrome.runtime.sendMessage = wrappedSend;
        }
        if (chrome.runtime.onMessage && chrome.runtime.onMessage.addListener && !chrome.runtime.onMessage.addListener.__crxrayPatched) {
          const originalAdd = chrome.runtime.onMessage.addListener;
          const wrappedAdd = function (handler) {
            const wrapped = function (message, sender, sendResponse) {
              report({ kind: 'message', direction: 'received', message });
              return handler(message, sender, sendResponse);
            };
            return originalAdd.call(chrome.runtime.onMessage, wrapped);
          };
          wrappedAdd.__crxrayPatched = true;
          chrome.runtime.onMessage.addListener = wrappedAdd;
        }
        return true;
      }

      // R14: crypto.subtle is a standard Web Crypto API global, not something Chrome binds late
      // into an extension context the way chrome.* is -- confirmed present even at the earliest
      // pre-resume pause (unlike chrome.storage/chrome.runtime). Only the five "operation"
      // methods are wrapped (digest/sign/verify/encrypt/decrypt); key-management methods
      // (generateKey/importKey/exportKey/wrapKey/unwrapKey/deriveKey/deriveBits) are deliberately
      // left unpatched -- several of those can return actual raw key bytes, a materially
      // different and riskier capture-safety question than "did this extension call sign()".
      // Reports metadata only (algorithm name, byte lengths, verify's boolean result) -- never
      // the actual input/output bytes, so no new redaction logic is needed for this event kind.
      function patchCrypto() {
        if (!(globalThis.crypto && globalThis.crypto.subtle)) return false;
        const subtle = globalThis.crypto.subtle;
        if (subtle.__crxrayPatched) return true;
        function byteLength(data) {
          if (!data) return 0;
          if (data.byteLength !== undefined) return data.byteLength;
          if (data.buffer && data.buffer.byteLength !== undefined) return data.buffer.byteLength;
          return 0;
        }
        function algorithmName(algorithm) {
          return typeof algorithm === 'string' ? algorithm : algorithm?.name;
        }
        for (const method of ['digest', 'sign', 'encrypt', 'decrypt']) {
          const original = subtle[method];
          if (typeof original !== 'function') continue;
          subtle[method] = function (algorithm, ...rest) {
            const data = rest[rest.length - 1];
            const resultPromise = original.apply(subtle, [algorithm, ...rest]);
            resultPromise.then(
              (output) => report({ kind: 'crypto', method, algorithm: algorithmName(algorithm), dataByteLength: byteLength(data), outputByteLength: byteLength(output) }),
              () => report({ kind: 'crypto', method, algorithm: algorithmName(algorithm), dataByteLength: byteLength(data), failed: true })
            );
            return resultPromise;
          };
        }
        if (typeof subtle.verify === 'function') {
          const originalVerify = subtle.verify;
          subtle.verify = function (algorithm, key, signature, data) {
            const resultPromise = originalVerify.call(subtle, algorithm, key, signature, data);
            resultPromise.then(
              (verified) => report({ kind: 'crypto', method: 'verify', algorithm: algorithmName(algorithm), dataByteLength: byteLength(data), verified }),
              () => report({ kind: 'crypto', method: 'verify', algorithm: algorithmName(algorithm), dataByteLength: byteLength(data), failed: true })
            );
            return resultPromise;
          };
        }
        subtle.__crxrayPatched = true;
        return true;
      }

      globalThis.__crxrayTryPatch = function () {
        const storageOk = patchStorage();
        const runtimeOk = patchRuntime();
        const cryptoOk = patchCrypto();
        globalThis.__crxrayNamespaceCheck = { chromeStorage: storageOk, chromeRuntime: runtimeOk, crypto: cryptoOk };
        return storageOk && runtimeOk;
      };
      if (!globalThis.__crxrayTryPatch() && typeof chrome === 'undefined') {
        try {
          let realChrome;
          Object.defineProperty(globalThis, 'chrome', {
            configurable: true,
            enumerable: true,
            get() { return realChrome; },
            set(v) {
              realChrome = v;
              globalThis.__crxrayTryPatch();
            },
          });
          globalThis.__crxrayTrapInstalled = true;
        } catch (e) {
          globalThis.__crxrayTrapInstalled = false;
        }
      }
    })();
  `;

  // R12: a real breakpoint at the entry script's own first line, registered before resume --
  // fires in the target's live execution context, after Chrome's own binding setup but before
  // any of the target's own code (confirmed: see this function's own comment above). The
  // target stays genuinely paused -- nothing in its own script can run -- until our own
  // Debugger.paused handler (below, in captureBehavior) explicitly resumes it, so this is a
  // real await on that handler's own confirmation, never a race against it: an EARLIER version
  // of this polled `breakpointConfirmed` from an independent Node-timer retry loop and could
  // observe it as still false at the moment the retry loop's own, unrelated check happened to
  // return true first -- correct data (the retry loop's check also runs while the target is
  // still paused, so it can't miss the one-shot call either), but the WRONG attribution in the
  // limitations wording below. Awaiting the breakpoint's own promise removes that race.
  const scriptUrls = getEntryScriptUrls(targetInfo, breakpointCtx);
  let breakpointConfirmedPromise = null;
  if (scriptUrls.length > 0) {
    await client.send('Debugger.enable', {}, sessionId);
    for (const url of scriptUrls) {
      await client.send('Debugger.setBreakpointByUrl', { url, lineNumber: 0, columnNumber: 0 }, sessionId);
    }
    breakpointConfirmedPromise = new Promise((resolve) => {
      breakpointCtx.pendingBreakpointInjections.set(sessionId, {
        injectSource: defineInjectSource,
        onConfirmed: () => resolve(true),
      });
    });
  }

  if (targetInfo.type === 'service_worker') {
    await client.send('Runtime.evaluate', { expression: defineInjectSource }, sessionId);
  } else {
    await client.send('Page.enable', {}, sessionId);
    await client.send('Page.addScriptToEvaluateOnNewDocument', { source: defineInjectSource }, sessionId);
  }
  await client.send('Network.enable', {}, sessionId);
  await client.send('Runtime.enable', {}, sessionId);
  await client.send('Log.enable', {}, sessionId);
  await client.send('Runtime.runIfWaitingForDebugger', {}, sessionId);

  let patched = false;
  let breakpointConfirmed = false;
  if (breakpointConfirmedPromise) {
    // 2s is generous headroom over every observed real confirmation (well under 100ms) -- a
    // safety bound in case a target we set a breakpoint on never actually hits it, not a
    // budget this capability expects to spend routinely.
    breakpointConfirmed = await Promise.race([
      breakpointConfirmedPromise,
      new Promise((resolve) => setTimeout(() => resolve(false), 2000)),
    ]);
    patched = breakpointConfirmed;
  }

  // Node-driven follow-up attempts (see function comment for why this has to be Node's timer,
  // not the worker's own) -- the only path left once the breakpoint above either wasn't set
  // (no determinable entry script URL) or didn't confirm within its own timeout.
  if (!patched) {
    for (const delayMs of [0, 15, 40, 100, 300]) {
      await new Promise((r) => setTimeout(r, delayMs));
      const res = await client.send(
        'Runtime.evaluate',
        { expression: 'globalThis.__crxrayTryPatch && globalThis.__crxrayTryPatch()' },
        sessionId
      );
      if (res.result?.result?.value === true) {
        patched = true;
        break;
      }
    }
  }

  addLimitation(limitations, {
    capability: 'storageMessageLiveCapture',
    target: targetInfo.type,
    reason: breakpointConfirmed
      ? "chrome.storage/chrome.runtime were patched via a debugger breakpoint on this target's own entry script, before any of its top-level code ran -- both the first, one-shot call and any later, repeated call are captured"
      : patched
        ? "chrome.storage/chrome.runtime were patched, but only after the target's own top-level script may have already run (no entry script URL could be determined for this target, so the breakpoint mechanism above was skipped) -- a one-time call made at startup can still be missed; a later, repeated call made after patching is reliably captured"
        : 'could not confirm chrome.storage/chrome.runtime were ever successfully patched for this target; treat any storage/message events as best-effort, not complete',
    severity: breakpointConfirmed ? 'always-on' : 'known-gap',
  });

  // R14: unlike chrome.storage/chrome.runtime, crypto.subtle is confirmed present at every
  // patch attempt (see patchCrypto's own comment) -- so this is a fixed scope boundary, not a
  // per-run confirmation question. A hand-rolled or bundled pure-JS crypto implementation (a
  // vendored HMAC/AES library, common for custom request-signing schemes) makes no browser API
  // call this mechanism can intercept, and is invisible to it.
  addLimitation(limitations, {
    capability: 'cryptoLiveCapture',
    target: targetInfo.type,
    reason: 'only Web Crypto API (crypto.subtle) operations are captured -- digest/sign/verify/encrypt/decrypt, metadata only (algorithm, byte lengths), never raw key material or actual input/output bytes; a pure-JS crypto implementation bundled into the extension makes no browser API call this can see',
    severity: 'always-on',
  });
}

function parseScenario(scenarioPath) {
  const raw = JSON.parse(readFileSync(scenarioPath, 'utf8'));
  if (!Array.isArray(raw.steps)) throw new Error('Scenario file must have a "steps" array.');
  return raw.steps;
}

async function runStep(client, state, step) {
  switch (step.action) {
    case 'openPopup': {
      const popupPath = state.manifest?.action?.default_popup ?? state.manifest?.browser_action?.default_popup;
      if (!popupPath) throw new Error('Scenario step "openPopup" but manifest has no action.default_popup.');
      const url = `chrome-extension://${state.extensionId}/${popupPath}`;
      const res = await client.send('Target.createTarget', { url });
      state.namedTargets.popup = { targetId: res.result?.targetId };
      break;
    }
    case 'navigate': {
      const url = step.url.startsWith('chrome-extension://') ? step.url : `chrome-extension://${state.extensionId}/${step.url}`;
      const res = await client.send('Target.createTarget', { url });
      state.namedTargets[step.target ?? 'page'] = { targetId: res.result?.targetId };
      break;
    }
    case 'click': {
      const session = state.sessionFor(step.target ?? 'popup');
      if (session) {
        await client.send(
          'Runtime.evaluate',
          { expression: `document.querySelector(${JSON.stringify(step.selector)})?.click()` },
          session
        );
      }
      break;
    }
    case 'wait':
      await new Promise((r) => setTimeout(r, step.ms ?? 500));
      break;
    case 'evaluate': {
      const session = state.sessionFor(step.target ?? 'serviceWorker');
      if (session) await client.send('Runtime.evaluate', { expression: step.expression }, session);
      break;
    }
    default:
      throw new Error(`Unknown scenario step action: ${step.action}`);
  }
}

/**
 * Captures one extension's real runtime behavior into a structured, redacted file. Opt-in
 * only -- never invoked by the default crxray <url> download path (R10). See the plan this
 * implements: EP+ PLAN "crxray behavior-capture capability".
 *
 * @param {string} extensionDir - unpacked extension directory to load.
 * @param {string} scenarioPath - path to a scenario JSON file ({"steps": [...]})
 * @param {object} opts
 * @param {string} opts.outFile - where to write the capture file.
 * @param {boolean} opts.yesIReviewedPermissions - required confirmation gate (R11).
 * @param {number} [opts.timeoutMs] - hard wall-clock cap for the scenario run (R11).
 * @param {boolean} [opts.quiet]
 */
export async function captureBehavior(extensionDir, scenarioPath, opts = {}) {
  if (!opts.yesIReviewedPermissions) {
    throw new Error(
      'capture-behavior loads and runs third-party extension code. Pass --yes-i-reviewed-permissions ' +
        'after reviewing the extension\'s requested permissions (see `crxray audit`).'
    );
  }

  const manifestPath = path.join(extensionDir, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  // Static, no browser involved -- gives the message-passing/endpoint maps this capture's
  // events get cross-referenced against below (see mechanism.js). Run before anything else
  // touches extensionDir, same assumptions `crxray audit` already makes about that directory.
  const staticAudit = auditExtension(extensionDir, manifest, summarizeManifest(manifest));
  const steps = parseScenario(scenarioPath);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const chromePath = findChrome();
  const profileDir = mkdtempSync(path.join(tmpdir(), 'crxray-capture-'));

  const events = [];
  const limitations = [];
  let seq = 0;
  let extensionId = null;

  const namedTargets = {};
  const state = {
    manifest,
    get extensionId() {
      return extensionId;
    },
    namedTargets,
    sessionFor(name) {
      return namedTargets[name]?.sessionId;
    },
  };

  const client = new CdpPipeClient(chromePath, [
    '--remote-debugging-pipe',
    '--enable-unsafe-extension-debugging',
    `--user-data-dir=${profileDir}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--headless=new',
    '--disable-gpu',
    'about:blank',
  ]);

  const pendingResponseBodies = new Map(); // requestId -> {sessionId, url}
  // R12: sessionId -> { injectSource, onConfirmed } for a target instrumentAndResume set a real
  // breakpoint on. One listener handles every such session, rather than one per attach --
  // see instrumentAndResume's own comment for why this mechanism exists.
  const pendingBreakpointInjections = new Map();

  function pushEvent(raw) {
    events.push({ seq: seq++, ts: Date.now(), ...redactEvent(raw) });
  }

  client.on('Debugger.paused', async (msg) => {
    const entry = pendingBreakpointInjections.get(msg.sessionId);
    if (!entry) return; // not a pause this capability caused; nothing registered to resume it
    await client.send('Runtime.evaluate', { expression: entry.injectSource }, msg.sessionId);
    const res = await client.send(
      'Runtime.evaluate',
      { expression: 'globalThis.__crxrayTryPatch && globalThis.__crxrayTryPatch()' },
      msg.sessionId
    );
    if (res.result?.result?.value === true) entry.onConfirmed();
    await client.send('Debugger.resume', {}, msg.sessionId);
  });

  client.on('Target.attachedToTarget', (msg) => {
    const { sessionId, targetInfo, waitingForDebugger } = msg.params;
    const belongsToUs = extensionId && targetInfo.url?.includes(extensionId);

    if (targetInfo.type === 'service_worker' && targetInfo.url?.includes(extensionId ?? '\u0000')) {
      namedTargets.serviceWorker = { targetId: targetInfo.targetId, sessionId };
    }
    for (const [name, ref] of Object.entries(namedTargets)) {
      if (ref.targetId === targetInfo.targetId) ref.sessionId = sessionId;
    }

    if (!waitingForDebugger) {
      if (belongsToUs) {
        addLimitation(limitations, {
          capability: 'preExecutionInstrumentation',
          target: targetInfo.type,
          reason: 'target was already running when the capture session attached; calls made before attachment are not captured',
          severity: 'known-gap',
        });
      }
      return;
    }

    instrumentAndResume(client, sessionId, targetInfo, limitations, {
      extensionDir,
      extensionId,
      manifest,
      pendingBreakpointInjections,
    }).catch((err) => {
      addLimitation(limitations, {
        capability: 'preExecutionInstrumentation',
        target: targetInfo.type,
        reason: `instrumentation failed: ${err.message}`,
        severity: 'known-gap',
      });
    });
  });

  client.on('Runtime.consoleAPICalled', (msg) => {
    const arg = msg.params.args?.[0];
    if (arg?.type !== 'string' || !arg.value?.startsWith(CAPTURE_MARKER)) return;
    try {
      const entry = JSON.parse(arg.value.slice(CAPTURE_MARKER.length));
      pushEvent({ targetType: 'instrumented', sessionId: msg.sessionId, ...entry });
    } catch {
      // malformed capture payload; drop rather than crash the run
    }
  });

  client.on('Network.requestWillBeSent', (msg) => {
    const { requestId, request } = msg.params;
    pendingResponseBodies.set(requestId, { sessionId: msg.sessionId });
    pushEvent({
      kind: 'network',
      direction: 'request',
      sessionId: msg.sessionId,
      requestId,
      url: request.url,
      method: request.method,
      headers: request.headers,
      body: request.postData,
    });
  });

  client.on('Network.responseReceived', async (msg) => {
    const { requestId, response } = msg.params;
    const mimeOk = CAPTURABLE_MIME_RE.test(response.mimeType ?? '');
    const base = {
      kind: 'network',
      direction: 'response',
      sessionId: msg.sessionId,
      requestId,
      url: response.url,
      status: response.status,
      headers: response.headers,
    };
    if (!mimeOk) {
      addLimitation(limitations, {
        capability: 'responseBody',
        target: response.url,
        reason: `response body skipped (mimeType=${response.mimeType})`,
        severity: 'known-gap',
      });
      pushEvent(base);
      return;
    }
    try {
      const bodyRes = await client.send('Network.getResponseBody', { requestId }, msg.sessionId);
      const bodyText = bodyRes.result?.body ?? '';
      const truncated = bodyText.length > RESPONSE_BODY_BYTE_CAP;
      pushEvent({
        ...base,
        body: truncated ? bodyText.slice(0, RESPONSE_BODY_BYTE_CAP) : bodyText,
        truncated,
        originalByteLength: truncated ? bodyText.length : undefined,
      });
    } catch (err) {
      pushEvent({ ...base, bodyUnavailable: true, reason: err.message });
    }
  });

  client.on('Log.entryAdded', (msg) => {
    pushEvent({ kind: 'console', sessionId: msg.sessionId, level: msg.params.entry.level, text: msg.params.entry.text });
  });

  await client.send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
  await client.send('Target.setDiscoverTargets', { discover: true });

  const loadRes = await client.send('Extensions.loadUnpacked', { path: path.resolve(extensionDir) });
  if (loadRes.error) {
    await killAndCleanup(client, profileDir);
    throw new Error(`Extensions.loadUnpacked failed: ${loadRes.error.message}`);
  }
  extensionId = loadRes.result.id;

  let timedOut = false;
  try {
    await Promise.race([
      (async () => {
        for (const step of steps) await runStep(client, state, step);
      })(),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), timeoutMs)),
    ]);
  } catch (err) {
    if (err.message === 'timeout') {
      timedOut = true;
      addLimitation(limitations, {
        capability: 'scenario',
        target: 'all',
        reason: `scenario exceeded ${timeoutMs}ms timeout and was aborted`,
        severity: 'blocking',
      });
    } else {
      throw err;
    }
  }

  // Let in-flight response bodies settle briefly before closing.
  await new Promise((r) => setTimeout(r, 500));

  await killAndCleanup(client, profileDir);

  addLimitation(limitations, {
    capability: 'scope',
    target: 'all',
    reason: 'this capture reflects only the scenario actually exercised, under one run, one environment -- not a complete record of the extension\'s behavior',
    severity: 'always-on',
  });

  const capture = {
    schemaVersion: SCHEMA_VERSION,
    scenarioId: path.basename(scenarioPath),
    extensionId,
    version: manifest.version ?? null,
    chromeVersion: null,
    timestamp: new Date().toISOString(),
    events,
    mechanism: buildMechanismReport(staticAudit, events),
    timeline: { edges: buildCausalityEdges(events) },
    limitations,
    disclaimer: DISCLAIMER,
  };

  const outFile = opts.outFile ?? `${path.basename(extensionDir)}-capture.json`;
  writeFileSync(outFile, JSON.stringify(capture, null, 2));

  return { outFile, capture, timedOut };
}
