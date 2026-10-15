import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { captureBehavior } from '../src/behavior-capture.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_EXT = path.join(HERE, 'fixtures', 'capture-fixture-ext');
const FIXTURE_SCENARIO = path.join(HERE, 'fixtures', 'capture-fixture-scenario.json');

function hasRealChrome() {
  const candidates = [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
  ];
  return process.env.CRXRAY_CHROME_PATH ? existsSync(process.env.CRXRAY_CHROME_PATH) : candidates.some(existsSync);
}

// This suite launches a real Chrome and loads a real extension -- skipped, not failed, when
// no Chrome binary is available in the environment, same graceful-degradation posture as the
// humanify/wakaru integrations (see test/humanify.test.js).
const describe = hasRealChrome() ? test : test.skip;

describe('captureBehavior refuses to run without the permission-gate confirmation (R11)', () => {
  return assert.rejects(
    () => captureBehavior(FIXTURE_EXT, FIXTURE_SCENARIO, {}),
    /yes-i-reviewed-permissions/
  );
});

describe('captureBehavior captures pre-execution service-worker storage writes, a popup message round-trip, and redacts secrets (R3, R6, R7, R0)', async () => {
  const outDir = mkdtempSync(path.join(tmpdir(), 'crxray-capture-test-'));
  const outFile = path.join(outDir, 'capture.json');

  const { capture, outFile: writtenPath } = await captureBehavior(FIXTURE_EXT, FIXTURE_SCENARIO, {
    outFile,
    yesIReviewedPermissions: true,
    timeoutMs: 20_000,
  });

  assert.equal(writtenPath, outFile);
  assert.ok(existsSync(outFile), 'capture file was written');

  const onDisk = JSON.parse(readFileSync(outFile, 'utf8'));
  assert.equal(onDisk.schemaVersion, 1);
  assert.ok(onDisk.extensionId, 'extension ID resolved from Extensions.loadUnpacked');
  assert.ok(Array.isArray(onDisk.limitations) && onDisk.limitations.length > 0, 'limitations always populated');
  assert.ok(onDisk.limitations.some((l) => l.severity === 'always-on'), 'standard scope caveat always present');
  assert.ok(onDisk.disclaimer.includes('verification aid'));

  // R12 closed the one-shot blind spot documented in instrumentAndResume's own comment: a real
  // debugger breakpoint at the entry script's own first line holds the target paused -- nothing
  // in its own code can run -- until patching is confirmed, so the extension's very first,
  // one-time chrome.storage.local.set() (swStarted/token, the one-shot call this harness used
  // to structurally miss) is now a hard assertion, not a soft one. Confirmed deterministic
  // across 9 direct repeated real-Chrome runs before this test was written, not assumed.
  const storageEvents = capture.events.filter((e) => e.kind === 'storage');
  const oneShotWrite = storageEvents.find((e) => e.value?.swStarted === true);
  assert.ok(oneShotWrite, 'the extension\'s very first, one-time storage write is captured, not missed');
  assert.equal(oneShotWrite.value.token, '[REDACTED]', 'the one-shot write\'s own secret-shaped value is redacted');

  const pingValue = storageEvents.find((e) => 'apiKey' in (e.value ?? {}));
  assert.ok(pingValue, 'the later, repeated storage write is also captured');
  assert.equal(pingValue.value.apiKey, '[REDACTED]', 'a secret-shaped storage key is redacted before being written to disk');

  assert.ok(
    onDisk.limitations.some(
      (l) => l.capability === 'storageMessageLiveCapture' && l.target === 'service_worker' && l.severity === 'always-on'
    ),
    'the service worker\'s entry script URL is determinable from the manifest, so its breakpoint-confirmed limitation entry is always present'
  );
  assert.ok(
    onDisk.limitations.some(
      (l) => l.capability === 'storageMessageLiveCapture' && l.target === 'page' && l.severity === 'always-on'
    ),
    'the popup\'s entry script URL is read off its own HTML, so its breakpoint-confirmed limitation entry is always present'
  );

  // R14: crypto.subtle is a standard Web Crypto API global, confirmed present (unlike
  // chrome.storage/chrome.runtime) even at the earliest pre-resume breakpoint pause -- so the
  // extension's one-shot digest() call, made before chrome.storage even exists, is captured
  // with the same hard-assertion confidence as the network probe above, not a soft one.
  const cryptoEvents = capture.events.filter((e) => e.kind === 'crypto');
  const digestEvent = cryptoEvents.find((e) => e.method === 'digest');
  assert.ok(digestEvent, 'the one-shot crypto.subtle.digest() call is captured, not missed');
  assert.equal(digestEvent.algorithm, 'SHA-256');
  assert.equal(typeof digestEvent.dataByteLength, 'number');
  assert.equal(typeof digestEvent.outputByteLength, 'number');
  assert.ok(
    onDisk.limitations.some((l) => l.capability === 'cryptoLiveCapture'),
    'the Web-Crypto-only scope boundary (pure-JS crypto libraries are invisible to this) is always named'
  );

  const networkEvents = capture.events.filter((e) => e.kind === 'network');
  assert.ok(networkEvents.some((e) => e.direction === 'response' && e.url.endsWith('sw.js')), 'network capture works regardless of the injection mechanism above');

  // mechanism report (R12): cross-references audit.js's static maps against this same run's
  // events. The fixture's sw.js opens with a real fetch() call -- network capture is CDP-level
  // and unaffected by the one-shot/pre-resume timing issues above, so this side is a hard
  // assertion, not a soft one.
  assert.ok(onDisk.mechanism, 'capture file carries a mechanism section');
  const probeEndpoint = onDisk.mechanism.endpoints.find((e) => e.url.includes('mechanism-probe'));
  assert.ok(probeEndpoint, 'the static fetch() call site in sw.js is present in mechanism.endpoints');
  assert.equal(probeEndpoint.method, 'POST');
  assert.deepEqual(probeEndpoint.headersKeys, ['X-Test']);
  assert.equal(probeEndpoint.confirmedAtRuntime, true, 'network-level capture confirms the fetch() actually fired, independent of the storage/message patching race');

  // R12 also closes the popup's one-shot sendMessage() call -- its own entry script (popup.js)
  // is read off disk and breakpointed the same way, so this is a hard assertion too now.
  const pingPair = onDisk.mechanism.messages.find((m) => m.discriminants.includes('PING'));
  assert.ok(pingPair, 'the static sender/listener pair for PING is present in mechanism.messages');
  assert.equal(pingPair.confidence, 'exact');
  assert.equal(pingPair.confirmedAtRuntime, true, 'the popup\'s one-shot sendMessage() call is captured, not missed');
  assert.ok(pingPair.observed.sent.length > 0, 'the sent side of the pair carries the real captured message');

  // Causal timeline (R13): a pure post-processing pass over the same events, no new browser
  // mechanism. The popup's sent PING and the service worker's received PING are two separate
  // events (different sessions) with identical content -- a hard assertion, same CDP-level
  // reliability as the mechanism checks above. The message-receipt -> storage-write link is a
  // same-session heuristic, explicitly 'probable', so this only asserts it exists when the
  // underlying storage write is itself present (soft on the heuristic, hard on the real pair).
  assert.ok(onDisk.timeline, 'capture file carries a timeline section');
  const sentPing = capture.events.find((e) => e.kind === 'message' && e.direction === 'sent');
  const receivedPing = capture.events.find((e) => e.kind === 'message' && e.direction === 'received');
  assert.ok(sentPing && receivedPing, 'both sides of the PING round-trip were captured');
  assert.ok(
    onDisk.timeline.edges.some(
      (e) => e.from === sentPing.seq && e.to === receivedPing.seq && e.basis === 'message-pair' && e.confidence === 'exact'
    ),
    'the sent PING links to the received PING as an exact message-pair edge'
  );
  if (pingValue) {
    assert.ok(
      onDisk.timeline.edges.some(
        (e) => e.to === pingValue.seq && e.basis === 'same-session-proximity' && e.confidence === 'probable'
      ),
      'the repeated storage write links back to something in the same session shortly before it'
    );
  }

  // R15: a crypto operation is a timeline trigger/effect too (same-session-proximity), same
  // mechanism as storage/message. The fixture's digest() chains its own fetch() inside .then(),
  // so the signed-probe request is guaranteed to come strictly after the digest's own report --
  // a hard assertion, not conditional, since the ordering is deterministic by construction.
  const signedProbeRequest = networkEvents.find((e) => e.direction === 'request' && e.url.includes('signed-probe'));
  assert.ok(signedProbeRequest, 'the fetch chained inside digest().then() is captured');
  assert.ok(
    onDisk.timeline.edges.some(
      (e) => e.from === digestEvent.seq && e.to === signedProbeRequest.seq && e.basis === 'same-session-proximity' && e.confidence === 'probable'
    ),
    'the crypto digest links to the fetch it triggers, same heuristic already proven for storage/message'
  );

  rmSync(outDir, { recursive: true, force: true });
});

describe('captureBehavior enforces the timeout and cleans up the temp profile (R11)', async () => {
  const outDir = mkdtempSync(path.join(tmpdir(), 'crxray-capture-timeout-'));
  const outFile = path.join(outDir, 'capture.json');
  const slowScenario = path.join(outDir, 'slow-scenario.json');
  await import('node:fs').then((fs) =>
    fs.writeFileSync(slowScenario, JSON.stringify({ steps: [{ action: 'wait', ms: 5000 }] }))
  );

  const { capture, timedOut } = await captureBehavior(FIXTURE_EXT, slowScenario, {
    outFile,
    yesIReviewedPermissions: true,
    timeoutMs: 500,
  });

  assert.equal(timedOut, true);
  assert.ok(capture.limitations.some((l) => l.capability === 'scenario' && l.severity === 'blocking'));
  assert.ok(existsSync(outFile), 'a labeled capture is still written on timeout, not silently dropped');

  rmSync(outDir, { recursive: true, force: true });
});
