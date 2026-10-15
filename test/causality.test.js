import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCausalityEdges } from '../src/causality.js';

test('buildCausalityEdges links a sent message to the first matching later received event (exact)', () => {
  const events = [
    { seq: 0, ts: 1000, kind: 'message', direction: 'sent', sessionId: 'popup', message: { type: 'PING' } },
    { seq: 1, ts: 1005, kind: 'message', direction: 'received', sessionId: 'sw', message: { type: 'PING' } },
  ];
  const edges = buildCausalityEdges(events);
  assert.deepEqual(edges, [{ from: 0, to: 1, basis: 'message-pair', confidence: 'exact' }]);
});

test('buildCausalityEdges does not link a sent message to an earlier received event (ordering matters)', () => {
  const events = [
    { seq: 0, ts: 1000, kind: 'message', direction: 'received', sessionId: 'sw', message: { type: 'PING' } },
    { seq: 1, ts: 1005, kind: 'message', direction: 'sent', sessionId: 'popup', message: { type: 'PING' } },
  ];
  const edges = buildCausalityEdges(events);
  assert.deepEqual(edges.filter((e) => e.basis === 'message-pair'), []);
});

test('buildCausalityEdges does not link messages with different content', () => {
  const events = [
    { seq: 0, ts: 1000, kind: 'message', direction: 'sent', sessionId: 'popup', message: { type: 'PING' } },
    { seq: 1, ts: 1005, kind: 'message', direction: 'received', sessionId: 'sw', message: { type: 'OTHER' } },
  ];
  const edges = buildCausalityEdges(events);
  assert.deepEqual(edges.filter((e) => e.basis === 'message-pair'), []);
});

test('buildCausalityEdges does not double-claim the same received event for two sent events', () => {
  const events = [
    { seq: 0, ts: 1000, kind: 'message', direction: 'sent', sessionId: 'popup', message: { type: 'PING' } },
    { seq: 1, ts: 1001, kind: 'message', direction: 'sent', sessionId: 'popup2', message: { type: 'PING' } },
    { seq: 2, ts: 1005, kind: 'message', direction: 'received', sessionId: 'sw', message: { type: 'PING' } },
  ];
  const edges = buildCausalityEdges(events);
  const messagePairs = edges.filter((e) => e.basis === 'message-pair');
  assert.equal(messagePairs.length, 1, 'only one sender claims the single received event');
  assert.equal(messagePairs[0].from, 0, 'the earlier sender claims it');
});

test('buildCausalityEdges links a storage write to an earlier same-session message-received event within the proximity window', () => {
  const events = [
    { seq: 0, ts: 1000, kind: 'message', direction: 'received', sessionId: 'sw', message: { type: 'PING' } },
    { seq: 1, ts: 1010, kind: 'storage', sessionId: 'sw', area: 'local', method: 'set', value: { lastPing: 1 } },
  ];
  const edges = buildCausalityEdges(events);
  assert.deepEqual(edges.filter((e) => e.basis === 'same-session-proximity'), [
    { from: 0, to: 1, basis: 'same-session-proximity', confidence: 'probable' },
  ]);
});

test('buildCausalityEdges links a network request to an earlier same-session storage event within the proximity window', () => {
  const events = [
    { seq: 0, ts: 1000, kind: 'storage', sessionId: 'sw', area: 'local', method: 'set', value: { a: 1 } },
    { seq: 1, ts: 1050, kind: 'network', direction: 'request', sessionId: 'sw', url: 'https://api.example.com/x' },
  ];
  const edges = buildCausalityEdges(events);
  assert.deepEqual(edges.filter((e) => e.basis === 'same-session-proximity'), [
    { from: 0, to: 1, basis: 'same-session-proximity', confidence: 'probable' },
  ]);
});

test('buildCausalityEdges does not link same-session events outside the proximity window', () => {
  const events = [
    { seq: 0, ts: 1000, kind: 'message', direction: 'received', sessionId: 'sw', message: { type: 'PING' } },
    { seq: 1, ts: 5000, kind: 'storage', sessionId: 'sw', area: 'local', method: 'set', value: { a: 1 } },
  ];
  const edges = buildCausalityEdges(events);
  assert.deepEqual(edges.filter((e) => e.basis === 'same-session-proximity'), []);
});

test('buildCausalityEdges does not link events across different sessions', () => {
  const events = [
    { seq: 0, ts: 1000, kind: 'message', direction: 'received', sessionId: 'sw', message: { type: 'PING' } },
    { seq: 1, ts: 1010, kind: 'storage', sessionId: 'popup', area: 'local', method: 'set', value: { a: 1 } },
  ];
  const edges = buildCausalityEdges(events);
  assert.deepEqual(edges.filter((e) => e.basis === 'same-session-proximity'), []);
});

test('buildCausalityEdges ignores events with no sessionId for proximity linking, without throwing', () => {
  const events = [
    { seq: 0, ts: 1000, kind: 'network', direction: 'response', url: 'https://x' },
    { seq: 1, ts: 1010, kind: 'console', level: 'log', text: 'hi' },
  ];
  assert.doesNotThrow(() => buildCausalityEdges(events));
  assert.deepEqual(buildCausalityEdges(events), []);
});

test('buildCausalityEdges returns an empty array for an empty event list', () => {
  assert.deepEqual(buildCausalityEdges([]), []);
});

test('buildCausalityEdges links a crypto operation to the network request it triggers', () => {
  const events = [
    { seq: 0, ts: 1000, kind: 'crypto', sessionId: 'sw', method: 'sign', algorithm: 'HMAC' },
    { seq: 1, ts: 1010, kind: 'network', direction: 'request', sessionId: 'sw', url: 'https://api.example.com/x' },
  ];
  const edges = buildCausalityEdges(events);
  assert.deepEqual(edges.filter((e) => e.basis === 'same-session-proximity'), [
    { from: 0, to: 1, basis: 'same-session-proximity', confidence: 'probable' },
  ]);
});

test('buildCausalityEdges links a storage write to an earlier same-session crypto operation', () => {
  const events = [
    { seq: 0, ts: 1000, kind: 'crypto', sessionId: 'sw', method: 'digest', algorithm: 'SHA-256' },
    { seq: 1, ts: 1010, kind: 'storage', sessionId: 'sw', area: 'local', method: 'set', value: { a: 1 } },
  ];
  const edges = buildCausalityEdges(events);
  assert.deepEqual(edges.filter((e) => e.basis === 'same-session-proximity'), [
    { from: 0, to: 1, basis: 'same-session-proximity', confidence: 'probable' },
  ]);
});

test('buildCausalityEdges links a crypto operation to an earlier same-session message-received event', () => {
  const events = [
    { seq: 0, ts: 1000, kind: 'message', direction: 'received', sessionId: 'sw', message: { type: 'SIGN_THIS' } },
    { seq: 1, ts: 1010, kind: 'crypto', sessionId: 'sw', method: 'sign', algorithm: 'HMAC' },
  ];
  const edges = buildCausalityEdges(events);
  assert.deepEqual(edges.filter((e) => e.basis === 'same-session-proximity'), [
    { from: 0, to: 1, basis: 'same-session-proximity', confidence: 'probable' },
  ]);
});
