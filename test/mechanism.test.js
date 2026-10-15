import test from 'node:test';
import assert from 'node:assert/strict';
import { matchEndpoints, matchMessages, buildMechanismReport } from '../src/mechanism.js';

test('matchEndpoints confirms an exact URL+query match against a captured network request', () => {
  const endpointDetails = [{ url: 'https://api.example.com/v1/sync', method: 'POST', headersKeys: ['Authorization'] }];
  const events = [
    { seq: 0, kind: 'network', direction: 'request', url: 'https://api.example.com/v1/sync', method: 'POST', headers: { Authorization: '[REDACTED]' } },
  ];
  const result = matchEndpoints(endpointDetails, events);
  assert.equal(result.length, 1);
  assert.equal(result[0].confirmedAtRuntime, true);
  assert.equal(result[0].observed.length, 1);
  assert.equal(result[0].observed[0].seq, 0);
});

test('matchEndpoints confirms a match when the real request carries extra query params the static scan could not predict', () => {
  const endpointDetails = [{ url: 'https://api.example.com/v1/sync', method: null, headersKeys: [] }];
  const events = [
    { seq: 0, kind: 'network', direction: 'request', url: 'https://api.example.com/v1/sync?token=abc&ts=123', method: 'GET', headers: {} },
  ];
  const result = matchEndpoints(endpointDetails, events);
  assert.equal(result[0].confirmedAtRuntime, true);
});

test('matchEndpoints confirms a same-host, path-prefix match for a dynamically-built URL', () => {
  const endpointDetails = [{ url: 'https://api.example.com/v1/items', method: null, headersKeys: [] }];
  const events = [
    { seq: 0, kind: 'network', direction: 'request', url: 'https://api.example.com/v1/items/42/detail', method: 'GET', headers: {} },
  ];
  const result = matchEndpoints(endpointDetails, events);
  assert.equal(result[0].confirmedAtRuntime, true);
});

test('matchEndpoints leaves a static finding unconfirmed when nothing observed at runtime matches it', () => {
  const endpointDetails = [{ url: 'https://unused.example.com/never-called', method: null, headersKeys: [] }];
  const events = [
    { seq: 0, kind: 'network', direction: 'request', url: 'https://other.example.com/x', method: 'GET', headers: {} },
  ];
  const result = matchEndpoints(endpointDetails, events);
  assert.equal(result[0].confirmedAtRuntime, false);
  assert.deepEqual(result[0].observed, []);
});

test('matchEndpoints ignores response-direction events when matching request-shape findings', () => {
  const endpointDetails = [{ url: 'https://api.example.com/v1/sync', method: 'POST', headersKeys: [] }];
  const events = [
    { seq: 0, kind: 'network', direction: 'response', url: 'https://api.example.com/v1/sync', status: 200, headers: {} },
  ];
  const result = matchEndpoints(endpointDetails, events);
  assert.equal(result[0].confirmedAtRuntime, false);
});

test('matchMessages confirms both sides of a sender/listener pair when both fire at runtime', () => {
  const messagePassing = [
    {
      sender: { file: 'popup.js', line: 1, kind: 'sendMessage' },
      listener: { file: 'sw.js', line: 3, kind: 'onMessage' },
      discriminants: ['PING'],
      confidence: 'exact',
    },
  ];
  const events = [
    { seq: 0, kind: 'message', direction: 'sent', message: { type: 'PING' } },
    { seq: 1, kind: 'message', direction: 'received', message: { type: 'PING' } },
  ];
  const result = matchMessages(messagePassing, events);
  assert.equal(result[0].confirmedAtRuntime, true);
  assert.equal(result[0].observed.sent.length, 1);
  assert.equal(result[0].observed.received.length, 1);
});

test('matchMessages reports a pair as unconfirmed, not fabricated, when nothing was observed (the documented one-shot/popup-injection gap)', () => {
  const messagePassing = [
    {
      sender: { file: 'popup.js', line: 1, kind: 'sendMessage' },
      listener: { file: 'sw.js', line: 3, kind: 'onMessage' },
      discriminants: ['PING'],
      confidence: 'exact',
    },
  ];
  const result = matchMessages(messagePassing, []);
  assert.equal(result[0].confirmedAtRuntime, false);
  assert.deepEqual(result[0].observed, { sent: [], received: [] });
});

test('matchMessages never confirms an ambiguous entry that has no discriminant at all', () => {
  const messagePassing = [
    { sender: { file: 'a.js', line: 1, kind: 'sendMessage' }, listener: null, discriminants: [], confidence: 'ambiguous' },
  ];
  const events = [{ seq: 0, kind: 'message', direction: 'sent', message: { foo: 'bar' } }];
  const result = matchMessages(messagePassing, events);
  assert.equal(result[0].confirmedAtRuntime, false);
});

test('matchMessages only checks the sent side for a sender-only entry, never the received side', () => {
  const messagePassing = [
    { sender: { file: 'a.js', line: 1, kind: 'sendMessage' }, listener: null, discriminants: ['PING'], confidence: 'ambiguous' },
  ];
  const events = [{ seq: 0, kind: 'message', direction: 'received', message: { type: 'PING' } }];
  const result = matchMessages(messagePassing, events);
  assert.equal(result[0].confirmedAtRuntime, false, 'a received event should not confirm a sender-only static finding');
});

test('buildMechanismReport combines endpoint and message matching from an audit result', () => {
  const auditResult = {
    endpointDetails: [{ url: 'https://api.example.com/x', method: 'GET', headersKeys: [] }],
    messagePassing: [
      { sender: { file: 'a.js', line: 1, kind: 'sendMessage' }, listener: null, discriminants: ['X'], confidence: 'ambiguous' },
    ],
  };
  const events = [
    { seq: 0, kind: 'network', direction: 'request', url: 'https://api.example.com/x', method: 'GET', headers: {} },
  ];
  const report = buildMechanismReport(auditResult, events);
  assert.equal(report.endpoints.length, 1);
  assert.equal(report.endpoints[0].confirmedAtRuntime, true);
  assert.equal(report.messages.length, 1);
  assert.equal(report.messages[0].confirmedAtRuntime, false);
});

test('buildMechanismReport tolerates an audit result with no endpointDetails/messagePassing fields', () => {
  const report = buildMechanismReport({}, []);
  assert.deepEqual(report.endpoints, []);
  assert.deepEqual(report.messages, []);
});
