import test from 'node:test';
import assert from 'node:assert/strict';
import { redactDeep, redactHeaders, redactUrl, redactEvent } from '../src/redact.js';

test('redactHeaders redacts an Authorization bearer header by key', () => {
  const headers = { Authorization: 'Bearer abc123', 'Content-Type': 'application/json' };
  const out = redactHeaders(headers);
  assert.equal(out.Authorization, '[REDACTED]');
  assert.equal(out['Content-Type'], 'application/json');
});

test('redactUrl redacts a sensitive query parameter value', () => {
  const out = redactUrl('https://api.example.com/x?token=supersecret&page=2');
  assert.ok(out.includes('token=%5BREDACTED%5D') || out.includes('token=[REDACTED]'));
  assert.ok(out.includes('page=2'));
});

test('redactUrl leaves an unparseable/relative URL unchanged', () => {
  assert.equal(redactUrl('/relative/path?x=1'), '/relative/path?x=1');
});

test('redactDeep redacts a nested sensitive key regardless of depth', () => {
  const out = redactDeep({ user: { apiKey: 'sk_live_abc', name: 'ok' } });
  assert.equal(out.user.apiKey, '[REDACTED]');
  assert.equal(out.user.name, 'ok');
});

test('redactDeep redacts a storage value carrying a secret key', () => {
  const out = redactDeep({ secret: 'x', count: 3 });
  assert.equal(out.secret, '[REDACTED]');
  assert.equal(out.count, 3);
});

test('redactDeep passes an ordinary value through unchanged', () => {
  const out = redactDeep({ count: 3, label: 'hello' });
  assert.deepEqual(out, { count: 3, label: 'hello' });
});

test('redactDeep redacts a bare bearer-shaped string value even under a non-sensitive key', () => {
  const out = redactDeep({ note: 'Bearer abcdefg123' });
  assert.equal(out.note, '[REDACTED]');
});

test('redactEvent redacts url, headers, and nested body/value/message/args together', () => {
  const event = {
    kind: 'network',
    url: 'https://x.example.com/y?apikey=zzz',
    requestHeaders: { Authorization: 'Bearer t', Accept: '*/*' },
    body: { user: { password: 'p', id: 1 } },
    args: ['Bearer abc', 'plain text'],
  };
  const out = redactEvent(event);
  assert.ok(out.url.includes('[REDACTED]') || out.url.includes('%5BREDACTED%5D'));
  assert.equal(out.requestHeaders.Authorization, '[REDACTED]');
  assert.equal(out.requestHeaders.Accept, '*/*');
  assert.equal(out.body.user.password, '[REDACTED]');
  assert.equal(out.body.user.id, 1);
  assert.equal(out.args[0], '[REDACTED]');
  assert.equal(out.args[1], 'plain text');
});
