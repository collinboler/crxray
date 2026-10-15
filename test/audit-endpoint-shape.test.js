import test from 'node:test';
import assert from 'node:assert/strict';
import { collectEndpointDetailsFromContent } from '../src/audit.js';

test('collectEndpointDetailsFromContent captures method and header keys from a literal fetch() call', () => {
  const content = "fetch('https://api.example.com/v1/sync', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Api-Key': k}});";
  const details = collectEndpointDetailsFromContent(content);
  assert.equal(details.length, 1);
  assert.equal(details[0].url, 'https://api.example.com/v1/sync');
  assert.equal(details[0].method, 'POST');
  assert.deepEqual(details[0].headersKeys, ['Content-Type', 'X-Api-Key']);
});

test('collectEndpointDetailsFromContent returns a bare entry (no method/headers) for a plain fetch(url)', () => {
  const content = "fetch('https://example.com/ping');";
  const details = collectEndpointDetailsFromContent(content);
  assert.equal(details.length, 1);
  assert.equal(details[0].url, 'https://example.com/ping');
  assert.equal(details[0].method, null);
  assert.deepEqual(details[0].headersKeys, []);
});

test('collectEndpointDetailsFromContent handles multiple fetch() calls in one file', () => {
  const content = [
    "fetch('https://a.example.com/one', {method: 'GET'});",
    "fetch('https://b.example.com/two', {method: 'DELETE', headers: {Authorization: tok}});",
  ].join('\n');
  const details = collectEndpointDetailsFromContent(content);
  assert.equal(details.length, 2);
  assert.equal(details[0].method, 'GET');
  assert.equal(details[1].method, 'DELETE');
  assert.deepEqual(details[1].headersKeys, ['Authorization']);
});
