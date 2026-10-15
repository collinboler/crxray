import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { collectMessagePassing } from '../src/audit.js';

function makeFiles(dir, files) {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
}

test('collectMessagePassing links a sender and listener sharing a literal discriminant as exact', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-msgmap-'));
  makeFiles(dir, {
    'background.js': "chrome.runtime.sendMessage({type: 'PING', value: 1});\n",
    'content.js':
      "chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {\n  if (msg.type === 'PING') sendResponse('pong');\n});\n",
  });

  const map = collectMessagePassing(dir);
  const exact = map.filter((c) => c.confidence === 'exact');
  assert.equal(exact.length, 1);
  assert.equal(exact[0].sender.file, 'background.js');
  assert.equal(exact[0].listener.file, 'content.js');
  assert.deepEqual(exact[0].discriminants, ['PING']);
});

test('collectMessagePassing marks both sides ambiguous when no discriminant is inferable', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-msgmap-'));
  makeFiles(dir, {
    'background.js': 'chrome.runtime.sendMessage(someVariable);\n',
    'content.js': 'chrome.runtime.onMessage.addListener((msg) => { doSomething(msg); });\n',
  });

  const map = collectMessagePassing(dir);
  assert.equal(map.length, 2);
  for (const entry of map) {
    assert.equal(entry.confidence, 'ambiguous');
    assert.deepEqual(entry.discriminants, []);
  }
  const senderOnly = map.find((e) => e.sender && !e.listener);
  const listenerOnly = map.find((e) => e.listener && !e.sender);
  assert.ok(senderOnly, 'unmatched sender is its own entry, not forced into a pair');
  assert.ok(listenerOnly, 'unmatched listener is its own entry, not forced into a pair');
});

test('collectMessagePassing marks a shared discriminant as probable when it is not unique', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'crxray-msgmap-'));
  makeFiles(dir, {
    'a.js': "chrome.runtime.sendMessage({type: 'SYNC'});\n",
    'b.js': "chrome.runtime.sendMessage({type: 'SYNC'});\n",
    'c.js':
      "chrome.runtime.onMessage.addListener((msg) => { if (msg.type === 'SYNC') {} });\n",
  });

  const map = collectMessagePassing(dir);
  const probable = map.filter((c) => c.confidence === 'probable');
  assert.ok(probable.length >= 1, 'two senders claiming the same discriminant should not read as exact');
  for (const entry of map) assert.notEqual(entry.confidence, 'exact');
});
