import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { crxUrl, downloadFromUrl } from '../src/download.js';

test('crxUrl builds the chrome update endpoint', () => {
  const url = crxUrl('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'chrome');
  assert.match(url, /^https:\/\/clients2\.google\.com\/service\/update2\/crx\?/);
});

test('crxUrl builds the edge update endpoint', () => {
  const url = crxUrl('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'edge');
  assert.match(url, /^https:\/\/edge\.microsoft\.com\/extensionwebstorebase\/v1\/crx\?/);
});

test('crxUrl accepts a chromeVersion override, for when the built-in default goes stale', () => {
  // Google's update endpoint returns 204 (treated as "not found" by
  // downloadFromUrl) for any extension whose manifest requires a newer
  // Chrome than the prodversion a request declares -- confirmed live against
  // Bitwarden on 2026-10-10, which requires newer than the then-current
  // built-in default. The override is the escape hatch for whenever the
  // built-in default next falls behind.
  const chromeUrl = crxUrl('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'chrome', '142.0.7444.0');
  assert.match(chromeUrl, /prodversion=142\.0\.7444\.0/);

  const edgeUrl = crxUrl('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'edge', '142.0.7444.0');
  assert.match(edgeUrl, /prodversion=142\.0\.7444\.0/);
});

test('crxUrl uses the built-in sentinel version by default', () => {
  // Confirmed live on 2026-10-10: Google's endpoint accepts a permanently
  // high version (999.0.0.0) exactly like a real current one, so this
  // never needs bumping the way a real version string does.
  const url = crxUrl('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'chrome');
  assert.match(url, /prodversion=999\.0\.0\.0/);
});

test('crxUrl rejects a chromeVersion override that is not digits and dots', () => {
  // Found by independent review: the override was passed straight into a
  // URL query string with no validation, so an empty string or anything
  // containing "&" could inject extra query parameters.
  assert.throws(() => crxUrl('a'.repeat(32), 'chrome', ''), /Invalid --chrome-version/);
  assert.throws(() => crxUrl('a'.repeat(32), 'chrome', '1&x=evil'), /Invalid --chrome-version/);
  assert.throws(() => crxUrl('a'.repeat(32), 'chrome', 'latest'), /Invalid --chrome-version/);
});

async function withServer(handler, fn) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await fn(`http://127.0.0.1:${port}/`);
  } finally {
    server.close();
  }
}

test('downloadFromUrl returns the body when the host is allowed', async () => {
  await withServer(
    (req, res) => res.end('crx-bytes'),
    async (url) => {
      const buf = await downloadFromUrl(url, { isAllowedHost: (h) => h === '127.0.0.1' });
      assert.equal(buf.toString(), 'crx-bytes');
    }
  );
});

test('downloadFromUrl rejects a disallowed host', async () => {
  await withServer(
    (req, res) => res.end('crx-bytes'),
    async (url) => {
      await assert.rejects(downloadFromUrl(url, { isAllowedHost: () => false }), /untrusted host/);
    }
  );
});

test('downloadFromUrl rejects a response over the size limit', async () => {
  await withServer(
    (req, res) => {
      res.writeHead(200, { 'Content-Length': '20' });
      res.end('x'.repeat(20));
    },
    async (url) => {
      await assert.rejects(
        downloadFromUrl(url, { isAllowedHost: () => true, maxBytes: 10 }),
        /byte limit/
      );
    }
  );
});

test('downloadFromUrl times out a hanging response', async () => {
  await withServer(
    () => {
      /* never respond */
    },
    async (url) => {
      await assert.rejects(
        downloadFromUrl(url, { isAllowedHost: () => true, timeoutMs: 50 }),
        /timed out/
      );
    }
  );
});

test('downloadFromUrl times out when headers arrive but the body stalls', { timeout: 5000 }, async () => {
  await withServer(
    (req, res) => {
      res.writeHead(200, { 'Content-Length': '1000' });
      res.write('partial'); // headers + some bytes, then never finish
    },
    async (url) => {
      await assert.rejects(
        downloadFromUrl(url, { isAllowedHost: () => true, timeoutMs: 50 }),
        /timed out/
      );
    }
  );
});

test('downloadFromUrl surfaces a 404 as "not found"', async () => {
  await withServer(
    (req, res) => res.writeHead(404).end(),
    async (url) => {
      await assert.rejects(downloadFromUrl(url, { isAllowedHost: () => true }), /not found/);
    }
  );
});
