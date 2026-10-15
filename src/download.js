// These are the same update endpoints the browsers themselves poll for
// extension installs/updates, so they serve the canonical CRX for an ID.
// Google's endpoint returns 204 (treated as "not found" below) for any
// extension whose manifest requires a newer Chrome than the prodversion
// this declares. A real version string goes stale the moment it ships --
// confirmed twice in one session: the previous value here (131.x) failed
// against Bitwarden on 2026-10-10, and the real-current replacement
// (142.x) was independently found to already be ~a year stale again by
// the time of review, without the code itself changing at all. Using a
// permanent high sentinel instead: confirmed live on 2026-10-10 that
// Google's endpoint accepts prodversion=999.0.0.0 and serves the normal
// 302 redirect + real CRX, identical to a current real version string,
// for the same extension that failed against the stale 131.x value.
// Nothing here needs bumping again. (Edge's endpoint uses the same
// Omaha-protocol version check but wasn't independently confirmed with
// this sentinel -- no live Edge-catalog extension ID was on hand to test
// against; --chrome-version remains the escape hatch if that ever needs
// a real version string instead.)
const CHROME_VERSION = '999.0.0.0';
const DOWNLOAD_TIMEOUT_MS = 30_000;
const MAX_CRX_SIZE = 200 * 1024 * 1024; // 200MB

const CHROME_VERSION_RE = /^\d{1,4}(\.\d{1,5}){0,3}$/;

// Hosts the CRX download is allowed to land on after following redirects.
// clients2.google.com / edge.microsoft.com are the endpoints we request
// directly; the others are the CDN hosts those endpoints actually
// redirect to, confirmed by a live request on 2026-10-09 (chrome ->
// clients2.googleusercontent.com, edge -> *.delivery.mp.microsoft.com).
// If a store rotates its CDN host this will start throwing "untrusted
// host <name>" — update the entry below for that store.
const ALLOWED_HOSTS = {
  chrome: (host) => host === 'clients2.google.com' || host === 'clients2.googleusercontent.com',
  edge: (host) => host === 'edge.microsoft.com' || host.endsWith('.delivery.mp.microsoft.com'),
};

export function crxUrl(id, store = 'chrome', chromeVersion = CHROME_VERSION) {
  if (!CHROME_VERSION_RE.test(chromeVersion)) {
    throw new Error(`Invalid --chrome-version "${chromeVersion}": expected digits and dots only (e.g. 142.0.7444.0).`);
  }
  if (store === 'edge') {
    const x = encodeURIComponent(`id=${id}&installsource=ondemand&uc`);
    return `https://edge.microsoft.com/extensionwebstorebase/v1/crx?response=redirect&prodversion=${chromeVersion}&acceptformat=crx3&x=${x}`;
  }
  const x = encodeURIComponent(`id=${id}&uc`);
  return `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=${chromeVersion}&acceptformat=crx2,crx3&x=${x}`;
}

/**
 * Fetch a URL with a timeout, a response-size cap, and a check that the
 * final (post-redirect) host passes `isAllowedHost`. Exported separately
 * from downloadCrx so tests can point it at a local server instead of the
 * real store endpoints.
 */
export async function downloadFromUrl(
  url,
  { timeoutMs = DOWNLOAD_TIMEOUT_MS, maxBytes = MAX_CRX_SIZE, isAllowedHost = () => true, id = url } = {}
) {
  const controller = new AbortController();
  // The timer must stay armed through the full body read, not just until
  // the response headers arrive — a server that sends headers and then
  // stalls the body must still be caught by this deadline.
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, { redirect: 'follow', signal: controller.signal });

    if (res.status === 204 || res.status === 404) {
      throw new Error(
        `Extension ${id} not found. It may be unlisted, removed, the ID may be wrong, or it may require a newer ` +
          `Chrome/Edge than this request declared -- try --chrome-version <higher version>.`
      );
    }
    if (!res.ok) {
      throw new Error(`Download failed for ${id}: HTTP ${res.status} ${res.statusText}`);
    }

    const host = new URL(res.url).hostname;
    if (!isAllowedHost(host)) {
      throw new Error(`Refusing to use download from untrusted host "${host}".`);
    }

    const declaredLength = Number(res.headers.get('content-length') ?? 0);
    if (declaredLength > maxBytes) {
      throw new Error(`Download for ${id} declares ${declaredLength} bytes, over the ${maxBytes}-byte limit.`);
    }

    const buf = await readWithLimit(res, maxBytes, id);
    if (buf.length === 0) {
      throw new Error(`Empty response for ${id} — the extension may not be available.`);
    }
    return buf;
  } catch (err) {
    if (err.name === 'AbortError' || controller.signal.aborted) {
      throw new Error(`Download timed out after ${timeoutMs / 1000}s for ${id}.`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

async function readWithLimit(res, maxBytes, id) {
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`Download for ${id} exceeded the ${maxBytes}-byte limit.`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

/**
 * Download the CRX for an extension ID. Returns a Buffer.
 */
export async function downloadCrx(id, store = 'chrome', chromeVersion = CHROME_VERSION) {
  const url = crxUrl(id, store, chromeVersion);
  return downloadFromUrl(url, { id, isAllowedHost: ALLOWED_HOSTS[store] ?? (() => false) });
}
