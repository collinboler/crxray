// These are the same update endpoints the browsers themselves poll for
// extension installs/updates, so they serve the canonical CRX for an ID.
const CHROME_VERSION = '131.0.6778.86';

export function crxUrl(id, store = 'chrome') {
  if (store === 'edge') {
    const x = encodeURIComponent(`id=${id}&installsource=ondemand&uc`);
    return `https://edge.microsoft.com/extensionwebstorebase/v1/crx?response=redirect&prodversion=${CHROME_VERSION}&acceptformat=crx3&x=${x}`;
  }
  const x = encodeURIComponent(`id=${id}&uc`);
  return `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=${CHROME_VERSION}&acceptformat=crx2,crx3&x=${x}`;
}

/**
 * Download the CRX for an extension ID. Returns a Buffer.
 */
export async function downloadCrx(id, store = 'chrome') {
  const url = crxUrl(id, store);
  const res = await fetch(url, { redirect: 'follow' });

  if (res.status === 204 || res.status === 404) {
    throw new Error(
      `Extension ${id} not found on the ${store} store. ` +
        'It may be unlisted, removed, or the ID may be wrong.'
    );
  }
  if (!res.ok) {
    throw new Error(`Download failed for ${id}: HTTP ${res.status} ${res.statusText}`);
  }

  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length === 0) {
    throw new Error(`Empty response for ${id} — the extension may not be available.`);
  }
  return buf;
}
