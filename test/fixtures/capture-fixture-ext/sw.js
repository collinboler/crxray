crypto.subtle.digest('SHA-256', new TextEncoder().encode('crxray-fixture')).then(() => {
  fetch('http://127.0.0.1:1/signed-probe', { method: 'POST' }).catch(() => {});
}).catch(() => {});

fetch('http://127.0.0.1:1/mechanism-probe', { method: 'POST', headers: { 'X-Test': '1' } }).catch(() => {});

chrome.storage.local.set({ swStarted: true, token: 'should-not-redact-in-storage-value-test' });

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === 'PING') {
    chrome.storage.local.set({ lastPing: Date.now(), apiKey: 'secret-should-be-redacted' });
    sendResponse({ type: 'PONG' });
  }
});
