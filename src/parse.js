// Extension IDs are 32 chars in the a-p alphabet (base16 mapped onto a-p).
const ID_RE = /[a-p]{32}/;

const URL_PATTERNS = [
  { store: 'chrome', re: /^https?:\/\/chromewebstore\.google\.com\/detail\/(?:[^/]+\/)?([a-p]{32})/ },
  { store: 'chrome', re: /^https?:\/\/chrome\.google\.com\/webstore\/detail\/(?:[^/]+\/)?([a-p]{32})/ },
  { store: 'edge', re: /^https?:\/\/microsoftedge\.microsoft\.com\/addons\/detail\/(?:[^/]+\/)?([a-z]{32})/ },
];

/**
 * Resolve a Web Store URL or bare extension ID into { id, store }.
 * @param {string} input - store URL or 32-char extension ID
 * @param {string} [defaultStore] - store to assume for bare IDs ('chrome' | 'edge')
 */
export function parseExtensionRef(input, defaultStore = 'chrome') {
  const trimmed = input.trim();

  for (const { store, re } of URL_PATTERNS) {
    const m = trimmed.match(re);
    if (m) return { id: m[1], store };
  }

  if (/^[a-p]{32}$/.test(trimmed)) {
    return { id: trimmed, store: defaultStore };
  }

  // Edge IDs use the full a-z alphabet.
  if (defaultStore === 'edge' && /^[a-z]{32}$/.test(trimmed)) {
    return { id: trimmed, store: 'edge' };
  }

  // Last resort: an ID embedded somewhere in an unrecognized URL shape.
  if (/^https?:\/\//.test(trimmed)) {
    const m = trimmed.match(ID_RE);
    if (m) {
      const store = trimmed.includes('microsoftedge.microsoft.com') ? 'edge' : 'chrome';
      return { id: m[0], store };
    }
  }

  throw new Error(
    `Could not find an extension ID in "${input}". ` +
      'Pass a Chrome Web Store / Edge Add-ons URL or a 32-character extension ID.'
  );
}
