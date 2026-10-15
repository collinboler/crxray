// Recursive, best-effort redaction for the behavior-capture tool (R0). This module has no
// capture-writing logic of its own -- it exists so behavior-capture.js's writer can gate every
// write through it, built and tested before that writer exists at all (see the plan: no code
// path may write an unredacted event to disk, including during the harness's own development).
//
// Best-effort, not a security guarantee: it matches common secret-shaped keys and header
// value shapes (Bearer/Basic auth), not every possible secret encoding. Documented as such
// wherever this module's output is used.

const SENSITIVE_KEY_RE =
  /^(authorization|cookie|set-cookie|proxy-authorization|password|passwd|secret|token|api[-_]?key|access[-_]?token|refresh[-_]?token|session(?:id)?|private[-_]?key|client[-_]?secret)$/i;

const BEARER_RE = /^Bearer\s+\S+/i;
const BASIC_AUTH_RE = /^Basic\s+[A-Za-z0-9+/=]+$/i;

function looksLikeSecretValue(value) {
  return typeof value === 'string' && (BEARER_RE.test(value) || BASIC_AUTH_RE.test(value));
}

/**
 * Recursively redacts any object/array value: a key matching the sensitive-key list gets its
 * whole value replaced; a string value shaped like a bearer/basic auth header is replaced
 * regardless of its key. Primitives that aren't secret-shaped pass through unchanged.
 */
export function redactDeep(value) {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map((v) => redactDeep(v));
  if (typeof value === 'object') {
    const out = {};
    for (const [key, v] of Object.entries(value)) {
      if (SENSITIVE_KEY_RE.test(key)) {
        out[key] = '[REDACTED]';
      } else {
        out[key] = redactDeep(v);
      }
    }
    return out;
  }
  if (looksLikeSecretValue(value)) return '[REDACTED]';
  return value;
}

/** Redacts a header map by key (Authorization, Cookie, etc.) regardless of value shape. */
export function redactHeaders(headers) {
  if (!headers || typeof headers !== 'object') return headers;
  const out = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key] = SENSITIVE_KEY_RE.test(key) ? '[REDACTED]' : value;
  }
  return out;
}

/** Redacts sensitive query-string parameter values in a URL. Non-absolute/unparseable URLs pass through unchanged. */
export function redactUrl(url) {
  if (typeof url !== 'string') return url;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return url;
  }
  let changed = false;
  for (const key of [...parsed.searchParams.keys()]) {
    if (SENSITIVE_KEY_RE.test(key)) {
      parsed.searchParams.set(key, '[REDACTED]');
      changed = true;
    }
  }
  return changed ? parsed.toString() : url;
}

/**
 * Redacts a capture event's known fields (url, headers, request/response headers, body,
 * storage value, message payload, console args) before it is ever written to disk. This is
 * the single function behavior-capture.js's writer calls -- see module comment above.
 */
export function redactEvent(event) {
  const out = { ...event };
  if (out.url !== undefined) out.url = redactUrl(out.url);
  if (out.headers !== undefined) out.headers = redactHeaders(out.headers);
  if (out.requestHeaders !== undefined) out.requestHeaders = redactHeaders(out.requestHeaders);
  if (out.responseHeaders !== undefined) out.responseHeaders = redactHeaders(out.responseHeaders);
  if (out.body !== undefined) out.body = redactDeep(out.body);
  if (out.value !== undefined) out.value = redactDeep(out.value);
  if (out.args !== undefined) out.args = redactDeep(out.args);
  if (out.message !== undefined) out.message = redactDeep(out.message);
  return out;
}
