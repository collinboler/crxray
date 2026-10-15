// Cross-references crxray's static maps (collectEndpointDetails, collectMessagePassing in
// audit.js) against a real behavior-capture run's events. Neither side replaces the other:
// a static finding that nothing at runtime confirmed stays in the report as unconfirmed, not
// deleted or downgraded -- same "never silently claim complete" discipline as the capture
// file's own `limitations` array.

const DEFAULT_SAMPLE_CAP = 5;

function stripQuery(url) {
  const qIdx = url.indexOf('?');
  return qIdx === -1 ? url : url.slice(0, qIdx);
}

// A real request's URL rarely matches a literal fetch() call site byte-for-byte: query params
// are often built at runtime, and a path can be a prefix the static scan found as a base URL.
// Three widening steps, cheapest and most exact first.
function endpointMatches(staticUrl, observedUrl) {
  const staticNoQuery = stripQuery(staticUrl);
  const observedNoQuery = stripQuery(observedUrl);
  if (observedNoQuery === staticNoQuery) return true;
  if (observedUrl.startsWith(staticNoQuery)) return true;
  try {
    const staticParsed = new URL(staticNoQuery);
    const observedParsed = new URL(observedNoQuery);
    return staticParsed.hostname === observedParsed.hostname && observedParsed.pathname.startsWith(staticParsed.pathname);
  } catch {
    return false; // one side isn't a well-formed absolute URL; no basis to call it a match
  }
}

/**
 * Cross-references audit.js's static endpointDetails (literal-shape fetch() calls) against
 * captured network request events. confirmedAtRuntime is only ever set from an observed
 * event -- never inferred from the static finding alone.
 */
export function matchEndpoints(endpointDetails, events) {
  const requests = events.filter((e) => e.kind === 'network' && e.direction === 'request' && typeof e.url === 'string');

  return endpointDetails.map((entry) => {
    const matches = requests.filter((e) => endpointMatches(entry.url, e.url));
    return {
      url: entry.url,
      method: entry.method,
      headersKeys: entry.headersKeys,
      confirmedAtRuntime: matches.length > 0,
      observed: matches.slice(0, DEFAULT_SAMPLE_CAP).map((e) => ({
        seq: e.seq,
        url: e.url,
        method: e.method,
        headers: e.headers,
        body: e.body,
      })),
    };
  });
}

function extractMessageDiscriminant(message) {
  if (!message || typeof message !== 'object') return null;
  for (const key of ['type', 'action', 'cmd', 'command']) {
    if (typeof message[key] === 'string') return message[key];
  }
  return null;
}

/**
 * Cross-references audit.js's static messagePassing pairs against captured message events.
 * A sender-only (or listener-only) static entry is only ever checked on the side it actually
 * claims -- a received event can't confirm a sender-only finding, and vice versa.
 */
export function matchMessages(messagePassing, events) {
  const messageEvents = events.filter((e) => e.kind === 'message');
  const sent = messageEvents.filter((e) => e.direction === 'sent');
  const received = messageEvents.filter((e) => e.direction === 'received');

  return messagePassing.map((entry) => {
    const matchingSent = entry.sender && entry.discriminants.length
      ? sent.filter((e) => entry.discriminants.includes(extractMessageDiscriminant(e.message)))
      : [];
    const matchingReceived = entry.listener && entry.discriminants.length
      ? received.filter((e) => entry.discriminants.includes(extractMessageDiscriminant(e.message)))
      : [];

    return {
      sender: entry.sender,
      listener: entry.listener,
      discriminants: entry.discriminants,
      confidence: entry.confidence,
      confirmedAtRuntime: matchingSent.length > 0 || matchingReceived.length > 0,
      observed: {
        sent: matchingSent.slice(0, DEFAULT_SAMPLE_CAP).map((e) => ({ seq: e.seq, message: e.message })),
        received: matchingReceived.slice(0, DEFAULT_SAMPLE_CAP).map((e) => ({ seq: e.seq, message: e.message })),
      },
    };
  });
}

/**
 * Combines both cross-references into the capture file's `mechanism` section. `auditResult`
 * is whatever auditExtension() returned for the same extension directory captureBehavior just
 * loaded -- its endpointDetails/messagePassing fields, if either is absent, degrade to an
 * empty, well-formed result rather than throwing.
 */
export function buildMechanismReport(auditResult, events) {
  return {
    endpoints: matchEndpoints(auditResult?.endpointDetails ?? [], events),
    messages: matchMessages(auditResult?.messagePassing ?? [], events),
  };
}
