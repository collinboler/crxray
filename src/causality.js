// Links captured events into a causal timeline, as a pure post-processing pass over the
// already-captured `events` array -- no new browser mechanism, no new instrumentation. Two
// edge types, each honestly labeled by how sure it is:
//
// - 'message-pair' (exact): a sent message and the first later received event with the exact
//   same content. This is the same idea as mechanism.js's static sender/listener matching, at
//   the individual-event level.
// - 'same-session-proximity' (probable): within the same CDP session, a storage write, a crypto
//   operation, or an outgoing network request soon after a message-received event, an earlier
//   storage event, or a crypto operation is plausibly its effect. This is a real heuristic, not
//   a proven trace -- it is never reported as 'exact', matching this project's own discipline of
//   never converting a correlation into a stronger claim than the evidence supports.

// How soon counts as "soon" for the same-session heuristic. Not a universal constant -- a
// documented, honest budget, same spirit as this file's siblings' own proximity windows
// (audit.js's ENTROPY_PROXIMITY_CHARS, MESSAGE_DISCRIMINANT_PROXIMITY_CHARS).
const SAME_SESSION_PROXIMITY_MS = 200;

function sameMessageContent(a, b) {
  try {
    return JSON.stringify(a) === JSON.stringify(b);
  } catch {
    return false;
  }
}

function buildMessagePairEdges(events) {
  const edges = [];
  const sent = events.filter((e) => e.kind === 'message' && e.direction === 'sent');
  const received = events.filter((e) => e.kind === 'message' && e.direction === 'received');
  const claimed = new Set();

  for (const s of sent) {
    const match = received.find(
      (r) => !claimed.has(r.seq) && r.seq > s.seq && sameMessageContent(r.message, s.message)
    );
    if (match) {
      claimed.add(match.seq);
      edges.push({ from: s.seq, to: match.seq, basis: 'message-pair', confidence: 'exact' });
    }
  }
  return edges;
}

// R15: a crypto op (digest/sign/verify/encrypt/decrypt) is a same-session-proximity trigger and
// effect too, same as storage already was -- a sign() call followed by a fetch() carrying its
// output is exactly the signing-mechanism shape this heuristic exists to surface, and a received
// message or storage read triggering a crypto op (sign the data you just got) is the same shape
// in the other direction.
function isProximityTrigger(e) {
  return (e.kind === 'message' && e.direction === 'received') || e.kind === 'storage' || e.kind === 'crypto';
}

function isProximityEffect(e) {
  return e.kind === 'storage' || e.kind === 'crypto' || (e.kind === 'network' && e.direction === 'request');
}

function buildSameSessionProximityEdges(events) {
  const edges = [];
  const bySession = new Map();
  for (const e of events) {
    if (!e.sessionId) continue;
    if (!bySession.has(e.sessionId)) bySession.set(e.sessionId, []);
    bySession.get(e.sessionId).push(e);
  }

  for (const sessionEvents of bySession.values()) {
    sessionEvents.sort((a, b) => a.seq - b.seq);
    for (let i = 0; i < sessionEvents.length; i++) {
      const trigger = sessionEvents[i];
      if (!isProximityTrigger(trigger)) continue;
      for (let j = i + 1; j < sessionEvents.length; j++) {
        const effect = sessionEvents[j];
        if (effect.ts - trigger.ts > SAME_SESSION_PROXIMITY_MS) break;
        if (effect.seq === trigger.seq) continue;
        if (isProximityEffect(effect)) {
          edges.push({ from: trigger.seq, to: effect.seq, basis: 'same-session-proximity', confidence: 'probable' });
        }
      }
    }
  }
  return edges;
}

/**
 * Builds the capture file's causal timeline edges from its already-captured events. Pure and
 * synchronous -- no Chrome, no I/O -- so every edge is reproducible from the events alone.
 */
export function buildCausalityEdges(events) {
  return [...buildMessagePairEdges(events), ...buildSameSessionProximityEdges(events)];
}
