import { readFileSync } from 'node:fs';
import path from 'node:path';
import { buildEntryPointMap } from './map.js';
import { walkFiles, relPath } from './walk.js';

const HIGH_RISK_PERMISSIONS = new Set([
  'webRequest',
  'webRequestBlocking',
  'cookies',
  'nativeMessaging',
  'debugger',
  'proxy',
  'management',
  'desktopCapture',
  'declarativeNetRequestWithHostAccess',
  'browsingData',
  'history',
  'clipboardRead',
  'geolocation',
  'downloads',
  'tabs',
]);

const MEDIUM_RISK_PERMISSIONS = new Set([
  'scripting',
  'activeTab',
  'notifications',
  'identity',
  'privacy',
  'sessions',
  'bookmarks',
]);

const SUSPICIOUS_PATTERNS = [
  { id: 'eval', label: 'eval()', re: /\beval\s*\(/g, severity: 'high' },
  { id: 'function-constructor', label: 'new Function()', re: /\bnew\s+Function\s*\(/g, severity: 'high' },
  { id: 'atob', label: 'atob() decoding', re: /\batob\s*\(/g, severity: 'medium' },
  { id: 'document-write', label: 'document.write()', re: /\bdocument\.write\s*\(/g, severity: 'medium' },
  { id: 'chrome-cookies', label: 'chrome.cookies access', re: /\bchrome\.cookies\b/g, severity: 'high' },
  { id: 'chrome-webRequest', label: 'chrome.webRequest access', re: /\bchrome\.webRequest\b/g, severity: 'high' },
  { id: 'send-beacon', label: 'navigator.sendBeacon()', re: /\bnavigator\.sendBeacon\s*\(/g, severity: 'medium' },
  { id: 'xhr', label: 'XMLHttpRequest', re: /\bnew\s+XMLHttpRequest\s*\(/g, severity: 'low' },
  { id: 'dynamic-import', label: 'dynamic import()', re: /\bimport\s*\(/g, severity: 'low' },
];

const URL_RE = /https?:\/\/[^\s"'`)]+/g;

export function collectEndpointsFromContent(content) {
  const endpoints = [];
  for (const url of content.match(URL_RE) ?? []) {
    const cleaned = url.replace(/[),.;]+$/, '');
    if (!cleaned.includes('mozilla.org') && !cleaned.includes('w3.org')) {
      endpoints.push(cleaned);
    }
  }
  return endpoints;
}

/**
 * Run a security-oriented audit on an unpacked extension directory.
 */
export function auditExtension(dir, manifest, summary) {
  const map = buildEntryPointMap(dir, manifest);
  const permissions = classifyPermissions(summary);
  const findings = scanSource(dir);
  const endpoints = collectEndpoints(dir);
  const risk = computeRisk(permissions, findings, summary);

  return {
    risk,
    permissions,
    findings,
    endpoints,
    entryPoints: map.entryPoints,
    readability: map.readability,
    startHere: map.startHere,
    version: summary?.version ?? null,
    name: summary?.name ?? null,
  };
}

function classifyPermissions(summary) {
  if (!summary) return { high: [], medium: [], low: [], hostAccess: [] };

  const all = [
    ...summary.permissions,
    ...summary.optionalPermissions,
    ...summary.hostPermissions,
  ];

  const high = [];
  const medium = [];
  const low = [];
  const hostAccess = [];

  for (const perm of all) {
    if (perm.includes('://') || perm === '<all_urls>' || perm.startsWith('*://')) {
      hostAccess.push(perm);
      if (perm === '<all_urls>' || perm === '*://*/*') high.push(perm);
      continue;
    }
    if (HIGH_RISK_PERMISSIONS.has(perm)) high.push(perm);
    else if (MEDIUM_RISK_PERMISSIONS.has(perm)) medium.push(perm);
    else low.push(perm);
  }

  return { high, medium, low, hostAccess };
}

function scanSource(dir) {
  const findings = [];
  const jsFiles = walkFiles(dir, { extensions: ['.js'] });

  for (const file of jsFiles) {
    const rel = relPath(dir, file);
    const content = readFileSync(file, 'utf8');
    const lines = content.split('\n');

    for (const pattern of SUSPICIOUS_PATTERNS) {
      pattern.re.lastIndex = 0;
      let match;
      while ((match = pattern.re.exec(content)) !== null) {
        const line = content.slice(0, match.index).split('\n').length;
        const snippet = lines[line - 1]?.trim().slice(0, 120) ?? '';
        findings.push({
          severity: pattern.severity,
          pattern: pattern.label,
          file: rel,
          line,
          snippet,
        });
        if (findings.length >= 200) return findings;
      }
    }
  }

  return findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

function collectEndpoints(dir) {
  const endpoints = new Set();
  const jsFiles = walkFiles(dir, { extensions: ['.js'] });

  for (const file of jsFiles) {
    const content = readFileSync(file, 'utf8');
    for (const url of collectEndpointsFromContent(content)) endpoints.add(url);
  }

  return [...endpoints].sort().slice(0, 100);
}

function computeRisk(permissions, findings, summary) {
  let score = 0;
  score += permissions.high.length * 3;
  score += permissions.medium.length * 1;
  score += findings.filter((f) => f.severity === 'high').length * 2;
  score += findings.filter((f) => f.severity === 'medium').length;

  const hasBroadHost =
    permissions.hostAccess.includes('<all_urls>') ||
    permissions.hostAccess.includes('*://*/*') ||
    summary?.permissions?.includes('<all_urls>');

  if (hasBroadHost) score += 5;

  let level = 'low';
  if (score >= 12) level = 'critical';
  else if (score >= 7) level = 'high';
  else if (score >= 3) level = 'medium';

  return { level, score, hasBroadHost };
}

function severityRank(severity) {
  return { high: 3, medium: 2, low: 1 }[severity] ?? 0;
}

export function formatAuditReport(audit) {
  const lines = [];
  const riskLabel = audit.risk.level.toUpperCase();

  lines.push(`${riskEmoji(audit.risk.level)}  ${riskLabel} RISK (score ${audit.risk.score})`);
  lines.push('');

  if (audit.name) {
    lines.push(`  ${audit.name}${audit.version ? ` v${audit.version}` : ''}`);
    lines.push('');
  }

  if (audit.permissions.high.length || audit.permissions.hostAccess.length) {
    lines.push('Permissions & access');
    if (audit.permissions.high.length) lines.push(`  High: ${audit.permissions.high.join(', ')}`);
    if (audit.permissions.medium.length) lines.push(`  Medium: ${audit.permissions.medium.join(', ')}`);
    if (audit.permissions.hostAccess.length) lines.push(`  Host: ${audit.permissions.hostAccess.join(', ')}`);
    lines.push('');
  }

  if (audit.findings.length) {
    lines.push('Suspicious patterns');
    for (const f of audit.findings.slice(0, 15)) {
      lines.push(`  ${f.file}:${f.line}  ${f.pattern}`);
      if (f.snippet) lines.push(`    ${f.snippet}`);
    }
    if (audit.findings.length > 15) {
      lines.push(`  ... and ${audit.findings.length - 15} more`);
    }
    lines.push('');
  }

  if (audit.endpoints.length) {
    lines.push(`Network endpoints (${audit.endpoints.length})`);
    for (const ep of audit.endpoints.slice(0, 10)) lines.push(`  ${ep}`);
    if (audit.endpoints.length > 10) lines.push(`  ... and ${audit.endpoints.length - 10} more`);
    lines.push('');
  }

  lines.push('Start here');
  for (const p of audit.startHere) lines.push(`  ${p}`);

  lines.push('');
  lines.push(
    `Readability: ${audit.readability.readable} readable, ${audit.readability.minified} minified JS files`
  );

  return lines.join('\n');
}

function riskEmoji(level) {
  return { critical: '🔴', high: '⚠️', medium: '🟡', low: '🟢' }[level] ?? '⚪';
}
