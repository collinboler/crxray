import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { readManifest, summarizeManifest } from './manifest.js';
import { walkFiles, relPath } from './walk.js';
import { collectEndpointsFromContent } from './audit.js';

/**
 * Diff two unpacked extension directories.
 */
export function diffExtensions(leftDir, rightDir) {
  const leftManifest = readManifest(leftDir);
  const rightManifest = readManifest(rightDir);
  const leftSummary = summarizeManifest(leftManifest);
  const rightSummary = summarizeManifest(rightManifest);

  const leftFiles = fileIndex(leftDir);
  const rightFiles = fileIndex(rightDir);

  const allPaths = new Set([...leftFiles.keys(), ...rightFiles.keys()]);
  const added = [];
  const removed = [];
  const modified = [];
  const unchanged = [];

  for (const rel of [...allPaths].sort()) {
    const left = leftFiles.get(rel);
    const right = rightFiles.get(rel);

    if (!left) {
      added.push(rel);
      continue;
    }
    if (!right) {
      removed.push(rel);
      continue;
    }
    if (left.hash === right.hash) unchanged.push(rel);
    else modified.push({ path: rel, leftSize: left.size, rightSize: right.size });
  }

  const permissionChanges = diffPermissions(leftSummary, rightSummary);
  const endpointChanges = diffEndpoints(leftDir, rightDir, modified.map((m) => m.path));

  return {
    left: { name: leftSummary?.name, version: leftSummary?.version, dir: leftDir },
    right: { name: rightSummary?.name, version: rightSummary?.version, dir: rightDir },
    files: { added, removed, modified, unchangedCount: unchanged.length },
    permissionChanges,
    endpointChanges,
  };
}

function fileIndex(dir) {
  const index = new Map();
  for (const file of walkFiles(dir)) {
    const rel = relPath(dir, file);
    const content = readFileSync(file);
    index.set(rel, {
      hash: createHash('sha256').update(content).digest('hex'),
      size: content.length,
    });
  }
  return index;
}

function diffPermissions(left, right) {
  const changes = { added: [], removed: [], hostAdded: [], hostRemoved: [] };
  if (!left || !right) return changes;

  const leftPerms = new Set([...left.permissions, ...left.optionalPermissions]);
  const rightPerms = new Set([...right.permissions, ...right.optionalPermissions]);
  const leftHost = new Set(left.hostPermissions);
  const rightHost = new Set(right.hostPermissions);

  for (const p of rightPerms) if (!leftPerms.has(p)) changes.added.push(p);
  for (const p of leftPerms) if (!rightPerms.has(p)) changes.removed.push(p);
  for (const h of rightHost) if (!leftHost.has(h)) changes.hostAdded.push(h);
  for (const h of leftHost) if (!rightHost.has(h)) changes.hostRemoved.push(h);

  return changes;
}

function diffEndpoints(leftDir, rightDir, modifiedPaths) {
  const jsModified = modifiedPaths.filter((p) => p.endsWith('.js'));
  const added = new Set();
  const removed = new Set();

  for (const rel of jsModified) {
    let leftContent = '';
    let rightContent = '';
    try {
      leftContent = readFileSync(path.join(leftDir, rel), 'utf8');
      rightContent = readFileSync(path.join(rightDir, rel), 'utf8');
    } catch {
      continue;
    }
    const leftEps = new Set(collectEndpointsFromContent(leftContent));
    const rightEps = new Set(collectEndpointsFromContent(rightContent));
    for (const ep of rightEps) if (!leftEps.has(ep)) added.add(ep);
    for (const ep of leftEps) if (!rightEps.has(ep)) removed.add(ep);
  }

  return { added: [...added].sort(), removed: [...removed].sort() };
}

export function formatDiffReport(diff) {
  const lines = [];
  lines.push(`Left:  ${diff.left.name ?? '?'} v${diff.left.version ?? '?'}`);
  lines.push(`Right: ${diff.right.name ?? '?'} v${diff.right.version ?? '?'}`);
  lines.push('');

  const pc = diff.permissionChanges;
  if (pc.added.length || pc.removed.length || pc.hostAdded.length || pc.hostRemoved.length) {
    lines.push('Permission changes');
    if (pc.added.length) lines.push(`  + ${pc.added.join(', ')}`);
    if (pc.removed.length) lines.push(`  - ${pc.removed.join(', ')}`);
    if (pc.hostAdded.length) lines.push(`  + host ${pc.hostAdded.join(', ')}`);
    if (pc.hostRemoved.length) lines.push(`  - host ${pc.hostRemoved.join(', ')}`);
    lines.push('');
  }

  lines.push('Files');
  lines.push(`  Added:     ${diff.files.added.length}`);
  lines.push(`  Removed:   ${diff.files.removed.length}`);
  lines.push(`  Modified:  ${diff.files.modified.length}`);
  lines.push(`  Unchanged: ${diff.files.unchangedCount}`);

  if (diff.files.added.length) {
    lines.push('');
    lines.push('Added files');
    for (const f of diff.files.added.slice(0, 20)) lines.push(`  + ${f}`);
  }
  if (diff.files.removed.length) {
    lines.push('');
    lines.push('Removed files');
    for (const f of diff.files.removed.slice(0, 20)) lines.push(`  - ${f}`);
  }
  if (diff.files.modified.length) {
    lines.push('');
    lines.push('Modified files');
    for (const f of diff.files.modified.slice(0, 20)) {
      lines.push(`  ~ ${f.path} (${f.leftSize} → ${f.rightSize} bytes)`);
    }
  }

  const ec = diff.endpointChanges;
  if (ec.added.length || ec.removed.length) {
    lines.push('');
    lines.push('Network endpoint changes (in modified JS)');
    for (const ep of ec.added.slice(0, 10)) lines.push(`  + ${ep}`);
    for (const ep of ec.removed.slice(0, 10)) lines.push(`  - ${ep}`);
  }

  return lines.join('\n');
}
