import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';

/**
 * Read manifest.json from an unpacked extension directory, resolving
 * __MSG_*__ i18n placeholders in name/description from _locales.
 */
export function readManifest(dir) {
  const manifestPath = path.join(dir, 'manifest.json');
  if (!existsSync(manifestPath)) return null;

  // Some manifests ship with a UTF-8 BOM.
  const raw = readFileSync(manifestPath, 'utf8').replace(/^\uFEFF/, '');
  const manifest = JSON.parse(raw);

  for (const key of ['name', 'description', 'short_name']) {
    if (typeof manifest[key] === 'string') {
      manifest[key] = resolveMessage(dir, manifest, manifest[key]);
    }
  }
  return manifest;
}

function resolveMessage(dir, manifest, value) {
  const m = value.match(/^__MSG_(.+)__$/);
  if (!m) return value;

  const msgName = m[1];
  const locales = [manifest.default_locale, 'en', 'en_US', 'en_GB'].filter(Boolean);
  for (const locale of locales) {
    const file = path.join(dir, '_locales', locale, 'messages.json');
    if (!existsSync(file)) continue;
    try {
      const messages = JSON.parse(readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
      // Message keys are case-insensitive per the chrome.i18n spec.
      const key = Object.keys(messages).find((k) => k.toLowerCase() === msgName.toLowerCase());
      if (key && messages[key]?.message) return messages[key].message;
    } catch {
      // fall through to the next locale
    }
  }
  return value;
}

/**
 * Build a flat, audit-oriented summary from a manifest.
 */
export function summarizeManifest(manifest) {
  if (!manifest) return null;
  return {
    name: manifest.name ?? null,
    version: manifest.version ?? null,
    manifestVersion: manifest.manifest_version ?? null,
    description: manifest.description ?? null,
    permissions: manifest.permissions ?? [],
    optionalPermissions: manifest.optional_permissions ?? [],
    hostPermissions: manifest.host_permissions ?? [],
    contentScripts: (manifest.content_scripts ?? []).map((cs) => ({
      matches: cs.matches ?? [],
      js: cs.js ?? [],
    })),
    background:
      manifest.background?.service_worker ??
      manifest.background?.scripts?.join(', ') ??
      null,
  };
}
