import { readFileSync } from 'node:fs';
import path from 'node:path';
import { walkFiles, relPath } from './walk.js';

/**
 * Build an entry-point map and readability stats for an unpacked extension.
 */
export function buildEntryPointMap(dir, manifest) {
  const entryPoints = {
    background: null,
    popup: null,
    options: null,
    devtools: null,
    sidePanel: null,
    contentScripts: [],
    webAccessibleResources: manifest?.web_accessible_resources ?? [],
  };

  if (manifest?.background?.service_worker) {
    entryPoints.background = manifest.background.service_worker;
  } else if (manifest?.background?.scripts?.length) {
    entryPoints.background = manifest.background.scripts;
  }

  const popup =
    manifest?.action?.default_popup ??
    manifest?.browser_action?.default_popup ??
    manifest?.page_action?.default_popup ??
    null;
  if (popup) {
    entryPoints.popup = { html: popup, scripts: scriptsFromHtml(dir, popup) };
  }

  const options =
    manifest?.options_page ??
    manifest?.options_ui?.page ??
    null;
  if (options) {
    entryPoints.options = { html: options, scripts: scriptsFromHtml(dir, options) };
  }

  if (manifest?.devtools_page) {
    entryPoints.devtools = {
      html: manifest.devtools_page,
      scripts: scriptsFromHtml(dir, manifest.devtools_page),
    };
  }

  if (manifest?.side_panel?.default_path) {
    entryPoints.sidePanel = {
      html: manifest.side_panel.default_path,
      scripts: scriptsFromHtml(dir, manifest.side_panel.default_path),
    };
  }

  for (const cs of manifest?.content_scripts ?? []) {
    entryPoints.contentScripts.push({
      matches: cs.matches ?? [],
      js: cs.js ?? [],
      css: cs.css ?? [],
      runAt: cs.run_at ?? null,
    });
  }

  const jsFiles = walkFiles(dir, { extensions: ['.js'] });
  const readability = { total: jsFiles.length, minified: 0, readable: 0, files: [] };

  for (const file of jsFiles) {
    const rel = relPath(dir, file);
    const content = readFileSync(file, 'utf8');
    const minified = isMinified(content);
    if (minified) readability.minified++;
    else readability.readable++;
    readability.files.push({ file: rel, minified, lines: content.split('\n').length });
  }

  const startHere = buildStartHere(entryPoints, manifest);

  return { entryPoints, readability, startHere };
}

function scriptsFromHtml(dir, htmlPath) {
  try {
    const html = readFileSync(path.join(dir, htmlPath), 'utf8');
    const scripts = [];
    for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
      scripts.push(path.posix.normalize(path.join(path.posix.dirname(htmlPath), m[1])));
    }
    return scripts;
  } catch {
    return [];
  }
}

function isMinified(content) {
  const lines = content.split('\n');
  if (lines.length <= 3 && content.length > 500) return true;
  const avg = content.length / Math.max(lines.length, 1);
  return avg > 200;
}

function buildStartHere(entryPoints, manifest) {
  const paths = ['manifest.json'];

  const add = (p) => {
    if (!p) return;
    if (Array.isArray(p)) p.forEach(add);
    else if (!paths.includes(p)) paths.push(p);
  };

  add(entryPoints.background);
  add(entryPoints.popup?.html);
  add(entryPoints.popup?.scripts);
  add(entryPoints.options?.html);
  add(entryPoints.options?.scripts);
  for (const cs of entryPoints.contentScripts) {
    add(cs.js);
    add(cs.css);
  }

  if (manifest?.action?.default_icon || manifest?.icons) {
    // no-op; keep focus on code
  }

  return paths.slice(0, 12);
}
