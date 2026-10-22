import fs from 'node:fs';
import path from 'node:path';

export function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

/** Expand package.json "workspaces" globs (supports "dir", "dir/*" and "dir/**"). */
export function findWorkspaces(root, manifest) {
  const patterns = Array.isArray(manifest?.workspaces) ? manifest.workspaces : (manifest?.workspaces?.packages ?? []);
  const dirs = new Set();
  for (const pattern of patterns) {
    if (pattern.startsWith('!')) continue;
    let current = [''];
    for (const seg of pattern.replace(/\/$/, '').split('/')) {
      const next = [];
      for (const base of current) {
        if (seg === '*' || seg === '**') {
          for (const d of safeReaddir(path.join(root, base))) {
            if (d.isDirectory() && d.name !== 'node_modules' && !d.name.startsWith('.')) next.push(path.join(base, d.name));
          }
        } else next.push(path.join(base, seg));
      }
      current = next;
    }
    for (const d of current) if (fs.existsSync(path.join(root, d, 'package.json'))) dirs.add(d);
  }
  return [...dirs].map((dir) => ({ dir, manifest: readJson(path.join(root, dir, 'package.json')) ?? {} }));
}

function safeReaddir(dir) {
  try {
    return fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

/** What kind of app is this? Drives how code is classified as browser vs server. */
export function detectFramework(deps) {
  const has = (n) => deps.has(n);
  if (has('next')) return 'next';
  if (has('nuxt')) return 'nuxt';
  if (has('@remix-run/react') || has('@remix-run/node')) return 'remix';
  if (has('@sveltejs/kit')) return 'sveltekit';
  if (has('astro')) return 'astro';
  if (has('react-scripts')) return 'cra';
  if (has('vite') && (has('react') || has('vue') || has('svelte'))) return 'vite-spa';
  if (['express', 'fastify', 'koa', '@nestjs/core', '@hapi/hapi', 'hono'].some(has)) return 'node-server';
  if (has('react') || has('vue')) return 'spa';
  return deps.size ? 'node' : 'unknown';
}

/** Non-JS projects: everything runs server-side, but name the stack for the report. */
function detectBackend(root) {
  const composer = readJson(path.join(root, 'composer.json'));
  if (composer) {
    const req = { ...composer.require, ...composer['require-dev'] };
    if (req['laravel/framework']) return 'laravel';
    if (Object.keys(req).some((n) => n.startsWith('symfony/'))) return 'symfony';
    return 'php';
  }
  let py = '';
  for (const f of ['pyproject.toml', 'requirements.txt', 'Pipfile']) {
    try {
      py += fs.readFileSync(path.join(root, f), 'utf8').toLowerCase();
    } catch {}
  }
  if (py) {
    if (/\bdjango\b/.test(py)) return 'django';
    if (/\bfastapi\b/.test(py)) return 'fastapi';
    if (/\bflask\b/.test(py)) return 'flask';
    return 'python';
  }
  return 'unknown';
}

export function loadProject(root) {
  root = path.resolve(root);
  const manifest = readJson(path.join(root, 'package.json'));
  const workspaces = manifest ? findWorkspaces(root, manifest) : [];
  const manifests = manifest ? [{ dir: '.', manifest }, ...workspaces] : [];
  const deps = new Set();
  for (const { manifest: m } of manifests) {
    for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const n of Object.keys(m[k] ?? {})) deps.add(n);
    }
  }
  let framework = detectFramework(deps);
  if (framework === 'unknown') framework = detectBackend(root);
  return {
    root,
    name: manifest?.name ?? readJson(path.join(root, 'composer.json'))?.name ?? path.basename(root),
    manifest,
    manifests,
    framework,
  };
}
