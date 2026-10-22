import fs from 'node:fs';
import path from 'node:path';

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', '.next', '.nuxt', '.output', '.svelte-kit', '.vercel', '.netlify', '.turbo',
  '.cache', '.parcel-cache', '.idea', '.vscode', 'dist', 'build', 'out', 'coverage', 'storybook-static', 'vendor',
  '__pycache__', '.venv', 'venv', '.tox', '.mypy_cache', '.pytest_cache', 'bower_components', '.yarn', '.pnpm-store',
  '.iamsecure',
]);

export const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '.astro', '.php', '.py']);
const CONFIG_EXT = new Set(['.json', '.yml', '.yaml', '.toml', '.ini', '.properties', '.sh', '.tf', '.xml', '.conf', '.cfg']);
const MAX_SIZE = 1024 * 1024;
const MAX_FILES = 25000;

/** Very small .gitignore support: plain names, dir/ names, and simple * globs. */
function loadIgnore(root) {
  let lines = [];
  try {
    lines = fs.readFileSync(path.join(root, '.gitignore'), 'utf8').split(/\r?\n/);
  } catch {}
  const rules = lines
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#') && !l.startsWith('!'))
    .map((l) => {
      const anchored = l.startsWith('/');
      const p = l.replace(/^\//, '').replace(/\/$/, '');
      const re = new RegExp('^' + p.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '.*').replace(/(?<!\.)\*/g, '[^/]*') + '$');
      return { re, anchored, hasSlash: p.includes('/') };
    });
  return (rel) => {
    const base = path.basename(rel);
    return rules.some((r) => (r.anchored || r.hasSlash ? r.re.test(rel) : r.re.test(base)));
  };
}

/**
 * Walk the project and return files worth scanning.
 * .env files are always returned (even if gitignored) so secrets in them can be reported.
 * @returns {{rel:string, abs:string, ext:string, kind:'code'|'config'|'env'}[]}
 */
export function walkFiles(root) {
  const ignored = loadIgnore(root);
  const out = [];
  const stack = [''];
  while (stack.length && out.length < MAX_FILES) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(path.join(root, dir), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const rel = dir ? `${dir}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && !ignored(rel)) stack.push(rel);
        continue;
      }
      if (!e.isFile()) continue;
      const isEnv = /^\.env(\..+)?$/.test(e.name) && !/\.(example|sample|template|dist)$/.test(e.name);
      const ext = path.extname(e.name).toLowerCase();
      if (!isEnv && ignored(rel)) continue;
      if (!isEnv && !CODE_EXT.has(ext) && !CONFIG_EXT.has(ext)) continue;
      if (/\.min\.[cm]?js$|\.bundle\.js$|-lock\.json$|\.lock$|\.map$/.test(e.name) || e.name === 'package-lock.json') continue;
      out.push({ rel, abs: path.join(root, rel), ext, kind: isEnv ? 'env' : CODE_EXT.has(ext) ? 'code' : 'config' });
    }
  }
  return out;
}

/** Read a text file, or null if it's too big / binary / generated. */
export function readText(abs) {
  try {
    if (fs.statSync(abs).size > MAX_SIZE) return null;
    const text = fs.readFileSync(abs, 'utf8');
    if (text.includes('\u0000')) return null;
    // Bundled/minified output: a handful of extremely long lines.
    const lines = text.split('\n');
    if (lines.length < 5 && text.length > 5000) return null;
    return text;
  } catch {
    return null;
  }
}
