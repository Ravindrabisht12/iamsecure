// Module-level reachability: follow the real import/require graph from your source files into node_modules
// and record which installed packages actually get loaded at runtime.
//
// A package can sit in the lockfile (pulled in by a dependency) without ever being loaded — e.g. an SDK
// that ships an optional Express-based HTTP transport you never import. This is what tells those apart.

import fs from 'node:fs';
import path from 'node:path';
import { builtinModules } from 'node:module';

const BUILTINS = new Set(builtinModules.flatMap((m) => [m, `node:${m}`]));
const EXTS = ['.js', '.cjs', '.mjs', '.json', '.node'];
const SRC_EXTS = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'];
const MAX_MODULES = 30000;
// Two passes per package: the CommonJS view and the ESM view. Browser/edge builds are never followed.
const CONDITION_SETS = [new Set(['node', 'require', 'default', 'module-sync']), new Set(['node', 'import', 'default', 'module-sync'])];

// Static imports, re-exports, require() and literal dynamic import(). `import type` / `export type` are skipped.
const SPEC_RE =
  /(?:\bimport\s+(type\s+)?(?:[\w*{}\s,$]+?\s+from\s+)?|\bexport\s+(type\s+)?(?:[\w*{}\s,$]+?\s+)?from\s+|\brequire\s*\(\s*|\bimport\s*\(\s*)(['"])([^'"\n]+)\3/g;

export function moduleSpecifiers(text) {
  const out = [];
  for (const m of text.matchAll(SPEC_RE)) if (!m[1] && !m[2]) out.push(m[4]);
  return out;
}

const statFile = (p) => {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
};

function readJson(p) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

/** Resolve a file path the way Node (and TS's `.js` → `.ts` mapping) would. */
function resolveFile(p, exts) {
  if (statFile(p)) return p;
  for (const e of exts) if (statFile(p + e)) return p + e;
  // TypeScript sources import "./x.js" meaning "./x.ts".
  const m = p.match(/\.(m|c)?js$/);
  if (m) for (const e of SRC_EXTS) if (statFile(p.slice(0, -m[0].length) + e)) return p.slice(0, -m[0].length) + e;
  for (const e of exts) if (statFile(path.join(p, 'index' + e))) return path.join(p, 'index' + e);
  return null;
}

/** Pick the target(s) of an `exports` condition object for one condition set. */
function pickConditions(target, conds) {
  if (typeof target === 'string') return [target];
  if (Array.isArray(target)) return target.flatMap((t) => pickConditions(t, conds)).slice(0, 1);
  if (target && typeof target === 'object') {
    for (const [k, v] of Object.entries(target)) if (conds.has(k)) return pickConditions(v, conds);
  }
  return [];
}

/** Map a subpath ("." or "./server/mcp.js") through package.json "exports". */
function resolveExports(exp, sub) {
  if (typeof exp === 'string' || Array.isArray(exp) || !Object.keys(exp).some((k) => k.startsWith('.'))) exp = { '.': exp };
  const out = new Set();
  for (const conds of CONDITION_SETS) {
    if (exp[sub] !== undefined) {
      pickConditions(exp[sub], conds).forEach((t) => out.add(t));
      continue;
    }
    // Longest matching "./prefix/*suffix" pattern wins.
    const pat = Object.keys(exp)
      .filter((k) => k.includes('*'))
      .map((k) => [k, ...k.split('*')])
      .filter(([, pre, post]) => sub.startsWith(pre) && sub.endsWith(post) && sub.length >= pre.length + post.length)
      .sort((a, b) => b[1].length - a[1].length)[0];
    if (pat) {
      const star = sub.slice(pat[1].length, sub.length - pat[2].length);
      pickConditions(exp[pat[0]], conds).forEach((t) => out.add(t.replaceAll('*', star)));
    }
  }
  return [...out];
}

/** All on-disk entry files a bare specifier can load, from a given directory. */
function resolveBare(spec, fromDir, pkgCache) {
  const parts = spec.split('/');
  const name = spec.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  const sub = spec.slice(name.length);
  for (let dir = fromDir; ; ) {
    const pkgDir = path.join(dir, 'node_modules', name);
    const manifest = pkgCache(pkgDir);
    if (manifest) {
      let targets;
      if (manifest.exports !== undefined) targets = resolveExports(manifest.exports, '.' + sub);
      else if (sub) targets = ['.' + sub];
      else targets = [manifest.main ?? 'index.js'];
      const files = targets.map((t) => resolveFile(path.join(pkgDir, t), EXTS)).filter(Boolean);
      return { pkgDir, files };
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/**
 * Walk from the project's runtime source files through every module they load.
 * @param {string} root project root
 * @param {{rel:string, context:string}[]} entries source files (build/test files are excluded by the caller)
 * @returns {{available: boolean, loaded: Map<string, {chain: string[]}>, installed: Set<string>, modules: number, truncated: boolean}}
 *   `loaded` is keyed by "name@version" of every package that gets loaded; `installed` holds every one on disk.
 */
export function walkModules(root, entries) {
  root = path.resolve(root);
  if (!fs.existsSync(path.join(root, 'node_modules'))) return { available: false, loaded: new Map(), installed: new Set(), modules: 0, truncated: false };

  const manifests = new Map();
  const pkgCache = (dir) => {
    if (!manifests.has(dir)) manifests.set(dir, readJson(path.join(dir, 'package.json')));
    return manifests.get(dir);
  };
  /** Nearest package root for a file inside node_modules. */
  const ownerOf = (file) => {
    const i = file.lastIndexOf(`${path.sep}node_modules${path.sep}`);
    if (i === -1) return null;
    const rest = file.slice(i + 14).split(path.sep);
    const dir = file.slice(0, i + 14) + (rest[0].startsWith('@') ? rest.slice(0, 2).join(path.sep) : rest[0]);
    const m = pkgCache(dir);
    return m?.name && m.version ? { dir, key: `${m.name}@${m.version}`, name: m.name } : null;
  };

  const parent = new Map(); // file → file that first loaded it (null for entries)
  const loaded = new Map();
  const queue = [];
  for (const e of entries) {
    const abs = path.join(root, e.rel);
    if (!parent.has(abs)) parent.set(abs, null), queue.push(abs);
  }

  const chainOf = (file) => {
    const files = [];
    for (let f = file; f; f = parent.get(f)) files.unshift(f);
    // Collapse to "your file that imports it → pkg → pkg …" for the report.
    const out = [];
    let lastSrc = files[0];
    for (const f of files) {
      const o = ownerOf(f);
      if (!o) lastSrc = f;
      else {
        if (!out.length) out.push(path.relative(root, lastSrc).split(path.sep).join('/'));
        if (out.at(-1) !== o.key) out.push(o.key);
      }
    }
    return out;
  };

  let truncated = false;
  for (let qi = 0; qi < queue.length; qi++) {
    if (qi >= MAX_MODULES) {
      truncated = true;
      break;
    }
    const file = queue[qi];
    const owner = ownerOf(file);
    if (owner && !loaded.has(owner.key)) loaded.set(owner.key, { chain: chainOf(file) });
    if (!/\.([cm]?[jt]sx?)$/.test(file)) continue;
    let text;
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    const dir = path.dirname(file);
    for (const spec of moduleSpecifiers(text)) {
      if (BUILTINS.has(spec) || BUILTINS.has(spec.split('/')[0]) || /^[a-z]+:/i.test(spec)) continue;
      let targets = [];
      if (spec.startsWith('.') || spec.startsWith('/')) {
        const t = resolveFile(path.resolve(dir, spec), owner ? EXTS : [...SRC_EXTS, '.json']);
        if (t) targets = [t];
      } else if (!/^[~#@]\//.test(spec)) {
        targets = resolveBare(spec, dir, pkgCache)?.files ?? [];
      }
      for (const t of targets) {
        if (parent.has(t)) continue;
        parent.set(t, file);
        queue.push(t);
      }
    }
  }
  return { available: true, loaded, installed: installedPackages(root), modules: Math.min(queue.length, MAX_MODULES), truncated };
}

/** Every "name@version" present on disk, nested copies included — so a stale node_modules isn't read as "never loaded". */
function installedPackages(root) {
  const out = new Set();
  const subdirs = (dir) => {
    try {
      return fs.readdirSync(dir, { withFileTypes: true }).filter((e) => e.isDirectory() && !e.name.startsWith('.')).map((e) => path.join(dir, e.name));
    } catch {
      return [];
    }
  };
  const visit = (nm) => {
    for (const entry of subdirs(nm)) {
      for (const dir of path.basename(entry).startsWith('@') ? subdirs(entry) : [entry]) {
        const m = readJson(path.join(dir, 'package.json'));
        if (m?.name && m.version) out.add(`${m.name}@${m.version}`);
        visit(path.join(dir, 'node_modules'));
      }
    }
  };
  visit(path.join(root, 'node_modules'));
  return out;
}
