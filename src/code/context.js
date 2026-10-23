// Works out WHERE code runs (server, browser, build/test) and which packages each file imports.
// This is what lets a ReDoS in a browser-only package rank far below the same bug on the server.

import { builtinModules } from 'node:module';

const BUILTINS = new Set(builtinModules.flatMap((m) => [m, `node:${m}`]));

export const CONTEXT_LABEL = {
  server: 'runs on server',
  local: 'local process, no network listener',
  client: 'browser only',
  universal: 'server + browser',
  build: 'build/test only',
  unused: 'installed, not imported',
  unknown: 'usage unknown',
};

const TEST_RE = /(^|\/)(__tests__|__mocks__|tests?|e2e|cypress|playwright|stories|fixtures)\/|\.(test|spec|stories|cy|e2e)\.[cm]?[jt]sx?$/;
const BUILD_RE = /(^|\/)[^/]+\.config\.[cm]?[jt]s$|(^|\/)(scripts|tools|\.storybook|\.github|\.husky)\/|(^|\/)(gulpfile|gruntfile|Jakefile)\.[cm]?[jt]s$/i;
const SERVER_HINT_RE = /\bfrom\s+['"](?:node:)?(fs|child_process|net|crypto|server-only|@prisma\/client|pg|mysql2?|mongoose|redis|ioredis)['"]|require\(\s*['"](?:node:)?(fs|child_process|net)['"]\)|\bprocess\.env\.(?!NEXT_PUBLIC_|VITE_|REACT_APP_)\w+/;
const CLIENT_HINT_RE = /\b(useState|useEffect|useLayoutEffect|useReducer)\s*\(|\bwindow\.|\bdocument\.|\blocalStorage\b|from\s+['"]client-only['"]/;

/**
 * @param {string} rel  path relative to project root, forward slashes
 * @param {string} text file contents
 * @param {string} framework from detectFramework()
 * @returns {'server'|'client'|'universal'|'build'}
 */
export function classifyFile(rel, text, framework) {
  if (TEST_RE.test(rel) || BUILD_RE.test(rel)) return 'build';
  if (/\.(php|py)$/.test(rel)) return 'server';

  const head = text.slice(0, 400).replace(/^(\s|\/\/[^\n]*\n|\/\*[\s\S]*?\*\/)*/, '');
  if (/^['"]use client['"]/.test(head)) return 'client';
  if (/^['"]use server['"]/.test(head)) return 'server';
  if (/from\s+['"]server-only['"]/.test(text)) return 'server';
  if (/from\s+['"]client-only['"]/.test(text)) return 'client';
  if (/\.server\.[cm]?[jt]sx?$|(^|\/)\+(page|layout)\.server\.|(^|\/)\+server\.[jt]s$/.test(rel)) return 'server';
  if (/\.client\.[cm]?[jt]sx?$/.test(rel)) return 'client';

  const p = rel.replace(/^(apps|packages)\/[^/]+\//, '');
  switch (framework) {
    case 'next':
      if (/^(src\/)?pages\/api\//.test(p)) return 'server';
      if (/^(src\/)?(middleware|instrumentation)\.[jt]s$/.test(p) || /^server\.[cm]?[jt]s$/.test(p)) return 'server';
      if (/^(src\/)?app\//.test(p)) return 'server'; // React Server Components unless "use client"
      if (/^(src\/)?pages\//.test(p)) return 'universal';
      break;
    case 'nuxt':
    case 'sveltekit':
    case 'remix':
    case 'astro':
      if (/^(src\/)?(server|api)\//.test(p)) return 'server';
      break;
    case 'cra':
    case 'vite-spa':
    case 'spa':
      if (/^(server|api|backend|functions)\//.test(p)) return 'server';
      return 'client';
    case 'node-server':
    case 'node':
      return 'server';
  }
  const server = SERVER_HINT_RE.test(text);
  const client = CLIENT_HINT_RE.test(text);
  if (server && !client) return 'server';
  if (client && !server) return 'client';
  return 'universal';
}

const IMPORT_RE =
  /(?:\bimport\s+(?:type\s+)?(?:[\w*{}\s,$]+?\s+from\s+)?|\bexport\s+(?:type\s+)?(?:[\w*{}\s,$]+?\s+)?from\s+|\brequire\s*\(\s*|\bimport\s*\(\s*)['"]([^'"\n]+)['"]/g;

/** Package name for a bare import specifier, or null for relative/aliased/builtin imports. */
export function packageOf(spec) {
  if (/^[./~#]|^@\/|^[a-z]+:/i.test(spec) && !spec.startsWith('node:')) return null;
  if (BUILTINS.has(spec) || BUILTINS.has(spec.split('/')[0])) return null;
  const parts = spec.split('/');
  return spec.startsWith('@') ? (parts.length > 1 ? `${parts[0]}/${parts[1]}` : null) : parts[0];
}

/** @returns {{pkg:string, line:number, binding:string|null}[]} */
export function extractImports(text) {
  const out = [];
  for (const m of text.matchAll(IMPORT_RE)) {
    const pkg = packageOf(m[1]);
    if (!pkg) continue;
    const line = text.slice(0, m.index).split('\n').length;
    // Capture the local name: `import _ from 'lodash'`, `const jwt = require('jsonwebtoken')`, `import * as x`.
    const before = text.slice(Math.max(0, m.index - 80), m.index + m[0].length);
    const binding =
      m[0].match(/^import\s+(?:type\s+)?(?:\*\s+as\s+)?([\w$]+)[\s,]/)?.[1] ??
      before.match(/(?:const|let|var)\s+([\w$]+)\s*=\s*require\s*\(\s*['"][^'"]+['"]$/)?.[1] ??
      null;
    out.push({ pkg, spec: m[1], line, binding });
  }
  return out;
}

/** Packages a framework loads for you even if no file imports them. */
export function frameworkRuntime(framework) {
  const ssr = ['server', 'client'];
  const map = {
    next: { next: ssr, react: ssr, 'react-dom': ssr },
    nuxt: { nuxt: ssr, vue: ssr },
    remix: { '@remix-run/node': ['server'], '@remix-run/react': ssr, react: ssr, 'react-dom': ssr },
    sveltekit: { '@sveltejs/kit': ssr, svelte: ssr },
    astro: { astro: ['server'] },
    cra: { react: ['client'], 'react-dom': ['client'] },
    'vite-spa': { react: ['client'], 'react-dom': ['client'], vue: ['client'], svelte: ['client'] },
    spa: { react: ['client'], 'react-dom': ['client'], vue: ['client'] },
  };
  return map[framework] ?? {};
}

/** Merge a set of contexts into one exposure bucket. */
export function mergeContexts(set) {
  const s = new Set(set);
  if (s.has('universal') || (s.has('server') && s.has('client'))) return 'universal';
  if (s.has('server')) return 'server';
  if (s.has('client')) return 'client';
  if (s.has('build')) return 'build';
  return null;
}
