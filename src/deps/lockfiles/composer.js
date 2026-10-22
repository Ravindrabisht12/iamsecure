import { DepGraph } from '../graph.js';

const isPlatform = (name) => name === 'php' || /^(ext|lib|composer)-/.test(name) || !name.includes('/');
const clean = (v) => String(v).replace(/^v(?=\d)/, '');

/** composer.lock (PHP). OSV ecosystem: Packagist. */
export function parseComposerLock(text, composerJson) {
  const lock = JSON.parse(text);
  const g = new DepGraph('Packagist', 'composer.lock');
  const byName = new Map();
  for (const p of [...(lock.packages ?? []), ...(lock['packages-dev'] ?? [])]) {
    byName.set(p.name.toLowerCase(), { key: g.addNode(p.name, clean(p.version)), pkg: p });
  }
  for (const { key, pkg } of byName.values()) {
    for (const dep of Object.keys(pkg.require ?? {})) {
      if (!isPlatform(dep)) g.addEdge(key, byName.get(dep.toLowerCase())?.key);
    }
  }
  for (const [field, dev] of [['require', false], ['require-dev', true]]) {
    for (const name of Object.keys(composerJson?.[field] ?? {})) {
      if (!isPlatform(name)) g.addRoot(name, byName.get(name.toLowerCase())?.key, { dev });
    }
  }
  // No composer.json? Treat packages nothing depends on as roots.
  if (!composerJson) {
    const depended = new Set([...g.nodes.values()].flatMap((n) => [...n.deps]));
    const devNames = new Set((lock['packages-dev'] ?? []).map((p) => p.name.toLowerCase()));
    for (const [name, { key }] of byName) if (!depended.has(key)) g.addRoot(name, key, { dev: devNames.has(name) });
  }
  return g.annotate();
}
