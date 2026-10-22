import { DepGraph } from '../graph.js';
import { parseToml } from '../../util/toml.js';

// PEP 503 normalisation so "PyYAML", "pyyaml" and "py_yaml" match.
const norm = (n) => String(n).toLowerCase().replace(/[-_.]+/g, '-');
const reqName = (spec) => norm(String(spec).trim().split(/[\s<>=!~;\[(@]/)[0]);

/** Direct dependency names from pyproject.toml: PEP 621 [project] and Poetry tables. */
export function pyprojectRoots(text) {
  if (!text) return null;
  let doc;
  try {
    doc = parseToml(text);
  } catch {
    return null;
  }
  const prod = new Set();
  const dev = new Set();
  for (const spec of doc.project?.dependencies ?? []) prod.add(reqName(spec));
  for (const list of Object.values(doc.project?.['optional-dependencies'] ?? {})) for (const s of list) dev.add(reqName(s));
  for (const list of Object.values(doc['dependency-groups'] ?? {})) for (const s of list) if (typeof s === 'string') dev.add(reqName(s));
  const poetry = doc.tool?.poetry ?? {};
  for (const n of Object.keys(poetry.dependencies ?? {})) if (n !== 'python') prod.add(norm(n));
  for (const n of Object.keys(poetry['dev-dependencies'] ?? {})) dev.add(norm(n));
  for (const grp of Object.values(poetry.group ?? {})) for (const n of Object.keys(grp.dependencies ?? {})) dev.add(norm(n));
  for (const s of doc.tool?.uv?.['dev-dependencies'] ?? []) dev.add(reqName(s));
  return { prod, dev };
}

function finish(g, byName, roots, depsOf) {
  for (const [name, key] of byName) for (const d of depsOf(name)) g.addEdge(key, byName.get(norm(d)));
  if (roots && (roots.prod.size || roots.dev.size)) {
    for (const n of roots.prod) g.addRoot(n, byName.get(n), { dev: false });
    for (const n of roots.dev) if (!roots.prod.has(n)) g.addRoot(n, byName.get(n), { dev: true });
  } else {
    const depended = new Set([...g.nodes.values()].flatMap((n) => [...n.deps]));
    for (const [name, key] of byName) if (!depended.has(key)) g.addRoot(name, key, { dev: false });
  }
  return g.annotate();
}

/** poetry.lock and uv.lock share the [[package]] layout. */
export function parseTomlLock(text, file, pyproject) {
  const doc = parseToml(text);
  const g = new DepGraph('PyPI', file);
  const byName = new Map();
  const pkgs = new Map();
  for (const p of doc.package ?? []) {
    if (p.source?.virtual || p.source?.editable) continue; // the project itself (uv)
    byName.set(norm(p.name), g.addNode(norm(p.name), p.version));
    pkgs.set(norm(p.name), p);
  }
  const depsOf = (name) => {
    const d = pkgs.get(name)?.dependencies;
    if (Array.isArray(d)) return d.map((x) => (typeof x === 'object' ? x.name : x));
    return Object.keys(d ?? {});
  };
  let roots = pyprojectRoots(pyproject);
  // uv records the project's own deps on its virtual/editable package entry.
  const self = (doc.package ?? []).find((p) => p.source?.virtual || p.source?.editable);
  if (self && !roots) {
    roots = { prod: new Set((self.dependencies ?? []).map((d) => norm(d.name))), dev: new Set() };
    for (const list of Object.values(self['dev-dependencies'] ?? {})) for (const d of list) roots.dev.add(norm(d.name));
  }
  return finish(g, byName, roots, depsOf);
}

/** Pipfile.lock: flat "default"/"develop" maps of pinned versions. */
export function parsePipfileLock(text) {
  const lock = JSON.parse(text);
  const g = new DepGraph('PyPI', 'Pipfile.lock');
  for (const [section, dev] of [['default', false], ['develop', true]]) {
    for (const [name, info] of Object.entries(lock[section] ?? {})) {
      const version = String(info.version ?? '').replace(/^==/, '');
      if (!version) continue;
      g.addRoot(norm(name), g.addNode(norm(name), version), { dev });
    }
  }
  return g.annotate();
}

/** requirements*.txt — only exact pins (==) can be checked. */
export function parseRequirements(files) {
  const g = new DepGraph('PyPI', files.map((f) => f.name).join(', '));
  let unpinned = 0;
  for (const { name: file, text } of files) {
    const dev = /dev|test|lint|doc/i.test(file);
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.replace(/\s#.*$/, '').trim();
      if (!line || line.startsWith('#') || line.startsWith('-')) continue;
      const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;,]+)/.exec(line);
      if (!m) {
        unpinned++;
        continue;
      }
      g.addRoot(norm(m[1]), g.addNode(norm(m[1]), m[2]), { dev });
    }
  }
  g.unpinned = unpinned;
  return g.annotate();
}
