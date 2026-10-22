import { DepGraph } from '../graph.js';

/** package-lock.json / npm-shrinkwrap.json, lockfileVersion 1, 2 and 3. */
export function parseNpmLock(text, manifest, lockfile = 'package-lock.json') {
  const lock = JSON.parse(text);
  const pkgs = lock.packages ?? convertV1(lock, manifest);
  const g = new DepGraph('npm', lockfile);

  const isLocal = (p) => p !== '' && !p.includes('node_modules/');
  const nameOf = (p) => pkgs[p]?.name || p.slice(p.lastIndexOf('node_modules/') + 'node_modules/'.length);

  const realPath = (p) => {
    const guard = new Set();
    while (pkgs[p]?.link && !guard.has(p)) {
      guard.add(p);
      p = pkgs[p].resolved;
    }
    return pkgs[p] ? p : null;
  };

  // Node's resolution: look in ./node_modules, then each ancestor's node_modules.
  const resolve = (from, name) => {
    let base = from;
    for (;;) {
      const cand = (base ? base + '/' : '') + 'node_modules/' + name;
      if (pkgs[cand]) return realPath(cand);
      if (base === '') return null;
      const i = base.lastIndexOf('/node_modules/');
      base = i === -1 ? '' : base.slice(0, i);
    }
  };

  const keys = new Map();
  for (const [p, e] of Object.entries(pkgs)) {
    if (p === '' || e.link) continue;
    keys.set(p, isLocal(p) ? g.addNode(nameOf(p), 'workspace', { local: true }) : g.addNode(nameOf(p), e.version ?? '0.0.0'));
  }

  for (const [p, e] of Object.entries(pkgs)) {
    if (e.link) continue;
    const declared = { ...e.peerDependencies, ...e.optionalDependencies, ...e.dependencies };
    if (p === '' || isLocal(p)) {
      const addRoot = (name, dev) => {
        const target = resolve(p, name);
        if (target) g.addRoot(name, keys.get(target), { dev, workspace: p || '.' });
      };
      for (const name of Object.keys(declared)) addRoot(name, false);
      for (const name of Object.keys(e.devDependencies ?? {})) addRoot(name, true);
      continue;
    }
    for (const name of Object.keys(declared)) {
      const target = resolve(p, name);
      if (target && !isLocal(target)) g.addEdge(keys.get(p), keys.get(target));
    }
  }
  return g.annotate();
}

/** Lockfile v1 nests deps under "dependencies" with "requires"; reshape it into the v2 path map. */
function convertV1(lock, manifest) {
  const pkgs = {
    '': {
      dependencies: manifest?.dependencies,
      optionalDependencies: manifest?.optionalDependencies,
      devDependencies: manifest?.devDependencies,
    },
  };
  const walk = (deps, prefix) => {
    for (const [name, e] of Object.entries(deps ?? {})) {
      const p = (prefix ? prefix + '/' : '') + 'node_modules/' + name;
      pkgs[p] = { version: e.version, dependencies: e.requires };
      walk(e.dependencies, p);
    }
  };
  walk(lock.dependencies, '');
  return pkgs;
}
