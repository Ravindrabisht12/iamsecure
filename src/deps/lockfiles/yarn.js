import { DepGraph } from '../graph.js';
import { parseYaml } from '../../util/yaml.js';

const specName = (spec) => spec.slice(0, spec.indexOf('@', 1));

const unquote = (s) => (s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s);

/** Classic yarn.lock (v1) — its own non-YAML format. Returns Map<spec, entry>. */
function parseClassic(text) {
  const entries = new Map();
  let current = null;
  let section = null;
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (indent === 0 && line.endsWith(':')) {
      const specs = line.slice(0, -1).split(/,\s*/).map(unquote);
      current = { name: specName(specs[0]), version: null, dependencies: {}, optionalDependencies: {} };
      for (const s of specs) entries.set(s, current);
      section = null;
    } else if (current && indent <= 2) {
      const m = line.match(/^(\S+)\s+"?([^"]*)"?$/);
      if (line === 'dependencies:' || line === 'optionalDependencies:') section = current[line.slice(0, -1)];
      else {
        section = null;
        if (m && m[1] === 'version') current.version = m[2];
      }
    } else if (current && section) {
      const m = line.match(/^("(?:[^"\\]|\\.)*"|\S+)\s+("(?:[^"\\]|\\.)*"|\S+)$/);
      if (m) section[unquote(m[1])] = unquote(m[2]);
    }
  }
  return entries;
}

/** Yarn 2+ (berry) lockfile — YAML with "name@npm:range" keys. */
function parseBerry(text) {
  const doc = parseYaml(text);
  const entries = new Map();
  for (const [keyList, e] of Object.entries(doc)) {
    if (keyList === '__metadata' || typeof e !== 'object') continue;
    const resolution = e.resolution ?? keyList.split(/,\s*/)[0];
    const entry = {
      name: specName(resolution),
      version: e.version,
      local: resolution.includes('@workspace:'),
      dependencies: e.dependencies ?? {},
      optionalDependencies: e.optionalDependencies ?? {},
    };
    for (const s of keyList.split(/,\s*/)) entries.set(s, entry);
  }
  return entries;
}

/**
 * @param {string} text yarn.lock contents
 * @param {{dir:string, manifest:any}[]} manifests root + workspace package.json files — yarn.lock
 *   doesn't record which deps are dev, so roots come from the manifests.
 */
export function parseYarnLock(text, manifests) {
  const berry = /^__metadata:/m.test(text);
  const entries = berry ? parseBerry(text) : parseClassic(text);
  const g = new DepGraph('npm', 'yarn.lock');

  const lookup = (name, range) =>
    entries.get(`${name}@${range}`) ?? entries.get(`${name}@npm:${range}`) ?? null;

  const unique = new Set(entries.values());
  for (const e of unique) {
    if (!e.version) continue;
    e.key = e.local ? null : g.addNode(e.name, e.version);
  }
  for (const e of unique) {
    if (!e.key) continue;
    for (const [dep, range] of Object.entries({ ...e.optionalDependencies, ...e.dependencies })) {
      const target = lookup(dep, range);
      if (target?.key) g.addEdge(e.key, target.key);
    }
  }
  for (const { dir, manifest } of manifests) {
    const add = (deps, dev) => {
      for (const [name, range] of Object.entries(deps ?? {})) {
        const target = lookup(name, range) ?? [...unique].find((e) => e.name === name && e.key);
        if (target?.key) g.addRoot(name, target.key, { dev, workspace: dir });
      }
    };
    add(manifest.dependencies, false);
    add(manifest.optionalDependencies, false);
    add(manifest.devDependencies, true);
  }
  return g.annotate();
}
