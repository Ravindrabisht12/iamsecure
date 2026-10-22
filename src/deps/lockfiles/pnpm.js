import { DepGraph } from '../graph.js';
import { parseYaml } from '../../util/yaml.js';

/** pnpm-lock.yaml, lockfile versions 5.x, 6.x and 9.x. */
export function parsePnpmLock(text) {
  const doc = parseYaml(text);
  const ver = parseFloat(doc.lockfileVersion) || 5;
  const section = (ver >= 9 ? doc.snapshots : doc.packages) ?? {};
  const g = new DepGraph('npm', 'pnpm-lock.yaml');

  // Turns a dependency reference ("18.2.0(react@18.2.0)", "/foo/1.0.0", "npm:bar@2.0.0") into a section key.
  const sectionKey = (name, ref) => {
    if (!ref || typeof ref !== 'string' || /^(link|file|workspace):/.test(ref)) return null;
    if (ver < 6 && ref.startsWith('/')) return ref;
    const alias = ref.replace(/^npm:/, '').replace(/^\//, '').match(/^(@?[^@(]+)@(.+)$/);
    const [n, v] = alias ? [alias[1], alias[2]] : [name, ref];
    if (ver >= 9) return `${n}@${v}`;
    if (ver >= 6) return `/${n}@${v}`;
    return `/${n}/${v}`;
  };

  const parseKey = (k) => {
    let s = k.replace(/^\//, '');
    if (ver < 6) {
      s = s.replace(/_.*$/, '');
      const i = s.lastIndexOf('/');
      return { name: s.slice(0, i), version: s.slice(i + 1) };
    }
    s = s.replace(/\(.*$/, '');
    const i = s.lastIndexOf('@');
    return { name: s.slice(0, i), version: s.slice(i + 1) };
  };

  const nodeKeys = new Map();
  for (const k of Object.keys(section)) {
    const { name, version } = parseKey(k);
    if (name && version) nodeKeys.set(k, g.addNode(name, version));
  }
  for (const [k, e] of Object.entries(section)) {
    if (!e || typeof e !== 'object') continue;
    for (const [dep, ref] of Object.entries({ ...e.optionalDependencies, ...e.dependencies })) {
      g.addEdge(nodeKeys.get(k), nodeKeys.get(sectionKey(dep, ref)));
    }
  }

  const importers = doc.importers ? Object.entries(doc.importers) : [['.', doc]];
  for (const [workspace, imp] of importers) {
    for (const type of ['dependencies', 'optionalDependencies', 'devDependencies']) {
      for (const [name, val] of Object.entries(imp?.[type] ?? {})) {
        const ref = typeof val === 'object' ? val.version : val;
        g.addRoot(name, nodeKeys.get(sectionKey(name, ref)), { dev: type === 'devDependencies', workspace });
      }
    }
  }
  return g.annotate();
}
