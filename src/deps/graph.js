/**
 * Resolved dependency graph for one lockfile. Nodes are unique name@version pairs;
 * roots are the dependencies declared in package.json (or a workspace's package.json).
 */
export class DepGraph {
  constructor(ecosystem, lockfile) {
    this.ecosystem = ecosystem;
    this.lockfile = lockfile;
    /** @type {Map<string, {key:string,name:string,version:string,local:boolean,deps:Set<string>,prod?:boolean,direct?:boolean,parent?:string|null,depth?:number,reachedBy?:Set<string>}>} */
    this.nodes = new Map();
    /** @type {{name:string,key:string,dev:boolean,workspace:string}[]} */
    this.roots = [];
  }

  addNode(name, version, { local = false } = {}) {
    const key = `${name}@${version}`;
    if (!this.nodes.has(key)) this.nodes.set(key, { key, name, version, local, deps: new Set() });
    return key;
  }

  addEdge(from, to) {
    if (from && to && from !== to) this.nodes.get(from)?.deps.add(to);
  }

  addRoot(name, key, { dev = false, workspace = '.' } = {}) {
    if (key && this.nodes.has(key) && !this.nodes.get(key).local) this.roots.push({ name, key, dev, workspace });
  }

  /**
   * Walks from every root and records, per node: whether any production root reaches it,
   * which direct dependencies pull it in, and a shortest "why is this installed" parent pointer
   * (production chains win over dev chains).
   */
  annotate() {
    for (const n of this.nodes.values()) {
      n.prod = false;
      n.direct = false;
      n.parent = undefined;
      n.depth = Infinity;
      n.reachedBy = new Set();
    }
    const roots = [...this.roots].sort((a, b) => Number(a.dev) - Number(b.dev));
    for (const root of roots) {
      const start = this.nodes.get(root.key);
      start.direct = true;
      if (start.depth > 0 && !(root.dev && start.prod)) {
        start.parent = null;
        start.depth = 0;
      }
      const seen = new Set([root.key]);
      const queue = [root.key];
      for (let qi = 0; qi < queue.length; qi++) {
        const n = this.nodes.get(queue[qi]);
        n.reachedBy.add(root.name);
        if (!root.dev) n.prod = true;
        for (const childKey of n.deps) {
          if (seen.has(childKey)) continue;
          seen.add(childKey);
          const c = this.nodes.get(childKey);
          if (!c || c.local) continue;
          const better = c.parent === undefined || (n.depth + 1 < c.depth && !(root.dev && c.prod));
          if (better && c.depth !== 0) {
            c.parent = n.key;
            c.depth = n.depth + 1;
          }
          queue.push(childKey);
        }
      }
    }
    return this;
  }

  /** Chain of node keys from a direct dependency down to `key`. */
  pathTo(key) {
    const chain = [];
    const guard = new Set();
    for (let k = key; k && !guard.has(k); k = this.nodes.get(k)?.parent) {
      guard.add(k);
      chain.unshift(k);
    }
    return chain;
  }

  /** Nodes that should be checked against advisory databases. */
  packages() {
    return [...this.nodes.values()].filter((n) => !n.local && n.version && !/^(file|link|git|https?):/.test(n.version));
  }
}
