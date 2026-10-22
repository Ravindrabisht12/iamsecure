import fs from 'node:fs';
import path from 'node:path';
import { parseNpmLock } from './lockfiles/npm.js';
import { parseYarnLock } from './lockfiles/yarn.js';
import { parsePnpmLock } from './lockfiles/pnpm.js';
import { parseComposerLock } from './lockfiles/composer.js';
import { parseTomlLock, parsePipfileLock, parseRequirements } from './lockfiles/python.js';
import { readJson } from '../project.js';
import { queryOsv, normalizeVuln, pkgId } from './osv.js';

const JS_LOCKFILES = [
  ['package-lock.json', (t, p) => parseNpmLock(t, p.manifest, 'package-lock.json')],
  ['npm-shrinkwrap.json', (t, p) => parseNpmLock(t, p.manifest, 'npm-shrinkwrap.json')],
  ['pnpm-lock.yaml', (t) => parsePnpmLock(t)],
  ['yarn.lock', (t, p) => parseYarnLock(t, p.manifests)],
  // npm ≥7 keeps a copy of the resolved tree here even when package-lock.json isn't committed.
  ['node_modules/.package-lock.json', (t, p) => parseNpmLock(t, p.manifest, 'node_modules/.package-lock.json')],
];

/** Find and parse the lockfile(s) of a project into dependency graphs. */
export function loadGraphs(project) {
  const graphs = [];
  const warnings = [];

  if (project.manifest) {
    const found = JS_LOCKFILES.filter(([f]) => fs.existsSync(path.join(project.root, f)));
    if (!found.length) {
      warnings.push(
        'package.json found but no lockfile — the full dependency tree can\'t be resolved. Run `npm install --package-lock-only` (or your package manager\'s equivalent) and scan again.',
      );
    } else {
      const [file, parse] = found[0];
      if (found.length > 1 && !found[1][0].startsWith('node_modules')) {
        warnings.push(`Multiple lockfiles found (${found.map((f) => f[0]).join(', ')}); using ${file}.`);
      }
      try {
        graphs.push(parse(fs.readFileSync(path.join(project.root, file), 'utf8'), project));
      } catch (err) {
        warnings.push(`Could not parse ${file}: ${err.message}`);
      }
    }
  }
  const read = (f) => fs.readFileSync(path.join(project.root, f), 'utf8');
  const exists = (f) => fs.existsSync(path.join(project.root, f));
  const tryParse = (file, fn) => {
    try {
      graphs.push(fn());
    } catch (err) {
      warnings.push(`Could not parse ${file}: ${err.message}`);
    }
  };

  // PHP
  if (exists('composer.lock')) {
    tryParse('composer.lock', () => parseComposerLock(read('composer.lock'), readJson(path.join(project.root, 'composer.json'))));
  } else if (exists('composer.json')) {
    warnings.push('composer.json found but no composer.lock — run `composer update --lock` so exact versions can be checked.');
  }

  // Python: prefer a real lockfile, fall back to pinned requirements files.
  const pyproject = exists('pyproject.toml') ? read('pyproject.toml') : null;
  const pyLock = ['uv.lock', 'poetry.lock'].find(exists);
  if (pyLock) tryParse(pyLock, () => parseTomlLock(read(pyLock), pyLock, pyproject));
  else if (exists('Pipfile.lock')) tryParse('Pipfile.lock', () => parsePipfileLock(read('Pipfile.lock')));
  else {
    const reqFiles = fs.readdirSync(project.root).filter((f) => /^requirements([._-].*)?\.(txt|in)$/i.test(f) && !f.endsWith('.in'));
    if (reqFiles.length) {
      tryParse(reqFiles.join(', '), () => {
        const g = parseRequirements(reqFiles.map((name) => ({ name, text: read(name) })));
        if (g.unpinned) warnings.push(`${g.unpinned} Python requirement(s) aren't pinned with == and were skipped — pin them or use a lockfile (uv/poetry/pip-tools).`);
        return g;
      });
    } else if (pyproject) {
      warnings.push('pyproject.toml found but no uv.lock / poetry.lock / pinned requirements — Python dependencies were not checked.');
    }
  }

  return { graphs, warnings };
}

/** Check every package in every graph against OSV and turn hits into findings. */
export async function scanDependencies(graphs, { onProgress } = {}) {
  const all = graphs.flatMap((g) => g.packages().map((n) => ({ node: n, graph: g, ecosystem: g.ecosystem })));
  const unique = new Map(all.map((p) => [pkgId({ ...p.node, ecosystem: p.ecosystem }), { name: p.node.name, version: p.node.version, ecosystem: p.ecosystem }]));
  const vulnsByPkg = await queryOsv([...unique.values()], { onProgress });

  const findings = [];
  for (const { node, graph, ecosystem } of all) {
    const records = vulnsByPkg.get(pkgId({ ...node, ecosystem }));
    if (!records) continue;
    const seen = new Set();
    for (const rec of records) {
      // OSV can return the same issue under several ids (GHSA + PYSEC, …) — keep one.
      if ([rec.id, ...(rec.aliases ?? [])].some((id) => seen.has(id))) continue;
      seen.add(rec.id);
      for (const a of rec.aliases ?? []) seen.add(a);

      const adv = normalizeVuln(rec, { name: node.name, version: node.version, ecosystem });
      const chain = graph.pathTo(node.key);
      findings.push({
        id: `dep:${ecosystem}:${node.key}:${adv.id}`,
        kind: 'dependency',
        title: adv.summary,
        ruleId: adv.id,
        severity: adv.severity,
        severityScore: adv.severityScore,
        package: {
          name: node.name,
          version: node.version,
          ecosystem,
          lockfile: graph.lockfile,
          direct: !!node.direct,
          prod: !!node.prod,
          path: chain,
          introducedBy: [...(node.reachedBy ?? [])],
          fixedIn: adv.fixedIn,
        },
        advisory: adv,
        fix: fixText(node, adv, chain),
      });
    }
  }
  return findings;
}

function fixText(node, adv, chain) {
  if (adv.malicious) return `Remove ${node.name} immediately, rotate any credentials on machines that installed it, and audit for compromise.`;
  if (!adv.fixedIn) return `No patched version published. Consider replacing ${node.name} or mitigating in code.`;
  if (node.direct || chain.length <= 1) return `Upgrade ${node.name} to ${adv.fixedIn} or later.`;
  const top = chain[0].slice(0, chain[0].lastIndexOf('@'));
  return `Upgrade ${node.name} to ${adv.fixedIn}+ — it comes in via ${top}; update ${top}, or force the version with "overrides" (npm) / "resolutions" (yarn) / "pnpm.overrides".`;
}

export function treeStats(graphs) {
  let total = 0, direct = 0, dev = 0;
  for (const g of graphs) {
    for (const n of g.packages()) {
      total++;
      if (n.direct) direct++;
      if (!n.prod) dev++;
    }
  }
  return { total, direct, transitive: total - direct, devOnly: dev };
}
