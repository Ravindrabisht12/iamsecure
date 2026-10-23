import { loadProject } from "./project.js";
import { loadGraphs, scanDependencies, treeStats } from "./deps/index.js";
import { LEVELS } from "./deps/cvss.js";
import { analyzeSource } from "./code/index.js";
import { scanCode } from "./code/engine.js";
import { scanSecrets } from "./code/secrets.js";
import { loadExploitData } from "./risk/exploit.js";
import { scoreFindings } from "./risk/score.js";

export const VERSION = "0.1.2";

/**
 * Run a full scan and return a JSON-serialisable report.
 * @param {string} root
 * @param {{deps?: boolean, code?: boolean, exploit?: boolean, log?: (msg:string)=>void}} [opts]
 */
export async function scan(root, opts = {}) {
  const { deps = true, code = true, exploit = true, log = () => {} } = opts;
  const started = Date.now();
  const project = loadProject(root);
  const warnings = [];
  const findings = [];

  log(`Resolving dependency tree…`);
  const { graphs, warnings: depWarnings } = loadGraphs(project);
  warnings.push(...depWarnings);
  const stats = { packages: treeStats(graphs) };

  if (deps && graphs.length) {
    log(`Checking ${stats.packages.total} packages against OSV.dev…`);
    try {
      findings.push(...(await scanDependencies(graphs)));
    } catch (err) {
      warnings.push(`Vulnerability lookup failed: ${err.message}`);
    }
  }

  let src = null;
  if (code) {
    log("Analysing source code…");
    src = analyzeSource(project);
    stats.files = src.contexts.size;
    findings.push(...scanCode(src), ...scanSecrets(src, project.root));
  }

  let exploitData;
  const cves = [...new Set(findings.flatMap((f) => (f.advisory ? [f.advisory.id, ...f.advisory.aliases] : [])).filter((id) => id.startsWith("CVE-")))];
  if (exploit && cves.length) {
    log(`Checking ${cves.length} CVEs against CISA KEV + EPSS…`);
    exploitData = await loadExploitData(cves);
    warnings.push(...exploitData.warnings);
  }

  scoreFindings(findings, { src, framework: project.framework, exploit: exploitData });

  return {
    tool: { name: "iamsecure", version: VERSION },
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    project: { name: project.name, root: project.root, framework: project.framework },
    sourceFiles: src ? [...src.contexts].slice(0, 400).map(([file, context]) => ({ file, context })) : [],
    stats,
    warnings,
    summary: summarize(findings),
    findings: sortFindings(findings, "risk"),
    tree: graphs.map(serializeGraph),
  };
}

export function sortFindings(findings, by = "risk") {
  const primary = by === "severity" ? "severityScore" : "riskScore";
  const secondary = by === "severity" ? "riskScore" : "severityScore";
  return [...findings].sort((a, b) => b[primary] - a[primary] || b[secondary] - a[secondary] || a.title.localeCompare(b.title));
}

export function summarize(findings) {
  const count = (field) => Object.fromEntries(LEVELS.slice(0, 4).map((l) => [l, findings.filter((f) => f[field] === l).length]));
  return { total: findings.length, bySeverity: count("severity"), byRisk: count("risk") };
}

/** Compact tree for the dashboard: direct deps and the vulnerable packages beneath them. */
function serializeGraph(g) {
  return {
    ecosystem: g.ecosystem,
    lockfile: g.lockfile,
    roots: g.roots.map((r) => ({ name: r.name, key: r.key, dev: r.dev, workspace: r.workspace })),
    nodes: Object.fromEntries([...g.nodes.values()].filter((n) => !n.local).map((n) => [n.key, { deps: [...n.deps], prod: !!n.prod }])),
  };
}
