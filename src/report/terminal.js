import { sortFindings } from '../scan.js';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const wrap = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
export const c = {
  bold: wrap('1'),
  dim: wrap('2'),
  red: wrap('31'),
  green: wrap('32'),
  yellow: wrap('33'),
  blue: wrap('34'),
  magenta: wrap('35'),
  cyan: wrap('36'),
  bgRed: wrap('41;97;1'),
};

const LEVEL_STYLE = {
  critical: (s) => c.bgRed(s),
  high: (s) => c.red(c.bold(s)),
  medium: (s) => c.yellow(s),
  low: (s) => c.blue(s),
  none: (s) => c.dim(s),
};

const pad = (s, n) => String(s).padEnd(n);
const label = (level) => LEVEL_STYLE[level](pad(level.toUpperCase(), 8));
const pkgOf = (key) => key; // keys are already name@version

/**
 * @param {any} report
 * @param {{sort?: 'risk'|'severity', limit?: number, min?: string}} opts
 */
export function printReport(report, { sort = 'risk', limit = 30, min } = {}) {
  const out = [];
  const p = report.stats.packages;
  out.push('');
  out.push(
    `${c.bold('iamsecure')} ${c.dim('v' + report.tool.version)} — ${c.bold(report.project.name)} ${c.dim(`(${report.project.framework})`)}`,
  );
  const bits = [`${p.total} packages (${p.direct} direct, ${p.transitive} transitive)`];
  if (report.stats.files) bits.push(`${report.stats.files} source files`);
  bits.push(`${(report.durationMs / 1000).toFixed(1)}s`);
  out.push(c.dim(bits.join(' · ')));
  for (const w of report.warnings) out.push(c.yellow(`⚠ ${w}`));
  out.push('');

  if (!report.findings.length) {
    out.push(c.green('✔ No known vulnerabilities or insecure code patterns found.'));
    console.log(out.join('\n'));
    return;
  }

  const s = report.summary;
  out.push(c.dim('                 critical    high  medium     low'));
  const row = (name, counts) =>
    `  ${pad(name, 13)}  ${['critical', 'high', 'medium', 'low'].map((l) => LEVEL_STYLE[l](String(counts[l]).padStart(6))).join('  ')}`;
  out.push(row('by severity', s.bySeverity));
  out.push(row('by real risk', s.byRisk));
  out.push('');

  const order = ['critical', 'high', 'medium', 'low', 'none'];
  const field = sort === 'severity' ? 'severity' : 'risk';
  let list = sortFindings(report.findings, sort);
  if (min) list = list.filter((f) => order.indexOf(f[field]) <= order.indexOf(min));
  out.push(
    c.bold(sort === 'severity' ? 'Sorted by SEVERITY (CVSS, high → low)' : 'Sorted by REAL RISK in this codebase (worst first)') +
      c.dim(sort === 'severity' ? '   · --sort risk for contextual ranking' : '   · --sort severity for raw CVSS order'),
  );
  out.push('');

  for (const f of list.slice(0, limit)) out.push(...formatFinding(f, sort));
  if (list.length > limit) out.push(c.dim(`  … ${list.length - limit} more. Use --limit, --json, or --ui to see everything.`), '');
  console.log(out.join('\n'));
}

function formatFinding(f, sort) {
  const lines = [];
  const primary = sort === 'severity' ? f.severity : f.risk;
  const scores = `${c.dim('risk')} ${f.riskScore.toFixed(1)} ${c.dim('· sev')} ${f.severityScore.toFixed(1)}`;

  if (f.kind === 'dependency') {
    const pk = f.package;
    lines.push(` ${label(primary)} ${scores}  ${c.bold(`${pk.name}@${pk.version}`)} ${c.dim('—')} ${f.title}`);
    const tags = [f.advisory.id];
    if (f.advisory.malicious) tags.push(c.bgRed(' MALICIOUS PACKAGE '));
    if (f.exploit?.kev) tags.push(c.bgRed(' ACTIVELY EXPLOITED '));
    if (f.exposure) tags.push(f.exposure.label);
    tags.push(pk.direct ? 'direct' : 'transitive');
    if (!pk.prod) tags.push('dev-only');
    tags.push(pk.fixedIn ? c.green(`fix → ${pk.fixedIn}`) : c.yellow('no fix yet'));
    lines.push(`            ${c.dim(tags.join(' · '))}`);
    if (pk.path.length > 1) lines.push(`            ${c.dim('via')} ${pk.path.map(pkgOf).join(c.dim(' › '))}`);
  } else {
    const loc = f.location ? `${f.location.file}:${f.location.line}` : '';
    lines.push(` ${label(primary)} ${scores}  ${c.bold(f.title)} ${c.dim(loc)}`);
    const tags = [f.ruleId];
    if (f.exposure) tags.push(f.exposure.label);
    lines.push(`            ${c.dim(tags.join(' · '))}`);
    if (f.location?.snippet) lines.push(`            ${c.cyan(f.location.snippet.trim().slice(0, 140))}`);
  }
  for (const r of f.reasons ?? []) lines.push(`            ${c.dim('· ' + r)}`);
  if (f.ai) {
    lines.push(`            ${c.magenta(`AI (${f.ai.provider}): ${f.ai.verdict}`)}${c.dim(` — ${f.ai.reasoning}`)}`);
  }
  lines.push('');
  return lines;
}
