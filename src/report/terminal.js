import os from 'node:os';
import { sortFindings } from '../scan.js';

const useColor = (process.stdout.isTTY || !!process.env.FORCE_COLOR) && !process.env.NO_COLOR;
const wrapAnsi = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
export const c = {
  bold: wrapAnsi('1'),
  dim: wrapAnsi('2'),
  italic: wrapAnsi('3'),
  red: wrapAnsi('31'),
  green: wrapAnsi('32'),
  yellow: wrapAnsi('33'),
  blue: wrapAnsi('34'),
  magenta: wrapAnsi('35'),
  cyan: wrapAnsi('36'),
  gray: wrapAnsi('90'),
  orange: wrapAnsi('38;5;208'),
  bgRed: wrapAnsi('41;97;1'),
};

const LEVELS = ['critical', 'high', 'medium', 'low'];
const TONE = {
  critical: (s) => c.red(c.bold(s)),
  high: c.orange,
  medium: c.yellow,
  low: c.blue,
  ok: c.green,
  none: c.gray,
  muted: c.gray,
};
const dot = (tone) => TONE[tone]('●');
const EXPOSURE_TONE = { server: 'critical', universal: 'critical', client: 'medium', build: 'low', unused: 'muted', unknown: 'muted' };
const EXPOSURE_WORD = { server: 'server', universal: 'server + browser', client: 'browser only', build: 'build/test only', unused: 'not imported', unknown: 'unknown' };
const KIND_WORD = { dependency: 'Dependency', code: 'Code', secret: 'Secret' };

// ── layout helpers (ANSI-aware) ──────────────────────────────────────────────
const ANSI = /\x1b\[[0-9;]*m/g;
const vlen = (s) => String(s).replace(ANSI, '').length;
const pad = (s, n) => s + ' '.repeat(Math.max(0, n - vlen(s)));
const center = (s, n) => {
  const left = Math.floor((n - vlen(s)) / 2);
  return pad(' '.repeat(Math.max(0, left)) + s, n);
};

/** Word-wrap plain text to `width`, hard-breaking words that don't fit. */
function wrap(text, width) {
  const out = [];
  for (const para of String(text).split('\n')) {
    let line = '';
    for (let word of para.split(/\s+/).filter(Boolean)) {
      while (word.length > width) {
        if (line) out.push(line), (line = '');
        out.push(word.slice(0, width));
        word = word.slice(width);
      }
      if (!line) line = word;
      else if (line.length + 1 + word.length <= width) line += ' ' + word;
      else out.push(line), (line = word);
    }
    out.push(line);
  }
  return out;
}

/** Wrap, then style every line (styles must not span lines). */
const block = (text, width, style = (s) => s, firstPrefix = '', restPrefix = firstPrefix) =>
  wrap(text, width - vlen(firstPrefix)).map((l, i) => (i ? restPrefix : firstPrefix) + style(l));

const ellipsisStart = (s, n) => (s.length <= n ? s : '…' + s.slice(-(n - 1)));
const ellipsisEnd = (s, n) => (s.length <= n ? s : s.slice(0, n - 1) + '…');

/** Lay two columns side by side; falls back to stacked when the terminal is narrow. */
function columns(left, right, leftWidth, total, indent = '  ') {
  if (total < 88) return [...left.map((l) => indent + l), ...right.map((r) => indent + '  ' + r)];
  const rows = Math.max(left.length, right.length);
  const out = [];
  for (let i = 0; i < rows; i++) out.push(indent + pad(left[i] ?? '', leftWidth) + '   ' + (right[i] ?? ''));
  return out;
}

// ── sections ─────────────────────────────────────────────────────────────────
function counters(summary) {
  const top = [];
  const mid = [];
  const lab = [];
  const bot = [];
  for (const l of LEVELS) {
    const n = summary.byRisk[l];
    const tone = n ? l : 'muted';
    top.push(c.gray('╭──────────╮'));
    mid.push(c.gray('│') + center(`${dot(tone)} ${n ? c.bold(n) : c.gray(n)}`, 10) + c.gray('│'));
    lab.push(c.gray('│') + center(n ? c.bold(l.toUpperCase()) : c.gray(l.toUpperCase()), 10) + c.gray('│'));
    bot.push(c.gray('╰──────────╯'));
  }
  return [top, mid, lab, bot].map((r) => '  ' + r.join(' '));
}

function overall(summary) {
  const r = summary.byRisk;
  if (r.critical) return { tone: 'critical', icon: '✖', label: 'ACTION REQUIRED', detail: `${r.critical} critical` };
  if (r.high) return { tone: 'high', icon: '▲', label: 'ATTENTION', detail: `${r.high} high` };
  if (summary.total) return { tone: 'medium', icon: '●', label: 'MONITOR', detail: 'minor issues' };
  return { tone: 'ok', icon: '✔', label: 'ALL CLEAR', detail: 'no issues' };
}

function groupLine(name, list) {
  if (!list.length) return `${dot('ok')} ${c.bold(name)} – ${c.green('Clear')}`;
  const worst = LEVELS.find((l) => list.some((f) => f.risk === l)) ?? 'muted';
  const counts = LEVELS.map((l) => [l, list.filter((f) => f.risk === l).length]).filter(([, n]) => n);
  return `${dot(worst)} ${c.bold(name)} – ${counts.map(([l, n]) => `${n} ${l}`).join(', ')}`;
}

const TRIO = [11, 8, 10, 6];

function latestPanel(report, width) {
  const s = report.summary;
  const p = report.stats.packages;
  const st = overall(s);
  const leftW = 36;
  const rightW = width < 88 ? width - 6 : width - leftW - 8;
  const bar = c.gray('┃ ');

  const left = [
    `${TONE[st.tone](st.icon)} ${c.bold(st.label)} ${c.gray('–')} ${st.detail}`,
    c.gray(new Date(report.scannedAt).toLocaleString() + ` · ${(report.durationMs / 1000).toFixed(1)}s`),
    '',
    LEVELS.map((l, i) => pad(c.gray(l[0].toUpperCase() + l.slice(1) + ':'), TRIO[i])).join(''),
    LEVELS.map((l, i) => pad(`${dot(s.byRisk[l] ? l : 'muted')} ${s.byRisk[l]}`, TRIO[i])).join(''),
    c.gray(`by raw severity: ${LEVELS.map((l) => s.bySeverity[l]).join(' · ')}`),
  ];

  const kinds = { dependency: [], code: [], secret: [] };
  for (const f of report.findings) kinds[f.kind].push(f);
  const prose =
    `Scanned ${p.total} packages (${p.direct} direct, ${p.transitive} transitive)` +
    (report.stats.files != null ? ` and ${report.stats.files} source files` : '') +
    `. Found ${s.total} issue${s.total === 1 ? '' : 's'}: ${kinds.dependency.length} in dependencies, ${kinds.code.length} in your code, ${kinds.secret.length} secret${kinds.secret.length === 1 ? '' : 's'}.` +
    (s.total ? ` After weighing where each one runs, ${s.byRisk.critical} ${s.byRisk.critical === 1 ? 'is' : 'are'} critical here (raw severity says ${s.bySeverity.critical}).` : '');
  const right = [
    ...wrap(prose, rightW),
    '',
    groupLine('Dependencies', kinds.dependency),
    groupLine('Your code', kinds.code),
    groupLine('Secrets', kinds.secret),
  ];
  if (width < 88) return [...left, '', ...right].map((l) => '  ' + bar + l);
  const rows = Math.max(left.length, right.length);
  const out = [];
  for (let i = 0; i < rows; i++) out.push('  ' + bar + pad(left[i] ?? '', leftW) + '  ' + (right[i] ?? ''));
  return out;
}

function findingEntry(f, sort, width) {
  const leftW = 34;
  const rightW = width < 88 ? width - 6 : Math.max(36, width - leftW - 7);
  const level = sort === 'severity' ? f.severity : f.risk;

  // Left: label, subject, score trio — like "UPDATE 3 – Identified / time / Up Affected Down".
  const subject =
    f.kind === 'dependency' ? ellipsisEnd(`${f.package.name}@${f.package.version}`, leftW - 2) : ellipsisStart(`${f.location.file}:${f.location.line}`, leftW - 2);
  const ctx = f.exposure?.context ?? 'unknown';
  const left = [
    `${TONE[level]('◉')} ${TONE[level](c.bold(level.toUpperCase()))} ${c.gray('–')} ${c.bold(KIND_WORD[f.kind])}`,
    '  ' + c.cyan(subject),
    `  ${c.gray('Risk')} ${dot(f.risk)} ${c.bold(f.riskScore.toFixed(1))}   ${c.gray('Sev')} ${dot(f.severity)} ${f.severityScore.toFixed(1)}`,
    `  ${c.gray('Runs')} ${dot(EXPOSURE_TONE[ctx])} ${EXPOSURE_WORD[ctx]}`,
  ];
  const tags = [];
  if (f.kind === 'dependency') {
    tags.push(f.package.direct ? 'direct' : 'transitive');
    if (!f.package.prod) tags.push('dev');
  } else if (f.tainted) tags.push('user input');
  if (tags.length) left.push('  ' + c.gray(tags.join(' · ')));

  // Right: what happened, why it ranks here, what to do.
  const right = [];
  const flags = [];
  if (f.advisory?.malicious) flags.push(c.bgRed(' MALICIOUS PACKAGE '));
  if (f.exploit?.kev) flags.push(c.bgRed(' EXPLOITED IN THE WILD '));
  right.push(...block(f.title, rightW, c.bold));
  if (flags.length) right.push(flags.join(' '));
  if (f.kind === 'dependency') {
    right.push(c.gray(ellipsisEnd(`${f.advisory.id}${f.advisory.aliases.length ? ' · ' + f.advisory.aliases.slice(0, 2).join(', ') : ''}`, rightW)));
    if (f.package.path.length > 1) right.push(...block(`via ${f.package.path.join(' › ')}`, rightW, c.gray));
  } else if (f.location?.snippet) {
    right.push(c.cyan('│ ') + c.cyan(ellipsisEnd(f.location.snippet.trim(), rightW - 2)));
  }
  for (const r of f.reasons ?? []) {
    if (/^AI \(/.test(r)) continue;
    right.push(...block(r, rightW, c.gray, c.gray('· '), '  '));
  }
  if (f.fix) right.push(...block(f.fix, rightW, (s) => s, c.green('Fix: '), '     '));
  if (f.ai) {
    right.push(...block(`${f.ai.verdict.replace('_', ' ')} (${Math.round(f.ai.confidence * 100)}%) — ${f.ai.reasoning}`.slice(0, 420), rightW, c.magenta, c.magenta(`AI ${f.ai.provider}: `), '  '));
  }

  return columns(left, right, leftW, width);
}

/**
 * @param {any} report
 * @param {{sort?: 'risk'|'severity', limit?: number, min?: string}} opts
 */
export function printReport(report, { sort = 'risk', limit = 30, min } = {}) {
  const width = Math.max(60, Math.min(Number(process.env.COLUMNS) || process.stdout.columns || 110, 130));
  const rule = (ch = '─') => '  ' + c.gray(ch.repeat(width - 4));
  const out = [''];

  // Header strip + title, like a status page.
  out.push(c.gray('━'.repeat(width)));
  const fw = report.project.framework;
  const brand = `  ${c.bold('iamsecure')} ${c.gray('v' + report.tool.version)}`;
  const home = os.homedir();
  const shown = report.project.root.startsWith(home) ? '~' + report.project.root.slice(home.length) : report.project.root;
  const where = c.gray(ellipsisStart(shown, Math.max(10, width - 30)));
  out.push(brand + ' '.repeat(Math.max(2, width - vlen(brand) - vlen(where) - 2)) + where);
  out.push(c.gray('━'.repeat(width)));
  out.push('');
  out.push(`  ${c.gray('Projects ›')} ${report.project.name}`);
  out.push('');
  out.push(`  ${c.yellow('⚠')}  ${c.bold(`Security Report — ${report.project.name}`)}  ${c.gray(`(${fw})`)}`);
  out.push('');
  out.push(...counters(report.summary));
  out.push('');
  for (const w of report.warnings) out.push(...block(w, width - 4, c.yellow, '  ' + c.yellow('⚠ '), '    '));
  if (report.warnings.length) out.push('');

  out.push(`  ${c.gray('Latest scan:')}`);
  out.push(...latestPanel(report, width));
  out.push('');

  if (!report.findings.length) {
    out.push('  ' + c.green('✔ No known vulnerabilities or insecure code patterns found.'), '');
    console.log(out.join('\n'));
    return;
  }

  const field = sort === 'severity' ? 'severity' : 'risk';
  const order = [...LEVELS, 'none'];
  let list = sortFindings(report.findings, sort);
  if (min) list = list.filter((f) => order.indexOf(f[field]) <= order.indexOf(min));

  const heading = sort === 'severity' ? 'Findings — by severity (raw CVSS, high → low):' : 'Findings — worst first (real risk in this codebase):';
  const hint = sort === 'severity' ? '--sort risk for contextual order' : '--sort severity for raw CVSS order';
  out.push(`  ${c.gray(heading)}${' '.repeat(Math.max(2, width - 4 - heading.length - hint.length))}${c.gray(hint)}`);
  out.push(rule());
  for (const f of list.slice(0, limit)) {
    out.push(...findingEntry(f, sort, width));
    out.push(rule());
  }
  if (list.length > limit) {
    out.push(`  ${c.gray('…')} ${c.bold(list.length - limit)} ${c.gray('more — use --limit <n>, --json, or open the dashboard with')} ${c.cyan('--ui')}`);
  }
  out.push('');
  console.log(out.join('\n'));
}
