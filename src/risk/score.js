// Turns "how bad is this bug in general" (severity) into "how bad is it HERE" (risk).
//
//   risk = severity × exposure(where it runs, what kind of bug) × attack-vector × exploit-intel × reachability
//
// Every multiplier that fires adds a human-readable reason, so the ranking is explainable.

import { levelFromScore } from '../deps/cvss.js';
import { CONTEXT_LABEL, mergeContexts, frameworkRuntime } from '../code/context.js';

const DEFAULT_WEIGHTS = { server: 1, universal: 1, client: 0.6, build: 0.3, unused: 0.5, unknown: 0.85 };

/** Vulnerability classes. `client` = how much the bug still matters when the code only runs in a browser. */
export const VULN_CLASSES = [
  { id: 'malicious', name: 'malicious code', cwes: [], re: /malicious (code|package)/i, weights: { client: 1, build: 1, unused: 1 } },
  { id: 'secret', name: 'leaked secret', clientNote: 'anything in client code ships to every visitor', cwes: ['CWE-798'], re: null, weights: { client: 1, server: 0.9, build: 0.8, unknown: 0.9 } },
  { id: 'rce', name: 'code execution', clientNote: 'code runs in the visitor\'s browser sandbox, not on your server', cwes: ['CWE-94', 'CWE-95', 'CWE-77', 'CWE-78', 'CWE-502', 'CWE-1336'], re: /remote code execution|command injection|code injection|\brce\b|arbitrary code|template injection/i, weights: { client: 0.5 } },
  { id: 'sqli', name: 'SQL injection', clientNote: 'the browser has no direct database access', cwes: ['CWE-89', 'CWE-943'], re: /sql injection|nosql injection/i, weights: { client: 0.3 } },
  { id: 'auth', name: 'auth bypass', clientNote: 'your server must enforce auth anyway', cwes: ['CWE-285', 'CWE-287', 'CWE-288', 'CWE-290', 'CWE-306', 'CWE-347', 'CWE-863', 'CWE-639', 'CWE-1390'], re: /authori[sz]ation bypass|authentication bypass|auth bypass|signature (verification|bypass)|forge/i, weights: { client: 0.4 } },
  { id: 'ssrf', name: 'SSRF', clientNote: 'browser requests can\'t reach your internal network', cwes: ['CWE-918'], re: /\bssrf\b|server-side request forgery/i, weights: { client: 0.25 } },
  { id: 'path', name: 'path traversal', clientNote: 'the browser has no access to your server\'s filesystem', cwes: ['CWE-22', 'CWE-23', 'CWE-24', 'CWE-73'], re: /path traversal|directory traversal|arbitrary file (read|write)/i, weights: { client: 0.25 } },
  { id: 'xss', name: 'XSS', clientNote: 'XSS targets exactly this environment', cwes: ['CWE-79', 'CWE-80', 'CWE-116'], re: /cross[- ]site scripting|\bxss\b|html injection/i, weights: { client: 0.95 } },
  { id: 'proto', name: 'prototype pollution', clientNote: 'can still be chained into client-side XSS', cwes: ['CWE-1321', 'CWE-915'], re: /prototype pollution/i, weights: { client: 0.65 } },
  { id: 'redirect', name: 'open redirect', clientNote: 'still usable for phishing', cwes: ['CWE-601'], re: /open redirect/i, weights: { client: 0.7 } },
  { id: 'dos', name: 'denial of service', clientNote: 'an attacker can only freeze their own tab', cwes: ['CWE-400', 'CWE-1333', 'CWE-770', 'CWE-674', 'CWE-835', 'CWE-407', 'CWE-776', 'CWE-1050', 'CWE-834'], re: /denial[- ]of[- ]service|\bdos\b|redos|regular expression|backtracking|resource exhaustion|uncontrolled resource|infinite loop|memory exhaustion/i, weights: { client: 0.2 } },
  { id: 'leak', name: 'information leak', clientNote: 'only data already sent to the browser is at risk', cwes: ['CWE-200', 'CWE-201', 'CWE-209', 'CWE-359', 'CWE-522', 'CWE-532', 'CWE-312'], re: /credential leak|information (disclosure|exposure)|exposure of sensitive|leaks?\b/i, weights: { client: 0.5 } },
  { id: 'crypto', name: 'weak crypto', clientNote: 'client-side crypto is rarely security-critical', cwes: ['CWE-327', 'CWE-328', 'CWE-330', 'CWE-338', 'CWE-326'], re: /weak (crypto|hash|random)|insecure random|predictable/i, weights: { client: 0.5 } },
];
const OTHER = { id: 'other', name: 'vulnerability', cwes: [], re: null, weights: {} };

export function classifyVuln({ cwes = [], text = '', category }) {
  if (category) return VULN_CLASSES.find((c) => c.id === category) ?? OTHER;
  return (
    VULN_CLASSES.find((c) => c.cwes.some((cwe) => cwes.includes(cwe))) ??
    VULN_CLASSES.find((c) => c.re?.test(text)) ??
    OTHER
  );
}

const STOP = new Set(['true', 'false', 'null', 'undefined', 'object', 'string', 'number', 'function', 'prototype', '__proto__', 'constructor', 'require', 'import', 'export', 'index', 'package', 'node', 'npm', 'json', 'options', 'config', 'version', 'default', 'this', 'window', 'document', 'http', 'https', 'localhost', 'test', 'name', 'data', 'keys', 'def', 'read', 'build', 'stack', 'prop', 'auth', 'username', 'password', 'cookie', 'value', 'key', 'url', 'path', 'input', 'output', 'error', 'false']);

/** Function/property names an advisory calls out in `backticks` — candidates for a reachability check. */
export function vulnerableSymbols(adv, pkgName) {
  const ids = new Set();
  for (const m of `${adv.summary}\n${adv.details}`.matchAll(/`([^`\n]{2,60})`/g)) {
    const s = m[1].trim().replace(/\(.*\)$/, '');
    if (!/^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$/.test(s)) continue;
    const last = s.split('.').pop();
    if (last.length < 3 || /^[A-Z0-9_]+$/.test(last) || /^[0-9a-f]{6,}$/.test(last) || STOP.has(last.toLowerCase()) || last === pkgName || pkgName.endsWith('/' + last)) continue;
    ids.add(last);
  }
  return [...ids].slice(0, 10);
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Find a call to one of `symbols` made through this package's import:
 * `binding.sym(` for default/namespace imports, `sym(` (or its alias) for named imports.
 */
function findSymbolUse(symbols, uses, texts) {
  for (const u of uses) {
    const text = texts.get(u.file);
    if (!text) continue;
    const lines = text.split('\n');
    const importText = lines.slice(u.line - 1, u.line + 6).join('\n').split(/\bfrom\b|require\s*\(/)[0];
    for (const sym of symbols) {
      const s = escapeRe(sym);
      const named = new RegExp(`[{,]\\s*${s}(?:\\s+as\\s+([\\w$]+))?\\s*[,}]`).exec(importText);
      let re;
      if (named) re = new RegExp(`(?<![\\w$.])${escapeRe(named[1] ?? sym)}\\s*\\(`, 'g');
      else if (u.binding) re = new RegExp(`(?<![\\w$.])${escapeRe(u.binding)}\\s*\\.\\s*${s}\\b`, 'g');
      else continue;
      for (const m of text.matchAll(re)) {
        const line = text.slice(0, m.index).split('\n').length;
        if (line !== u.line) return { symbol: sym, file: u.file, line };
      }
    }
  }
  return null;
}

/** Where a vulnerable package actually runs, inferred from which direct deps pull it in and where those are imported. */
function dependencyExposure(f, src, runtime) {
  // PHP/Python packages run in the backend; import names don't map cleanly to package names, so don't guess.
  if (f.package.ecosystem !== 'npm') {
    return { context: f.package.prod ? 'server' : 'build', evidence: [f.package.prod ? `${f.package.ecosystem} runtime dependency` : 'dev dependency'] };
  }
  if (!src) return { context: f.package.prod ? 'unknown' : 'build', evidence: [] };
  const contexts = new Set();
  const evidence = [];
  for (const root of f.package.introducedBy) {
    const uses = src.usage.get(root);
    if (uses?.length) {
      for (const u of uses) contexts.add(u.context);
      const best = uses.find((u) => u.context === 'server' || u.context === 'universal') ?? uses[0];
      evidence.push(`${root === f.package.name ? 'imported' : `via ${root}`} in ${best.file}:${best.line}`);
    } else if (runtime[root]) {
      runtime[root].forEach((c) => contexts.add(c));
      evidence.push(`${root} is loaded by the framework`);
    }
  }
  const context = mergeContexts(contexts) ?? (f.package.prod ? 'unused' : 'build');
  return { context, evidence: evidence.slice(0, 3) };
}

const round1 = (x) => Math.round(x * 10) / 10;

/**
 * Compute riskScore/risk/exposure/reasons on every finding (mutates).
 * @param {any[]} findings
 * @param {{src: ReturnType<import('../code/index.js').analyzeSource>|null, framework: string, exploit?: {kev:Map<string,any>, epss:Map<string,any>}}} ctx
 */
export function scoreFindings(findings, { src, framework, exploit }) {
  const runtime = frameworkRuntime(framework);
  for (const f of findings) {
    const reasons = [];
    let s = f.severityScore;
    const adv = f.advisory;

    const cls = classifyVuln(
      f.kind === 'dependency'
        ? { cwes: adv.cwes, text: `${adv.summary} ${adv.malicious ? 'malicious code' : ''}` }
        : { category: f.category },
    );
    f.vulnClass = cls.id;

    // 1. Exposure
    const exp =
      f.kind === 'dependency'
        ? dependencyExposure(f, src, runtime)
        : { context: f.context ?? src?.contexts.get(f.location?.file) ?? 'unknown', evidence: [] };
    const weight = { ...DEFAULT_WEIGHTS, ...cls.weights }[exp.context] ?? 1;
    f.exposure = { context: exp.context, label: CONTEXT_LABEL[exp.context], evidence: exp.evidence };
    s *= weight;
    const why = weight < 1 || exp.context === 'client' ? exposureReason(exp.context, cls, f) : null;
    if (why) reasons.push(why);
    else if (f.kind === 'dependency' && exp.evidence.length) reasons.push(`Runs on the server — ${exp.evidence[0]}`);

    // 2. Attack vector (CVSS)
    const m = adv?.cvss?.metrics;
    if (m && (exp.context === 'server' || exp.context === 'universal')) {
      if (m.AV === 'L' || m.AV === 'P') {
        s *= 0.75;
        reasons.push(`Needs ${m.AV === 'L' ? 'local' : 'physical'} access to exploit (CVSS AV:${m.AV})`);
      }
      if (m.PR === 'H') {
        s *= 0.85;
        reasons.push('Attacker needs high privileges first (CVSS PR:H)');
      }
    }

    // 3. Exploit intelligence
    if (f.kind === 'dependency' && exploit) {
      const cves = [adv.id, ...adv.aliases].filter((id) => id.startsWith('CVE-'));
      const kev = cves.map((c) => exploit.kev.get(c)).find(Boolean);
      const epss = cves.map((c) => exploit.epss.get(c)).filter(Boolean).sort((a, b) => b.epss - a.epss)[0];
      f.exploit = { cves, kev: kev ?? null, epss: epss ?? null };
      if (kev) {
        const live = !['build', 'unused'].includes(exp.context);
        s = live ? Math.max(s * 1.4, 9) : s * 1.3;
        reasons.push(`CISA KEV: actively exploited in the wild since ${kev.dateAdded}${kev.ransomware ? ' (used by ransomware)' : ''}`);
      }
      if (epss) {
        const pct = (epss.epss * 100).toFixed(epss.epss < 0.01 ? 2 : 1);
        if (epss.epss >= 0.5) (s *= 1.3), reasons.push(`EPSS ${pct}% — very likely to be exploited soon`);
        else if (epss.epss >= 0.1) (s *= 1.15), reasons.push(`EPSS ${pct}% — elevated exploitation likelihood`);
        else if (epss.epss < 0.001 && !kev) s *= 0.95;
      }
    }

    // 4. Reachability: does our code call the function the advisory names?
    if (f.kind === 'dependency' && src && f.package.direct && !adv.malicious) {
      const uses = src.usage.get(f.package.name) ?? [];
      const symbols = vulnerableSymbols(adv, f.package.name);
      if (uses.length && symbols.length) {
        const hit = findSymbolUse(symbols, uses, src.texts);
        if (hit) {
          s *= 1.15;
          f.reachable = hit;
          reasons.push(`Your code calls \`${hit.symbol}\` named in the advisory (${hit.file}:${hit.line})`);
        } else {
          // Advisories often name internal helpers, so absence is only weak evidence.
          s *= 0.9;
          f.reachable = false;
          reasons.push(`No direct calls found to the functions named in the advisory (${symbols.slice(0, 4).map((x) => `\`${x}\``).join(', ')}) — they may be internal; --ai can confirm`);
        }
      }
    }

    if (adv?.malicious) {
      s = 10;
      reasons.unshift('Known MALICIOUS package — its install scripts run on every machine that installs it, dev-only or not');
    }

    f.riskScore = round1(Math.min(10, Math.max(0, s)));
    f.risk = levelFromScore(f.riskScore);
    f.reasons = reasons;
  }
  return findings;
}

function exposureReason(context, cls, f) {
  switch (context) {
    case 'client':
      return `Only runs in the browser — ${cls.clientNote ?? `${cls.name} impact is reduced there`}`;
    case 'build':
      return f.kind === 'dependency' ? 'Dev/build/test tooling only — not shipped to production' : 'In test/build code — not shipped to production';
    case 'unused':
      return 'Installed as a production dependency but never imported — remove it if unused';
    case 'unknown':
      return 'Could not determine where this runs';
    default:
      return null;
  }
}
