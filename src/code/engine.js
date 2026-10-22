import { stripComments } from './strip.js';
import { RULES, SOURCES, langOf } from './rules.js';
import { levelFromScore } from '../deps/cvss.js';

const ASSIGN = {
  js: /(?:const|let|var)\s+(?:\{([^}]+)\}|\[([^\]]+)\]|([\w$]+))\s*=\s*([^;\n]+)/g,
  php: /(\$\w+)\s*=\s*([^;\n]+)/g,
  py: /^\s*([\w, ]+?)\s*=\s*([^\n]+)/gm,
};

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Lightweight intra-file taint tracking: variables assigned (directly or transitively)
 * from a user-input source. Good enough to tell `exec(userInput)` from `exec("ls")`.
 */
export function taintedNames(code, lang) {
  const names = new Set();
  const src = SOURCES[lang];
  // `[^\w$.]` before the name: `import.meta.url` is not the tainted variable `url`.
  const isTainted = (rhs) => src.test(rhs) || [...names].some((n) => new RegExp(`(^|[^\\w$.])${escapeRe(n)}([^\\w$]|$)`).test(rhs));
  for (let pass = 0; pass < 3; pass++) {
    const before = names.size;
    for (const m of code.matchAll(ASSIGN[lang])) {
      if (lang === 'js') {
        const [, destructObj, destructArr, single, rhs] = m;
        if (!isTainted(rhs)) continue;
        if (single) names.add(single);
        for (const part of (destructObj ?? destructArr ?? '').split(',')) {
          const name = part.split(':').pop().split('=')[0].trim().replace(/^\.\.\./, '');
          if (/^[\w$]+$/.test(name)) names.add(name);
        }
      } else if (lang === 'php') {
        if (isTainted(m[2])) names.add(m[1]);
      } else {
        if (!isTainted(m[2])) continue;
        for (const n of m[1].split(',')) if (/^\w+$/.test(n.trim())) names.add(n.trim());
      }
    }
    if (names.size === before) break;
  }
  return names;
}

function argsAfter(window, idx) {
  // Text from the sink onwards, roughly up to the end of the call/statement.
  return window.slice(idx).split(/;\s*(\n|$)/)[0];
}

const DYNAMIC = /\$\{|['"`]\s*\+|\+\s*['"`\w$]|\(\s*[\w$.[\]]+\s*[,)]|\(\s*\w+\s*\(|=\s*[\w$.[\]()]+\s*;?\s*$|\$\w+|\bf['"]|%\s*\(|\.format\(/;

/**
 * Run all rules over one file.
 * @returns {any[]} findings
 */
export function scanFile(rel, text, fileContext) {
  const lang = langOf(rel);
  if (!lang) return [];
  const rules = RULES[lang];
  const code = stripComments(text, lang);
  const lines = code.split('\n');
  // Same text with string contents blanked: most sinks must appear in code, not inside a string.
  const bare = stripComments(text, lang, { blankStrings: true }).split('\n');
  const raw = text.split('\n');
  const tainted = taintedNames(code, lang);
  const taintRe = tainted.size
    ? new RegExp(`(^|[^\\w$.])(${[...tainted].map(escapeRe).join('|')})([^\\w$]|$)`)
    : null;
  const findings = [];

  for (const rule of rules) {
    if (rule.requires && !rule.requires.test(code)) continue;
    if (rule.fileExclude && rule.fileExclude.test(code)) continue;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const m = rule.sink.exec(rule.inStrings ? line : bare[i]);
      if (!m) continue;
      if (rule.lineHint && !rule.lineHint.test(line)) continue;
      if (rule.exclude && rule.exclude.test(line)) continue;

      const window = lines.slice(i, i + 3).join('\n');
      // From the sink onwards (including the sink itself, which may already contain $_GET, req.body, …).
      const args = argsAfter(window, m.index);
      const isTainted = SOURCES[lang].test(args) || (taintRe?.test(args) ?? false);
      const isDynamic = isTainted || DYNAMIC.test(args);
      if (rule.when === 'tainted' && !isTainted) continue;
      if (rule.when === 'dynamic' && !isDynamic) continue;

      const score = isTainted ? (rule.taintedSev ?? rule.sev) : rule.sev;
      findings.push({
        id: `code:${rule.id}:${rel}:${i + 1}`,
        kind: rule.category === 'secret' ? 'secret' : 'code',
        title: rule.title,
        ruleId: rule.id,
        category: rule.category,
        cwe: rule.cwe,
        severityScore: score,
        severity: levelFromScore(score),
        confidence: isTainted ? 'high' : rule.when === 'always' ? 'medium' : 'low',
        tainted: isTainted,
        context: rule.context ?? fileContext,
        location: { file: rel, line: i + 1, snippet: raw[i].trim().slice(0, 200) },
        fix: rule.fix,
      });
    }
  }
  return findings;
}

export function scanCode(src) {
  const findings = [];
  for (const [rel, context] of src.contexts) {
    findings.push(...scanFile(rel, src.texts.get(rel), context));
  }
  return findings;
}
