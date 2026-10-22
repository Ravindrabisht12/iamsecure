import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { mapLimit } from '../util/http.js';
import { cacheGet, cacheSet } from '../util/cache.js';
import { levelFromScore } from '../deps/cvss.js';
import { createProvider } from './providers.js';

const VERDICTS = { exploitable: 1.15, likely: 1, unlikely: 0.6, not_exploitable: 0.3 };
const MAX_DETAILS = 3000;

function readLines(root, rel, center, radius) {
  const abs = path.resolve(root, rel);
  if (!abs.startsWith(path.resolve(root) + path.sep)) return null;
  let text;
  try {
    text = fs.readFileSync(abs, 'utf8');
  } catch {
    return null;
  }
  const lines = text.split('\n');
  const from = Math.max(1, center - radius);
  const to = Math.min(lines.length, center + radius);
  const body = lines.slice(from - 1, to).map((l, i) => `${String(from + i).padStart(4)}| ${l}`).join('\n');
  return `<code file="${rel}" lines="${from}-${to}">\n${body}\n</code>`;
}

/** Evidence the model needs: the finding plus the code that uses it. */
export function buildPrompt(f, report) {
  const root = report.project.root;
  const parts = [];
  const meta = {
    type: f.kind,
    title: f.title,
    framework: report.project.framework,
    whereItRuns: f.exposure?.label,
    scannerSeverity: f.severityScore,
    scannerRisk: f.riskScore,
    scannerReasons: f.reasons,
  };
  if (f.kind === 'dependency') {
    Object.assign(meta, {
      package: `${f.package.name}@${f.package.version}`,
      direct: f.package.direct,
      productionDependency: f.package.prod,
      installedVia: f.package.path,
      advisory: f.advisory.id,
      aliases: f.advisory.aliases,
      cwes: f.advisory.cwes,
      cvss: f.advisory.cvss?.vector,
      fixedIn: f.package.fixedIn,
      advisoryText: `${f.advisory.summary}\n\n${f.advisory.details}`.slice(0, MAX_DETAILS),
    });
  } else {
    Object.assign(meta, { rule: f.ruleId, cwe: f.cwe, userInputDetected: !!f.tainted, location: `${f.location.file}:${f.location.line}` });
  }
  parts.push(`<finding>\n${JSON.stringify(meta, null, 2)}\n</finding>`);

  if (f.kind === 'dependency') {
    // Show where the package (or the direct dependency that pulls it in) is used.
    const evid = [];
    if (f.reachable?.file) evid.push([f.reachable.file, f.reachable.line]);
    for (const e of f.exposure?.evidence ?? []) {
      const m = e.match(/in (.+):(\d+)$/);
      if (m) evid.push([m[1], Number(m[2])]);
    }
    const seen = new Set();
    for (const [file, line] of evid) {
      if (seen.has(file) || seen.size >= 3) continue;
      seen.add(file);
      const block = readLines(root, file, line, 25);
      if (block) parts.push(block);
    }
    if (!seen.size) parts.push('(No source file imports this package directly; it is pulled in transitively or loaded by the framework.)');
    if (report.sourceFiles?.length) {
      const list = report.sourceFiles.slice(0, 120).map((s) => `${s.file} [${s.context}]`).join('\n');
      parts.push(`Project source files (to judge whether the affected feature is used):\n${list}`);
    }
  } else {
    const block = readLines(root, f.location.file, f.location.line, 30);
    if (block) parts.push(block);
  }

  parts.push(`Question: is this finding actually exploitable in this codebase, as deployed in production?
Consider: can an attacker reach it (network-facing route, user input), does the vulnerable code path get used, is input validated or sanitised first, does it only run in the browser or at build time, and what an attacker gains.

Respond with ONLY a JSON object, no markdown:
{"verdict": "exploitable" | "likely" | "unlikely" | "not_exploitable",
 "confidence": <number 0..1>,
 "reasoning": "<at most 3 sentences citing the specific code>",
 "fix": "<the concrete change to make; a short code snippet if it helps>"}`);
  return parts.join('\n\n');
}

function parseVerdict(text) {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end <= start) throw new Error('AI response had no JSON object');
  const obj = JSON.parse(text.slice(start, end + 1));
  const verdict = String(obj.verdict ?? '').toLowerCase().replace(/[\s-]+/g, '_');
  if (!(verdict in VERDICTS)) throw new Error(`AI returned unknown verdict "${obj.verdict}"`);
  const confidence = Math.min(1, Math.max(0, Number(obj.confidence) || 0.5));
  return { verdict, confidence, reasoning: String(obj.reasoning ?? '').slice(0, 1200), fix: String(obj.fix ?? '').slice(0, 2000) };
}

/** Fold an AI verdict into the risk score; low confidence moves it less. */
function applyVerdict(f, ai) {
  const m = 1 + (VERDICTS[ai.verdict] - 1) * ai.confidence;
  f.ai = ai;
  f.riskScore = Math.round(Math.min(10, f.riskScore * m) * 10) / 10;
  f.risk = levelFromScore(f.riskScore);
  f.reasons = [...(f.reasons ?? []), `AI (${ai.provider}) judged it ${ai.verdict.replace('_', ' ')} (${Math.round(ai.confidence * 100)}% confidence)`];
}

async function reviewOne(f, report, provider) {
  const prompt = buildPrompt(f, report);
  const key = `${provider.name}:${provider.model}:${crypto.createHash('sha256').update(prompt).digest('hex')}`;
  let ai = cacheGet('ai', key);
  if (!ai) {
    ai = { ...parseVerdict(await provider.complete(prompt)), provider: provider.name, model: provider.model };
    cacheSet('ai', key, ai);
  }
  applyVerdict(f, ai);
  return ai;
}

/**
 * Ask an AI provider to validate the top findings.
 * @param {any} report scan report (findings are updated in place)
 * @param {{provider: string, model?: string, max?: number, dryRun?: boolean, log?: (m:string)=>void}} opts
 */
export async function aiReview(report, { provider: name, model, max = 15, dryRun = false, log = () => {} }) {
  const provider = createProvider(name, { model, root: report.project.root });
  const candidates = [...report.findings]
    .filter((f) => f.riskScore >= 4 && !f.ai && !f.advisory?.malicious)
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, max);
  if (!candidates.length) return { reviewed: 0, failed: 0, provider };

  if (dryRun) {
    for (const f of candidates) log(`--- prompt for ${f.id} ---\n${buildPrompt(f, report)}\n`);
    log(`Dry run: ${candidates.length} prompts shown above; nothing was sent.`);
    return { reviewed: 0, failed: 0, provider };
  }

  log(`Asking ${provider.name} (${provider.model}) to validate the top ${candidates.length} findings…`);
  let done = 0;
  let failed = 0;
  const errors = new Set();
  await mapLimit(candidates, provider.concurrency, async (f) => {
    try {
      await reviewOne(f, report, provider);
    } catch (err) {
      failed++;
      errors.add(err.message);
    }
    log(`  AI review ${++done}/${candidates.length}`);
  });
  if (errors.size) report.warnings.push(`AI review: ${failed} of ${candidates.length} failed — ${[...errors].slice(0, 2).join('; ')}`);
  return { reviewed: candidates.length - failed, failed, provider };
}

/** Single on-demand review (dashboard "Ask AI" button). */
export function makeAnalyzer({ provider: name, model }) {
  let provider;
  return async (f, report) => {
    provider ??= createProvider(name, { model, root: report.project.root });
    return reviewOne(f, report, provider);
  };
}
