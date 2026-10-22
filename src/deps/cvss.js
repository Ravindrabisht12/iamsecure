// CVSS v3.x base score calculator (spec: https://www.first.org/cvss/v3.1/specification-document).
// For v4 vectors we only parse the metrics; the score then comes from the advisory's label.

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },
};

function roundUp(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function parseVector(vector) {
  const metrics = {};
  for (const part of String(vector).split('/')) {
    const [k, v] = part.split(':');
    if (k && v) metrics[k] = v;
  }
  return metrics;
}

/** @returns {{version:string, score:number|null, metrics:Record<string,string>}} */
export function cvssScore(vector) {
  const m = parseVector(vector);
  const version = m.CVSS ?? '';
  if (!version.startsWith('3')) return { version, score: null, metrics: m };
  const scopeChanged = m.S === 'C';
  const [C, I, A] = [W.CIA[m.C], W.CIA[m.I], W.CIA[m.A]];
  const PR = (scopeChanged ? W.PR_C : W.PR_U)[m.PR];
  if ([W.AV[m.AV], W.AC[m.AC], W.UI[m.UI], PR, C, I, A].some((x) => x === undefined)) {
    return { version, score: null, metrics: m };
  }
  const iss = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * W.AV[m.AV] * W.AC[m.AC] * PR * W.UI[m.UI];
  if (impact <= 0) return { version, score: 0, metrics: m };
  const raw = scopeChanged ? 1.08 * (impact + exploitability) : impact + exploitability;
  return { version, score: roundUp(Math.min(raw, 10)), metrics: m };
}

export const LEVELS = ['critical', 'high', 'medium', 'low', 'none'];

export function levelFromScore(score) {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}

/** Representative score for advisories that only carry a label. */
export function scoreFromLabel(label) {
  return { CRITICAL: 9.5, HIGH: 8, MODERATE: 5.5, MEDIUM: 5.5, LOW: 2.5 }[String(label).toUpperCase()] ?? null;
}
