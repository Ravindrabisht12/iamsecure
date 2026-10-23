// SARIF 2.1.0 — consumed by GitHub code scanning, GitLab, Azure DevOps, VS Code SARIF viewer.

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', none: 'note' };

export function toSarif(report) {
  const rules = new Map();
  const results = [];

  for (const f of report.findings) {
    const ruleId = f.kind === 'dependency' ? f.advisory.id : f.ruleId;
    const helpUri = f.kind === 'dependency' ? f.advisory.url : f.cwe ? `https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-', '')}.html` : undefined;
    const prev = rules.get(ruleId);
    // GitHub reads `security-severity` (0–10) to bucket alerts; use the contextual risk score.
    if (!prev || Number(prev.properties['security-severity']) < f.riskScore) {
      rules.set(ruleId, {
        id: ruleId,
        name: ruleId.replace(/[^A-Za-z0-9]+/g, '_'),
        shortDescription: { text: f.title.slice(0, 200) },
        fullDescription: { text: (f.kind === 'dependency' ? f.advisory.details || f.title : f.title).slice(0, 1000) },
        helpUri,
        help: { text: f.fix ?? '' },
        properties: {
          'security-severity': f.riskScore.toFixed(1),
          tags: ['security', f.kind, ...(f.cwe ? [f.cwe] : f.advisory?.cwes ?? [])],
        },
      });
    }

    const where =
      f.kind === 'dependency'
        ? { uri: f.package.lockfile.split(',')[0].trim(), line: 1 }
        : { uri: f.location.file, line: f.location.line };
    const text =
      f.kind === 'dependency'
        ? `${f.package.name}@${f.package.version}: ${f.title}. ${f.fix}${f.package.path.length > 1 ? ` (via ${f.package.path.join(' > ')})` : ''}`
        : `${f.title}. ${f.fix}`;

    results.push({
      ruleId,
      level: LEVEL[f.risk],
      message: { text: [text, ...(f.reasons ?? []).map((r) => `• ${r}`)].join('\n') },
      locations: [{ physicalLocation: { artifactLocation: { uri: where.uri }, region: { startLine: where.line } } }],
      partialFingerprints: { iamsecure: f.id },
      properties: { riskScore: f.riskScore, severityScore: f.severityScore, exposure: f.exposure?.context, aiVerdict: f.ai?.verdict },
    });
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'iamsecure', version: report.tool.version, informationUri: 'https://github.com/Ravindrabisht12/iamsecure', rules: [...rules.values()] } },
        results,
      },
    ],
  };
}
