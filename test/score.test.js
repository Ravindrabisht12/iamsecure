import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreFindings, classifyVuln, vulnerableSymbols } from '../src/risk/score.js';

const dep = (name, { cwes = [], summary = 'x', score = 7.5, prod = true, malicious = false, introducedBy = [name] } = {}) => ({
  kind: 'dependency',
  title: summary,
  severityScore: score,
  package: { name, version: '1.0.0', ecosystem: 'npm', direct: true, prod, path: [`${name}@1.0.0`], introducedBy },
  advisory: { id: 'GHSA-1', aliases: [], summary, details: '', cwes, cvss: null, malicious },
});

const src = (usage) => ({ usage: new Map(Object.entries(usage)), texts: new Map(), contexts: new Map() });

test('the same ReDoS ranks far lower when the package only runs in the browser', () => {
  const server = dep('a', { cwes: ['CWE-1333'] });
  const browser = dep('b', { cwes: ['CWE-1333'] });
  scoreFindings([server, browser], {
    framework: 'next',
    src: src({ a: [{ file: 'app/api/x/route.ts', line: 1, context: 'server' }], b: [{ file: 'components/C.tsx', line: 1, context: 'client' }] }),
  });
  assert.equal(server.riskScore, 7.5);
  assert.equal(browser.riskScore, 1.5);
  assert.equal(browser.risk, 'low');
  assert.match(browser.reasons[0], /browser/);
});

test('XSS stays serious in the browser; dev tooling and unused deps drop', () => {
  const xss = dep('x', { cwes: ['CWE-79'], score: 6.1 });
  const devTool = dep('t', { score: 9.8, prod: false });
  const unused = dep('u', { score: 8 });
  scoreFindings([xss, devTool, unused], { framework: 'vite-spa', src: src({ x: [{ file: 'src/a.tsx', line: 1, context: 'client' }] }) });
  assert.ok(xss.riskScore >= 5.5);
  assert.equal(devTool.exposure.context, 'build');
  assert.ok(devTool.riskScore < 3.5);
  assert.equal(unused.exposure.context, 'unused');
});

test('malicious packages are always 10, KEV raises the floor', () => {
  const mal = dep('evil', { malicious: true, prod: false, score: 10 });
  const kev = dep('k', { score: 7.5 });
  kev.advisory.aliases = ['CVE-2099-0001'];
  scoreFindings([mal, kev], {
    framework: 'node-server',
    src: src({ k: [{ file: 'server.js', line: 1, context: 'server' }] }),
    exploit: { kev: new Map([['CVE-2099-0001', { dateAdded: '2099-01-01' }]]), epss: new Map() },
  });
  assert.equal(mal.riskScore, 10);
  assert.ok(kev.riskScore >= 9);
  assert.match(kev.reasons.join(' '), /CISA KEV/);
});

test('vulnerability classes and advisory symbols', () => {
  assert.equal(classifyVuln({ cwes: ['CWE-918'] }).id, 'ssrf');
  assert.equal(classifyVuln({ text: 'Regular expression denial of service' }).id, 'dos');
  assert.deepEqual(vulnerableSymbols({ summary: 'Code injection via `_.template`', details: 'set `NO_PROXY` and `localhost` see `afca61a`' }, 'lodash'), ['template']);
});
