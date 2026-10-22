#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { scan, summarize, sortFindings, VERSION } from '../src/scan.js';
import { aiReview, makeAnalyzer } from '../src/ai/index.js';
import { printReport, c } from '../src/report/terminal.js';
import { serveDashboard } from '../src/ui/server.js';
import { toSarif } from '../src/report/sarif.js';

const HELP = `
${c.bold('iamsecure')} — find vulnerable dependencies and insecure code, ranked by real-world risk

${c.bold('Usage')}
  npx iamsecure [path] [options]

${c.bold('Options')}
  --sort <risk|severity>   risk = worst for THIS codebase first (default); severity = raw CVSS high → low
  --min <level>            only show findings at or above critical|high|medium|low
  --limit <n>              max findings printed in the terminal (default 30)
  --ui                     open the interactive report in your browser (localhost only)
  --port <n>               dashboard port (default 4477; next free port is used if taken)
  --no-open                with --ui: don't launch the browser, just print the URL
  --json [file]            write the full report as JSON (default iamsecure-report.json)
  --sarif [file]           write SARIF for GitHub/GitLab code scanning (default iamsecure.sarif)
  --fail-on <level>        exit 1 if any finding's real risk is at/above critical|high|medium|low (CI)

${c.bold('AI validation')} (optional — only code snippets around each finding are sent, never the whole repo)
  --ai <provider>          claude-cli (uses your Claude Code login) | anthropic (ANTHROPIC_API_KEY)
                           | openai (OPENAI_API_KEY, OPENAI_BASE_URL for compatible APIs) | ollama (local)
  --ai-model <id>          override the provider's default model
  --ai-max <n>             how many top findings to review (default 15)
  --ai-dry-run             print the prompts that would be sent, send nothing
  --no-deps                skip the dependency scan
  --no-code                skip source analysis (exposure then becomes "unknown")
  --offline-intel          skip CISA KEV / EPSS lookups
  -v, --version            print version
  -h, --help               show this help

${c.bold('Examples')}
  npx iamsecure                       scan the current directory
  npx iamsecure ../my-next-app --sort severity
  npx iamsecure --ui                  interactive dashboard on http://localhost:4477
  npx iamsecure --ai claude-cli       let Claude double-check the top 15 findings
`;

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    sort: { type: 'string', default: 'risk' },
    min: { type: 'string' },
    limit: { type: 'string', default: '30' },
    json: { type: 'string' },
    sarif: { type: 'string' },
    'fail-on': { type: 'string' },
    ui: { type: 'boolean', default: false },
    port: { type: 'string', default: '4477' },
    'no-open': { type: 'boolean', default: false },
    ai: { type: 'string' },
    'ai-model': { type: 'string' },
    'ai-max': { type: 'string', default: '15' },
    'ai-dry-run': { type: 'boolean', default: false },
    'no-deps': { type: 'boolean', default: false },
    'no-code': { type: 'boolean', default: false },
    'offline-intel': { type: 'boolean', default: false },
    version: { type: 'boolean', short: 'v' },
    help: { type: 'boolean', short: 'h' },
  },
  // `--json` / `--sarif` with no value are allowed; parseArgs needs a value, so patch argv below.
  args: process.argv.slice(2).flatMap((a, i, arr) => {
    const defaults = { '--json': 'iamsecure-report.json', '--sarif': 'iamsecure.sarif' };
    return defaults[a] && (arr[i + 1] === undefined || arr[i + 1].startsWith('-')) ? [a, defaults[a]] : [a];
  }),
});

if (values.help) {
  console.log(HELP);
  process.exit(0);
}
if (values.version) {
  console.log(VERSION);
  process.exit(0);
}

const root = path.resolve(positionals[0] ?? '.');
if (!fs.existsSync(root)) {
  console.error(`Path not found: ${root}`);
  process.exit(2);
}

const log = (m) => process.stderr.write(c.dim(`› ${m}\n`));

const runScan = async () => {
  const report = await scan(root, { deps: !values['no-deps'], code: !values['no-code'], exploit: !values['offline-intel'], log });
  if (values.ai) {
    await aiReview(report, { provider: values.ai, model: values['ai-model'], max: Number(values['ai-max']), dryRun: values['ai-dry-run'], log });
    report.summary = summarize(report.findings);
    report.findings = sortFindings(report.findings, 'risk');
  }
  return report;
};

try {
  const report = await runScan();
  printReport(report, { sort: values.sort, limit: values.ui ? Math.min(Number(values.limit), 10) : Number(values.limit), min: values.min });
  if (values.json) {
    fs.writeFileSync(values.json, JSON.stringify(report, null, 2));
    log(`JSON report written to ${values.json}`);
  }
  if (values.sarif) {
    fs.writeFileSync(values.sarif, JSON.stringify(toSarif(report), null, 2));
    log(`SARIF report written to ${values.sarif}`);
  }
  const order = ['critical', 'high', 'medium', 'low'];
  if (values['fail-on'] && !values.ui) {
    if (!order.includes(values['fail-on'])) throw new Error(`--fail-on must be one of ${order.join(', ')}`);
    const failing = report.findings.filter((f) => order.indexOf(f.risk) !== -1 && order.indexOf(f.risk) <= order.indexOf(values['fail-on']));
    if (failing.length) {
      console.error(c.red(`✖ ${failing.length} finding(s) at or above "${values['fail-on']}" real risk.`));
      process.exitCode = 1;
    }
  }
  if (values.ui) {
    const { url } = await serveDashboard(report, {
      port: Number(values.port),
      open: !values['no-open'],
      rescan: runScan,
      aiProvider: values.ai ?? null,
      analyze: values.ai ? makeAnalyzer({ provider: values.ai, model: values['ai-model'] }) : undefined,
    });
    console.log(`\n${c.bold('Dashboard:')} ${c.cyan(url)}  ${c.dim('(Ctrl+C to stop)')}`);
  }
} catch (err) {
  console.error(c.red(`iamsecure failed: ${err.stack ?? err.message}`));
  process.exit(2);
}
