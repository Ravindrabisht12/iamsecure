import { spawnSync } from 'node:child_process';
import { levelFromScore } from '../deps/cvss.js';

const PATTERNS = [
  { id: 'aws-access-key', title: 'AWS access key ID', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/, sev: 9 },
  { id: 'aws-secret-key', title: 'AWS secret access key', re: /aws_?secret_?access_?key['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})\b/i, sev: 9.5 },
  { id: 'github-token', title: 'GitHub token', re: /\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b/, sev: 9 },
  { id: 'gitlab-token', title: 'GitLab personal access token', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/, sev: 9 },
  { id: 'npm-token', title: 'npm access token (can publish packages!)', re: /\bnpm_[A-Za-z0-9]{36}\b/, sev: 9.5 },
  { id: 'slack-token', title: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, sev: 8 },
  { id: 'slack-webhook', title: 'Slack webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, sev: 6.5 },
  { id: 'stripe-secret', title: 'Stripe live secret key', re: /\b(sk|rk)_live_[A-Za-z0-9]{20,}\b/, sev: 9.5 },
  { id: 'openai-key', title: 'OpenAI API key', re: /\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|\bsk-(proj|svcacct|admin)-[A-Za-z0-9_-]{40,}\b/, sev: 8.5 },
  { id: 'anthropic-key', title: 'Anthropic API key', re: /\bsk-ant-(api|admin)\d{2}-[A-Za-z0-9_-]{60,}\b/, sev: 8.5 },
  { id: 'google-api-key', title: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/, sev: 5.5 },
  { id: 'sendgrid-key', title: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/, sev: 8 },
  { id: 'twilio-key', title: 'Twilio API key', re: /\bSK[0-9a-f]{32}\b/, sev: 7 },
  { id: 'private-key', title: 'Private key', re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/, sev: 9 },
  { id: 'db-url-password', title: 'Database URL with password', re: /\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^:\s'"/@]+:([^@\s'"]{3,})@[^\s'"]+/, sev: 8, group: 2 },
  { id: 'jwt-literal', title: 'Hard-coded JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, sev: 5 },
];

const GENERIC =
  /\b([A-Za-z0-9_]*(?:secret|password|passwd|pwd|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)[A-Za-z0-9_]*)['"]?\s*[:=]\s*['"]([^'"\s]{8,})['"]/i;

const PLACEHOLDER =
  /^(\$\{|<|\{\{|%|process\.env|env\(|xxx|\*{3}|changeme|change_me|your[_-]|example|sample|dummy|placeholder|password|secret|test|todo|null|undefined|none|redacted|replace)|(xxx|\.\.\.|example|your_|_here|placeholder)$/i;

function entropy(s) {
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] ?? 0) + 1;
  return -Object.values(freq).reduce((h, n) => h + (n / s.length) * Math.log2(n / s.length), 0);
}

const mask = (s) => (s.length <= 8 ? '****' : `${s.slice(0, 4)}…${s.slice(-2)} (${s.length} chars)`);

function trackedFiles(root) {
  const r = spawnSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' });
  if (r.status !== 0) return null;
  return new Set(r.stdout.split('\0').filter(Boolean));
}

function gitIgnored(root, files) {
  if (!files.length) return new Set();
  const r = spawnSync('git', ['check-ignore', '--stdin'], { cwd: root, input: files.join('\n'), encoding: 'utf8' });
  return new Set((r.stdout ?? '').split('\n').filter(Boolean));
}

/**
 * Hard-coded credentials in source/config, and .env files that are (or could easily be) committed.
 * @param {{files:any[], texts:Map<string,string>, contexts:Map<string,string>}} src
 * @param {string} root
 */
export function scanSecrets(src, root) {
  const findings = [];
  const tracked = trackedFiles(root);
  const envFiles = src.files.filter((f) => f.kind === 'env').map((f) => f.rel);
  const ignored = tracked ? gitIgnored(root, envFiles) : new Set();

  for (const f of src.files) {
    const text = src.texts.get(f.rel);
    if (!text || /(^|\/)(test|tests|__tests__|fixtures?|__mocks__)\//.test(f.rel) && f.kind !== 'env') continue;
    const context = src.contexts.get(f.rel) ?? (f.kind === 'env' ? 'server' : 'build');

    let envState = null;
    if (f.kind === 'env') {
      if (tracked?.has(f.rel)) envState = 'committed';
      else if (tracked && !ignored.has(f.rel)) envState = 'not-ignored';
      else continue; // gitignored local .env (or not a git repo) is the expected setup
    }

    const lines = text.split('\n');
    const seen = new Set();
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 500) continue;
      let hit = null;
      for (const p of PATTERNS) {
        const m = p.re.exec(line);
        if (m) {
          hit = { id: p.id, title: p.title, sev: p.sev, value: m[p.group ?? 0] };
          break;
        }
      }
      if (!hit) {
        const m = GENERIC.exec(line) ?? (f.kind === 'env' ? /^\s*([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|PRIVATE_KEY|CLIENT_SECRET)[A-Z0-9_]*)\s*=\s*['"]?([^'"\s#]{8,})/i.exec(line) : null);
        if (m && !PLACEHOLDER.test(m[2]) && entropy(m[2]) >= 3 && !/^[a-z]+([._-][a-z]+)*$/i.test(m[2])) {
          hit = { id: 'generic-secret', title: `Hard-coded secret in "${m[1]}"`, sev: 6.5, value: m[2] };
        }
      }
      if (!hit || PLACEHOLDER.test(hit.value) || seen.has(hit.value)) continue;
      seen.add(hit.value);

      let sev = hit.sev;
      let title = hit.title;
      if (envState === 'committed') {
        sev = Math.max(sev, 8);
        title = `${hit.title} in committed ${f.rel}`;
      } else if (envState === 'not-ignored') {
        sev = Math.min(sev, 6);
        title = `${hit.title} in ${f.rel}, which is not gitignored`;
      }
      findings.push({
        id: `secret:${hit.id}:${f.rel}:${i + 1}`,
        kind: 'secret',
        title,
        ruleId: `secret-${hit.id}`,
        category: 'secret',
        cwe: 'CWE-798',
        severityScore: sev,
        severity: levelFromScore(sev),
        confidence: hit.id === 'generic-secret' ? 'medium' : 'high',
        context,
        location: { file: f.rel, line: i + 1, snippet: line.replace(hit.value, mask(hit.value)).trim().slice(0, 200) },
        fix:
          envState === 'not-ignored'
            ? `Add ${f.rel} to .gitignore before it gets committed.`
            : `Rotate this credential now (assume it is compromised), move it to an env var / secret manager${envState === 'committed' ? `, untrack the file (git rm --cached ${f.rel}) and purge it from history` : ''}.`,
      });
    }
  }
  return findings;
}
