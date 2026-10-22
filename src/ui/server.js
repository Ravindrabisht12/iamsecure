import http from 'node:http';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const PAGE = fileURLToPath(new URL('./index.html', import.meta.url));

function openBrowser(url) {
  const [cmd, args] =
    process.platform === 'darwin' ? ['open', [url]] : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]] : ['xdg-open', [url]];
  try {
    spawn(cmd, args, { stdio: 'ignore', detached: true }).unref();
  } catch {}
}

function listen(server, port, attempts = 20) {
  return new Promise((resolve, reject) => {
    const tryPort = (p, left) => {
      server.once('error', (err) => {
        if (err.code === 'EADDRINUSE' && left > 0) tryPort(p + 1, left - 1);
        else reject(err);
      });
      server.listen(p, '127.0.0.1', () => resolve(p));
    };
    tryPort(port, attempts);
  });
}

/**
 * Serve the dashboard for a report. Bound to 127.0.0.1 only; every API call needs the session
 * token and a localhost Host header so other sites can't read the report (DNS rebinding / CSRF).
 * @param {any} initialReport
 * @param {{port?: number, open?: boolean, rescan?: () => Promise<any>, analyze?: (findingId: string) => Promise<any>, aiProvider?: string|null}} opts
 */
export async function serveDashboard(initialReport, { port = 4477, open = true, rescan, analyze, aiProvider = null } = {}) {
  let report = initialReport;
  const token = crypto.randomBytes(16).toString('hex');
  let busy = false;

  const server = http.createServer(async (req, res) => {
    const host = (req.headers.host ?? '').split(':')[0];
    if (!['127.0.0.1', 'localhost'].includes(host)) {
      res.writeHead(403).end('Forbidden');
      return;
    }
    const send = (status, body, type = 'application/json') => {
      res.writeHead(status, {
        'content-type': type,
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        'content-security-policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:",
      });
      res.end(type === 'application/json' ? JSON.stringify(body) : body);
    };
    const url = new URL(req.url, 'http://localhost');

    if (req.method === 'GET' && url.pathname === '/') {
      const html = fs
        .readFileSync(PAGE, 'utf8')
        .replace('__IAMSECURE_TOKEN__', token)
        .replace('__IAMSECURE_AI__', JSON.stringify(aiProvider));
      return send(200, html, 'text/html; charset=utf-8');
    }
    if (!url.pathname.startsWith('/api/')) return send(404, { error: 'not found' });
    if (req.headers['x-iamsecure-token'] !== token) return send(401, { error: 'bad token' });

    try {
      if (req.method === 'GET' && url.pathname === '/api/report') return send(200, report);
      if (req.method === 'POST' && url.pathname === '/api/rescan' && rescan) {
        if (busy) return send(409, { error: 'A scan is already running' });
        busy = true;
        try {
          report = await rescan();
        } finally {
          busy = false;
        }
        return send(200, report);
      }
      if (req.method === 'POST' && url.pathname === '/api/analyze' && analyze) {
        const id = url.searchParams.get('id');
        const finding = report.findings.find((f) => f.id === id);
        if (!finding) return send(404, { error: 'unknown finding' });
        const ai = await analyze(finding, report);
        return send(200, finding.ai ? finding : { ...finding, ai });
      }
      send(404, { error: 'not found' });
    } catch (err) {
      send(500, { error: err.message });
    }
  });

  const actual = await listen(server, port);
  const url = `http://localhost:${actual}/`;
  if (open) openBrowser(url);
  return { url, server };
}
