import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { cacheDir } from '../util/cache.js';

const PAGE = fileURLToPath(new URL('./index.html', import.meta.url));

function openBrowser(url) {
  const [cmd, args] =
    process.platform === 'darwin' ? ['open', [url]] : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]] : ['xdg-open', [url]];
  try {
    spawn(cmd, args, { stdio: 'ignore', detached: true }).unref();
  } catch {}
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Each running dashboard records {pid, port, secret, root} in a user-only file, so a newer run can
// ask it to stop. Only someone who can read that file knows the secret, so websites can't do it.
const lockFile = (port) => path.join(cacheDir, `dashboard-${port}.json`);

function portFree(port) {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.listen(port, '127.0.0.1', () => probe.close(() => resolve(true)));
  });
}

/** Ask the dashboard holding `port` to shut down. Returns its lock info if it stopped, else null. */
async function stopPrevious(port) {
  let info;
  try {
    info = JSON.parse(fs.readFileSync(lockFile(port), 'utf8'));
  } catch {
    return null; // not one of ours (or from a version without this feature)
  }
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/shutdown`, {
      method: 'POST',
      headers: { 'x-iamsecure-shutdown': info.secret },
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) return null;
  } catch {
    return null;
  }
  for (let i = 0; i < 40; i++) {
    if (await portFree(port)) return info;
    await sleep(100);
  }
  return null;
}

function listen(server, port, attempts = 20) {
  // One 'listening' handler that reads the port actually bound. (A callback per attempt would
  // also fire for the failed attempts and report the busy port — opening another dashboard.)
  return new Promise((resolve, reject) => {
    let p = port;
    const onError = (err) => {
      if (err.code === 'EADDRINUSE' && attempts-- > 0) server.listen(++p, '127.0.0.1');
      else {
        server.off('listening', onListening);
        reject(err);
      }
    };
    const onListening = () => {
      server.off('error', onError);
      resolve(server.address().port);
    };
    server.on('error', onError);
    server.once('listening', onListening);
    server.listen(p, '127.0.0.1');
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
  const shutdownSecret = crypto.randomBytes(24).toString('hex');
  let busy = false;
  let lockPath = null;
  const removeLock = () => {
    try {
      if (lockPath && JSON.parse(fs.readFileSync(lockPath, 'utf8')).pid === process.pid) fs.unlinkSync(lockPath);
    } catch {}
  };

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
    if (req.method === 'POST' && url.pathname === '/api/shutdown') {
      if (req.headers['x-iamsecure-shutdown'] !== shutdownSecret) return send(403, { error: 'forbidden' });
      send(200, { ok: true });
      console.log('\nThis dashboard was replaced by a newer `iamsecure --ui` run. Stopping.');
      removeLock();
      server.close();
      setTimeout(() => process.exit(0), 100);
      return;
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

  // Replace an older iamsecure dashboard on the same port instead of piling up new ones.
  const replaced = (await portFree(port)) ? null : await stopPrevious(port);

  const actual = await listen(server, port);
  lockPath = lockFile(actual);
  try {
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(lockPath, JSON.stringify({ pid: process.pid, port: actual, secret: shutdownSecret, root: report.project.root, startedAt: new Date().toISOString() }), { mode: 0o600 });
  } catch {}
  process.once('exit', removeLock);
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.once(sig, () => {
      removeLock();
      process.exit(sig === 'SIGINT' ? 130 : 0);
    });
  }

  const url = `http://localhost:${actual}/`;
  if (open) openBrowser(url);
  return { url, server, replaced };
}
