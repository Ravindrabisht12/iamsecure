// Attack surface: does this app accept connections from the network, or is it a local process
// (CLI, stdio MCP server, IDE extension) that only talks to the user who started it?
//
// "Runs on the server" is not the same as "reachable by attackers over the internet". A request-parsing
// DoS in express only matters if something actually calls listen().

const LISTENERS = [
  { what: 'HTTP server', re: /\b(?:https?|http2)\s*\.\s*create(?:Secure)?Server\s*\(|\bcreateServer\s*\(/ },
  { what: '.listen() call', re: /\.\s*listen\s*\(\s*(?:[\w$.]*port\b|\d{2,5}\b|process\.env\.)/i },
  { what: 'Express app', re: /\bexpress\s*\(\s*\)/ },
  { what: 'Fastify app', re: /\bfastify\s*\(\s*[{)]/i },
  { what: 'Koa app', re: /\bnew\s+Koa\s*\(/ },
  { what: 'Hapi server', re: /\bHapi\s*\.\s*server\s*\(/ },
  { what: 'Hono server', re: /\bserve\s*\(\s*\{[^}]*\bfetch\b/ },
  { what: 'Bun/Deno server', re: /\b(?:Bun|Deno)\s*\.\s*serve\s*\(/ },
  { what: 'WebSocket server', re: /\bnew\s+(?:WebSocket\.)?(?:WebSocketServer|Server)\s*\(\s*\{[^}]*\b(?:port|server)\b/ },
  { what: 'MCP HTTP transport', re: /\bnew\s+(?:StreamableHTTPServerTransport|SSEServerTransport)\s*\(|\bcreateMcpExpressApp\s*\(/ },
  { what: 'NestJS app', re: /\bNestFactory\s*\.\s*create\s*\(/ },
  { what: 'Python web server', re: /\buvicorn\.run\s*\(|\bapp\.run\s*\(|\bweb\.run_app\s*\(|\bserve_forever\s*\(/ },
];

const LOCAL = [
  { what: 'MCP stdio transport', re: /\bnew\s+StdioServerTransport\s*\(/ },
  { what: 'reads commands from stdin', re: /\bprocess\.stdin\b/ },
];

// Frameworks that always serve HTTP even when no file calls listen() itself.
const NETWORK_FRAMEWORKS = new Set(['next', 'nuxt', 'remix', 'sveltekit', 'astro', 'node-server', 'laravel', 'symfony', 'django', 'fastapi', 'flask']);

/**
 * @param {{framework: string, manifest: any}} project
 * @param {{files: {rel:string, kind:string, context?:string}[], texts: Map<string,string>}} src
 * @returns {{kind: 'network'|'local'|'unknown', evidence: string[]}}
 *   network = something accepts connections; local = only a CLI/stdio entry point and no listener found.
 */
export function detectSurface(project, src) {
  const listeners = [];
  const local = [];
  for (const f of src.files) {
    if (f.kind !== 'code' || f.context === 'build') continue;
    const text = src.texts.get(f.rel);
    if (!text) continue;
    for (const [list, rules] of [[listeners, LISTENERS], [local, LOCAL]]) {
      for (const r of rules) {
        const m = r.re.exec(text);
        if (m) list.push(`${r.what} in ${f.rel}:${text.slice(0, m.index).split('\n').length}`);
      }
    }
  }

  if (listeners.length) return { kind: 'network', evidence: listeners.slice(0, 3) };
  if (NETWORK_FRAMEWORKS.has(project.framework)) return { kind: 'network', evidence: [`${project.framework} serves HTTP`] };

  const bin = project.manifest?.bin;
  if (bin) local.push(`package.json "bin" (${typeof bin === 'string' ? bin : Object.keys(bin).join(', ')})`);
  // A library with no entry point of its own is "unknown": whoever imports it decides whether it's exposed.
  if (local.length) return { kind: 'local', evidence: local.slice(0, 3) };
  return { kind: 'unknown', evidence: [] };
}

const SERVER_PACKAGES = ['express', 'fastify', 'koa', '@hapi/hapi', 'hono', '@hono/node-server', 'ws', 'socket.io', '@nestjs/core', 'restify', 'polka', 'h3'];

/**
 * Safety net for listeners the patterns above miss: if a server framework is actually loaded at runtime,
 * don't call the app local.
 * @param {ReturnType<typeof detectSurface>} surface
 * @param {{available: boolean, loaded: Map<string, {chain: string[]}>}|null} modules
 */
export function confirmSurface(surface, modules) {
  if (surface.kind !== 'local' || !modules?.available) return surface;
  for (const [key, { chain }] of modules.loaded) {
    const name = key.slice(0, key.lastIndexOf('@'));
    if (SERVER_PACKAGES.includes(name)) return { kind: 'network', evidence: [`${name} is loaded at runtime (${chain.join(' → ')})`] };
  }
  return surface;
}
