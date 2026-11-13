import { createServer as createHttpServer, type ServerResponse } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { hostHeaderValidation, toNodeHandler } from '@modelcontextprotocol/node';
import { createServer } from './server.js';

export function readConfig(env: NodeJS.ProcessEnv = process.env) {
  const token = env.MCP_AUTH_TOKEN ?? '';
  if (!/^[A-Za-z0-9_-]{32,}$/.test(token)) {
    throw new Error('MCP_AUTH_TOKEN must contain at least 32 letters, digits, underscores or hyphens');
  }
  if (!env.MCP_PUBLIC_URL) throw new Error('MCP_PUBLIC_URL is required (https://your-domain/mcp)');
  const publicUrl = new URL(env.MCP_PUBLIC_URL);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(publicUrl.hostname);
  if ((publicUrl.protocol !== 'https:' && !(local && publicUrl.protocol === 'http:')) ||
      publicUrl.pathname !== '/mcp' || publicUrl.search || publicUrl.hash || publicUrl.username || publicUrl.password) {
    throw new Error('MCP_PUBLIC_URL must be https://your-domain/mcp (HTTP allowed only for localhost)');
  }
  const port = Number(env.PORT ?? 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be between 1 and 65535');
  return { token, publicUrl, port, host: env.HOST ?? '127.0.0.1' };
}

function json(res: ServerResponse, status: number, body: object) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

export function createHttpApp(config: ReturnType<typeof readConfig>) {
  const handler = createMcpHandler(() => createServer('streamable-http'));
  const nodeHandler = toNodeHandler(handler, {
    maxRequestBodySize: 1024 * 1024,
    onerror: () => console.error('[app-security-mcp] HTTP adapter error'),
  });
  const validateHost = hostHeaderValidation([config.publicUrl.hostname]);
  const tokenHash = createHash('sha256').update(`Bearer ${config.token}`).digest();

  const server = createHttpServer((req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // 只公开存活状态，供容器探针使用，不暴露工具或配置。
    if (req.url === '/healthz' && req.method === 'GET') {
      json(res, 200, { status: 'ok' });
      return;
    }
    if (req.url?.split('?')[0] !== '/mcp') {
      json(res, 404, { error: 'Not found' });
      return;
    }
    if (!validateHost(req, res)) return;
    // 严格匹配来源；无 Origin 的原生 MCP 客户端可正常接入。
    if (req.headers.origin !== undefined && req.headers.origin !== config.publicUrl.origin) {
      json(res, 403, { error: 'Forbidden origin' });
      return;
    }
    const suppliedHash = createHash('sha256').update(req.headers.authorization ?? '').digest();
    if (!timingSafeEqual(tokenHash, suppliedHash)) {
      res.setHeader('WWW-Authenticate', 'Bearer realm="app-security-mcp"');
      json(res, 401, { error: 'Unauthorized' });
      return;
    }
    void nodeHandler(req, res).catch(() => {
      console.error('[app-security-mcp] request failed');
      if (!res.headersSent) json(res, 500, { error: 'Internal server error' });
      else res.destroy();
    });
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 15_000;

  return {
    server,
    async close() {
      const closed = new Promise<void>((resolve, reject) => {
        server.close(error => error ? reject(error) : resolve());
      });
      await handler.close();
      server.closeAllConnections();
      await closed;
    },
  };
}
