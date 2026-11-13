import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { request } from 'node:http';
import { test } from 'node:test';
import { verifySkills } from './helpers/skills.mjs';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createHttpApp, readConfig } from '../dist/http.js';

const token = randomBytes(32).toString('hex');

test('HTTP configuration rejects missing secrets and insecure public URLs', () => {
  const valid = { MCP_AUTH_TOKEN: token, MCP_PUBLIC_URL: 'https://mcp.example.com/mcp' };
  assert.equal(readConfig(valid).port, 3000);
  for (const overrides of [
    { MCP_AUTH_TOKEN: undefined }, { MCP_AUTH_TOKEN: 'short' },
    { MCP_PUBLIC_URL: undefined }, { MCP_PUBLIC_URL: 'http://mcp.example.com/mcp' },
    { MCP_PUBLIC_URL: 'https://mcp.example.com/' }, { PORT: '0' }, { PORT: 'abc' },
  ]) assert.throws(() => readConfig({ ...valid, ...overrides }));
});

test('HTTP authentication, origin/host validation, real clients and remote smoke script', { timeout: 30000 }, async t => {
  const config = readConfig({ MCP_AUTH_TOKEN: token, MCP_PUBLIC_URL: 'http://127.0.0.1/mcp' });
  const app = createHttpApp(config);
  app.server.listen(0, '127.0.0.1');
  await once(app.server, 'listening');
  const base = `http://127.0.0.1:${app.server.address().port}`;
  config.publicUrl = new URL(`${base}/mcp`);
  t.after(() => app.close());
  const url = `${base}/mcp`;
  const auth = { Authorization: `Bearer ${token}` };

  assert.equal((await fetch(`${base}/healthz`)).status, 200);
  assert.equal((await fetch(`${base}/unknown`)).status, 404);
  for (const headers of [{}, { Authorization: 'Bearer wrong' }]) {
    const response = await fetch(url, { method: 'POST', headers });
    assert.equal(response.status, 401);
    assert.match(response.headers.get('www-authenticate'), /^Bearer /);
  }
  assert.equal((await fetch(url, { method: 'POST', headers: { ...auth, Origin: 'https://evil.example' } })).status, 403);
  const badHostStatus = await new Promise((resolve, reject) => {
    const req = request(url, { method: 'POST', headers: { ...auth, Host: 'evil.example' } }, res => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on('error', reject);
    req.end();
  });
  assert.equal(badHostStatus, 403);

  for (const mode of ['legacy', 'auto']) {
    const client = new Client({ name: `http-test-${mode}`, version: '0.1.0' });
    const transport = new StreamableHTTPClientTransport(new URL(url), {
      requestInit: { headers: { ...auth, Origin: base } },
    });
    try {
      await client.connect(transport, { mode });
      assert.equal(client.getServerVersion().name, 'app-security-mcp');
      await verifySkills(client);
      const { tools } = await client.listTools();
      assert.deepEqual(tools.map(tool => tool.name).sort(), ['add_numbers', 'echo', 'get_workflow', 'health_check', 'inspect_package_filename', 'text_sha256']);
      const results = await Promise.all(Array.from({ length: 4 }, (_, i) =>
        client.callTool({ name: 'echo', arguments: { message: `中文并发 ${i}` } })));
      results.forEach((result, i) => assert.deepEqual(result.structuredContent, { message: `中文并发 ${i}` }));
      const invalid = await client.callTool({ name: 'echo', arguments: { message: '' } });
      assert.equal(invalid.isError, true);
      const health = await client.callTool({ name: 'health_check', arguments: {} });
      assert.deepEqual(health.structuredContent, { status: 'ok', transport: 'streamable-http' });
    } finally {
      await client.close();
      await transport.close();
    }
  }
  const malformed = await fetch(url, {
    method: 'POST', headers: { ...auth, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: '{',
  });
  assert.equal(malformed.status, 400);
  const oversized = await fetch(url, {
    method: 'POST', headers: { ...auth, 'Content-Type': 'application/json' }, body: 'x'.repeat(1024 * 1024 + 1),
  });
  assert.equal(oversized.status, 413);

  const child = spawn(process.execPath, ['scripts/smoke-remote.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: { ...process.env, MCP_URL: url, MCP_AUTH_TOKEN: token },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => child.kill());
  let output = '';
  child.stdout.on('data', data => { output += data; });
  child.stderr.on('data', data => { output += data; });
  const [code] = await once(child, 'exit');
  assert.equal(code, 0, output);
  assert.match(output, /PASS:/);
});
