import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { createHttpApp, readConfig } from '../dist/http.js';

test('installable connector forwards actual remote tools and validation errors', { timeout: 20000 }, async t => {
  const token = randomBytes(32).toString('hex');
  const app = createHttpApp(readConfig({ MCP_AUTH_TOKEN: token, MCP_PUBLIC_URL: 'http://127.0.0.1/mcp' }));
  app.server.listen(0, '127.0.0.1');
  await once(app.server, 'listening');
  t.after(() => app.close());
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL('../packages/connector/bin/cli.mjs', import.meta.url))],
    env: { ...process.env, MCP_URL: `http://127.0.0.1:${app.server.address().port}/mcp`, MCP_AUTH_TOKEN: token },
    stderr: 'pipe',
  });
  const client = new Client({ name: 'connector-test', version: '0.1.0' });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map(tool => tool.name).sort(), ['add_numbers', 'echo', 'get_workflow', 'health_check', 'inspect_package_filename', 'text_sha256']);
    const health = await client.callTool({ name: 'health_check', arguments: {} });
    assert.deepEqual(health.structuredContent, { status: 'ok', transport: 'streamable-http' });
    const echo = await client.callTool({ name: 'echo', arguments: { message: '安装包 → 远程服务' } });
    assert.deepEqual(echo.structuredContent, { message: '安装包 → 远程服务' });
    const invalid = await client.callTool({ name: 'echo', arguments: { message: '' } });
    assert.equal(invalid.isError, true);
  } finally {
    await client.close();
    await transport.close();
  }
});
