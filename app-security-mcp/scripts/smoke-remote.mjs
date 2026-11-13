import assert from 'node:assert/strict';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

const endpoint = process.env.MCP_URL;
const token = process.env.MCP_AUTH_TOKEN;
if (!endpoint || !token) {
  console.error('Set MCP_URL and MCP_AUTH_TOKEN, then run npm run smoke:remote');
  process.exit(1);
}
const url = new URL(endpoint);
if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) {
  throw new Error('Use HTTPS for remote endpoints');
}
const client = new Client({ name: 'app-security-remote-smoke', version: '0.1.0' });
const transport = new StreamableHTTPClientTransport(url, {
  requestInit: { headers: { Authorization: `Bearer ${token}` } },
});
const deadline = setTimeout(() => {
  console.error('Remote smoke test timed out');
  process.exit(1);
}, 20000);
try {
  await client.connect(transport);
  assert.equal(client.getServerVersion().name, 'app-security-mcp');
  const { tools } = await client.listTools();
  assert.ok(tools.some(tool => tool.name === 'health_check'));
  const health = await client.callTool({ name: 'health_check', arguments: {} });
  assert.notEqual(health.isError, true);
  assert.deepEqual(health.structuredContent, { status: 'ok', transport: 'streamable-http' });
  const message = '远程 MCP 链路验证 🔒';
  const echo = await client.callTool({ name: 'echo', arguments: { message } });
  assert.notEqual(echo.isError, true);
  assert.deepEqual(echo.structuredContent, { message });
  const sum = await client.callTool({ name: 'add_numbers', arguments: { a: 12, b: 30 } });
  assert.deepEqual(sum.structuredContent, { sum: 42 });
  const hash = await client.callTool({ name: 'text_sha256', arguments: { text: 'abc' } });
  assert.deepEqual(hash.structuredContent, { algorithm: 'SHA-256', digest: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', bytes: 3 });
  const file = await client.callTool({ name: 'inspect_package_filename', arguments: { filename: 'Demo.APK' } });
  assert.deepEqual(file.structuredContent, { filename: 'Demo.APK', format: 'apk', platform: 'Android', scanned: false });
  console.log('PASS: HTTP handshake, tool discovery and all five tools');
} catch {
  console.error('FAIL: check endpoint, token, DNS/TLS and server logs');
  process.exitCode = 1;
} finally {
  await client.close();
  await transport.close();
  clearTimeout(deadline);
}
