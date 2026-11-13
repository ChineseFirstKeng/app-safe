import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { verifySkills } from './helpers/skills.mjs';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

test('stdio: handshake, discovery, calls and invalid arguments', { timeout: 15000 }, async () => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL('../dist/index.js', import.meta.url))],
    // 验证启动不依赖客户端的工作目录。
    cwd: '/',
    stderr: 'pipe',
  });
  const client = new Client({ name: 'app-security-smoke-test', version: '0.1.0' });
  try {
    await client.connect(transport);
    assert.equal(client.getServerVersion().name, 'app-security-mcp');
      await verifySkills(client);
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map(tool => tool.name).sort(), ['add_numbers', 'cancel_scan', 'compare_scans', 'delete_imported_artifact', 'delete_scan', 'echo', 'export_report', 'get_analysis_capabilities', 'get_finding', 'get_scan_status', 'get_workflow', 'health_check', 'import_local_artifact', 'inspect_imported_artifact', 'inspect_package_filename', 'list_findings', 'read_evidence', 'scan_android_hardcoding', 'scan_ios_hardcoding', 'text_sha256', 'verify_android_finding', 'verify_android_native_finding', 'verify_ios_finding']);

    const health = await client.callTool({ name: 'health_check', arguments: {} });
    assert.notEqual(health.isError, true);
    assert.deepEqual(health.structuredContent, { status: 'ok', transport: 'stdio' });

    const message = 'App 安全 MCP 链路测试 🔒\n第二行';
    const echo = await client.callTool({ name: 'echo', arguments: { message } });
    assert.notEqual(echo.isError, true);
    assert.deepEqual(echo.structuredContent, { message });
    assert.equal(echo.content[0].text, message);

    for (const arguments_ of [{}, { message: 123 }, { message: '' }]) {
      const invalid = await client.callTool({ name: 'echo', arguments: arguments_ });
      assert.equal(invalid.isError, true);
    }
    const recovery = await client.callTool({ name: 'health_check', arguments: {} });
    assert.notEqual(recovery.isError, true);
  } finally {
    await client.close();
    await transport.close();
  }
});
