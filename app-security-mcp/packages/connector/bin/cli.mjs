#!/usr/bin/env node
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { Server } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';

if (process.argv.includes('--help')) {
  console.log('App Security MCP 0.3.0\nUsage:\n  app-security-mcp setup --client codex [--dry-run] [--url HTTPS_URL]\n  app-security-mcp doctor --client codex\n  app-security-mcp             (stdio connector)\n\nSetup installs MCP configuration only; workflow instructions are provided by the MCP server. Token input is hidden; existing credentials are reused.\nOptional environment: MCP_URL, MCP_AUTH_TOKEN, CODEX_HOME\nRequires Node.js 22+.');
  process.exit(0);
}
if (process.argv.includes('--version')) {
  console.log('0.3.0');
  process.exit(0);
}
if (['setup', 'doctor'].includes(process.argv[2])) {
  const { runSetup, parseOptions, SetupError } = await import('./setup.mjs');
  try {
    await runSetup(process.argv[2], parseOptions(process.argv.slice(3)));
  } catch (error) {
    console.error(error instanceof SetupError ? error.message : `安装/诊断失败（${error.code ?? 'internal error'}）。未输出凭证，请检查文件权限和备份。`);
    process.exitCode = 1;
  }
  process.exit(process.exitCode ?? 0);
}
if (process.argv.length > 2) {
  console.error('Unknown argument. Use --help.');
  process.exit(1);
}

const remote = new Client({ name: 'app-security-connector', version: '0.3.0' });
const local = new Server({ name: 'app-security-mcp', version: '0.3.0' }, { capabilities: { tools: {} } });
let closing = false;
async function close() {
  if (closing) return;
  closing = true;
  await Promise.allSettled([local.close(), remote.close()]);
}
process.once('SIGINT', () => { void close(); });
process.once('SIGTERM', () => { void close(); });
local.onclose = () => { void close(); };

try {
  const url = new URL(process.env.MCP_URL ?? 'https://www.hunluanshuihu.icu/mcp');
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) || url.username || url.password) {
    throw new Error('Remote MCP URL must use HTTPS and must not contain credentials');
  }
  const headers = process.env.MCP_AUTH_TOKEN ? { Authorization: `Bearer ${process.env.MCP_AUTH_TOKEN}` } : {};
  const transport = new StreamableHTTPClientTransport(url, { requestInit: { headers } });
  await remote.connect(transport, { timeout: 15000 });
  // 工具定义实时来自远程服务；服务端新增工具无需重新发布安装包。
  local.setRequestHandler('tools/list', request => remote.listTools(request.params));
  local.setRequestHandler('tools/call', async request => {
    try {
      return await remote.callTool(request.params);
    } catch {
      // 避免将包含请求头等上下文的网络错误暴露给宿主。
      return { isError: true, content: [{ type: 'text', text: 'Remote tool call failed. Check connection and credentials, then retry.' }] };
    }
  });
  await local.connect(new StdioServerTransport());
  console.error('[app-security-mcp] connected to hosted tools');
} catch {
  console.error('[app-security-mcp] Connection failed. Check MCP_URL, network and MCP_AUTH_TOKEN if required.');
  process.exitCode = 1;
  await close();
}
