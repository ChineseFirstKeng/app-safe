import { readFile } from 'node:fs/promises';
import { SkillsExtension, memorySkillFiles } from '@modelcontextprotocol/server/ext/skills';
import * as z from 'zod/v4';
import { McpServer } from '@modelcontextprotocol/server';
import { registerDiagnostics } from './tools/diagnostics.js';
import { registerCapabilities } from './tools/capabilities.js';
import { registerScans } from './tools/scans.js';
import { registerArtifacts } from './tools/artifacts.js';
import { registerExamples } from './tools/examples.js';

export const SERVER_INFO = { name: 'app-security-mcp', version: '0.3.0' };

// Resolve against this module, independent of the client working directory.
// Codex plugin names may contain colons; the MCP Skills extension has a separate name contract.
// Publish the existing portable workflow only; platform entries are registered by the plugin.
const skills = await SkillsExtension.load(memorySkillFiles({
  'app-security/SKILL.md': await readFile(new URL('../skills/app-security/SKILL.md', import.meta.url), 'utf8'),
}), { strict: true });

export function createServer(transport: 'stdio' | 'streamable-http' = 'stdio'): McpServer {
  const server = new McpServer(SERVER_INFO, { instructions: 'App Security MCP：操作流程由本服务提供，无需安装本地 Skill。验证整条链路时先读取 get_workflow，再按说明调用工具。支持 Skills 扩展的客户端也可发现并读取 skill://app-security/SKILL.md。' });
  skills.attach(server);
  server.registerTool('get_workflow', {
    description: '读取 App Security 的操作说明。检查整条 MCP 链路或不确定工具用法时先调用；说明由 MCP 提供，无需本地 Skill。',
    inputSchema: z.object({}),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async () => ({ content: [{ type: 'text' as const, text: await readFile(new URL('../skills/app-security/SKILL.md', import.meta.url), 'utf8') }] }));
  registerDiagnostics(server, transport);
  registerExamples(server);
  if (transport === 'stdio') {
    registerCapabilities(server, new URL('../workers/capabilities.py', import.meta.url));
    registerArtifacts(server, new URL('../workers/artifacts.py', import.meta.url));
    registerScans(server, new URL('../workers/scan_resources.py', import.meta.url), new URL('../workers/scan_gate.py',import.meta.url));
  }
  // 后续业务工具在此注册，业务实现放入独立模块。
  return server;
}
