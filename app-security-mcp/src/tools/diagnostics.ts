import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';

export function registerDiagnostics(server: McpServer, transport: 'stdio' | 'streamable-http'): void {
  server.registerTool('health_check', {
    description: '检查 App 安全 MCP 服务链路是否正常。仅返回服务状态，不执行安全扫描。',
    inputSchema: z.object({}),
    outputSchema: z.object({ status: z.literal('ok'), transport: z.enum(['stdio', 'streamable-http']) }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async () => {
    const result = { status: 'ok' as const, transport };
    return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result };
  });

  server.registerTool('echo', {
    description: '原样返回输入消息，用于验证 MCP 参数传入、校验和结果返回。',
    inputSchema: z.object({ message: z.string().min(1).max(4096).describe('需要回显的消息') }),
    outputSchema: z.object({ message: z.string() }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ message }) => ({
    content: [{ type: 'text', text: message }],
    structuredContent: { message },
  }));
}
