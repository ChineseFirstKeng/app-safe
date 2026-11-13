import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { createServer } from './server.js';

// stdout 专供 MCP JSON-RPC 协议使用，诊断日志只能输出到 stderr。
serveStdio(() => createServer('stdio'));
console.error('[app-security-mcp] listening on stdio');
