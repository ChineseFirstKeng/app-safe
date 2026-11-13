import { createHash } from 'node:crypto';
import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';

export function registerExamples(server: McpServer): void {
  const annotations = { readOnlyHint: true, openWorldHint: false };
  server.registerTool('add_numbers', {
    description: '演示工具：计算两个数字的和，验证数值参数传递。',
    inputSchema: z.object({ a: z.number().min(-1e12).max(1e12), b: z.number().min(-1e12).max(1e12) }),
    outputSchema: z.object({ sum: z.number() }), annotations,
  }, async ({ a, b }) => {
    const result = { sum: a + b };
    return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result };
  });

  server.registerTool('text_sha256', {
    description: '计算输入文本的 UTF-8 SHA-256 摘要；文本会发送到远程服务，不读取本地文件。',
    inputSchema: z.object({ text: z.string().max(65536).describe('待计算摘要的文本') }),
    outputSchema: z.object({ algorithm: z.literal('SHA-256'), digest: z.string(), bytes: z.number() }), annotations,
  }, async ({ text }) => {
    const result = { algorithm: 'SHA-256' as const, digest: createHash('sha256').update(text, 'utf8').digest('hex'), bytes: Buffer.byteLength(text, 'utf8') };
    return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result };
  });

  server.registerTool('inspect_package_filename', {
    description: '演示工具：仅根据文件名后缀识别 APK、AAB 或 IPA 类型，不上传或读取文件，不执行安全扫描。',
    inputSchema: z.object({ filename: z.string().trim().min(1).max(255).describe('文件名，例如 demo.apk') }),
    outputSchema: z.object({ filename: z.string(), format: z.enum(['apk', 'aab', 'ipa', 'unknown']), platform: z.enum(['Android', 'iOS', 'unknown']), scanned: z.literal(false) }), annotations,
  }, async ({ filename }) => {
    const suffix = filename.toLowerCase().split('.').at(-1);
    const format = filename.includes('.') && (suffix === 'apk' || suffix === 'aab' || suffix === 'ipa') ? suffix : 'unknown';
    const platform = format === 'ipa' ? 'iOS' : format === 'unknown' ? 'unknown' : 'Android';
    const result = { filename, format, platform, scanned: false as const };
    return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result };
  });
}
