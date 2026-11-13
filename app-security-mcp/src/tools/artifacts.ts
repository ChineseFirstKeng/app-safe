import { randomUUID } from 'node:crypto';
import { rm, readdir, readFile, lstat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';

import { withArtifactLock } from './storage-lock.js';

// Inject the worker URL at the server entry; bundling does not change its relative root.
export function registerArtifacts(server: McpServer, worker: URL): void {
  let busy = false;
  async function run(input: Record<string, unknown>) {
    if (busy) return failure('artifact_operation_busy');
    busy = true;
    const storageRoot = process.env.APP_SECURITY_DATA_DIR ?? join(homedir(), '.app-security', 'artifacts');
    const importId = randomUUID().replaceAll('-', '');
    try {
      return await new Promise<any>((resolve) => {
        const child = spawn(process.env.APP_SECURITY_PYTHON ?? 'python3', [fileURLToPath(worker)], { stdio: ['pipe', 'pipe', 'pipe'] });
        let output = '', bytes = 0, settled = false;
        const finish = (value: any) => { if (settled) return; settled = true; clearTimeout(timer); resolve(value); };
        const timer = setTimeout(() => { child.kill('SIGKILL'); finish(failure('artifact_timeout')); }, 50_000);
        child.stderr.resume();
        child.stdout.on('data', chunk => {
          bytes += chunk.length;
          if (bytes > 2 * 1024 * 1024) { child.kill('SIGKILL'); finish(failure('output_limit')); }
          else output += chunk;
        });
        child.on('error', () => finish(failure('python3_unavailable')));
        child.stdin.on('error', () => {});
        child.on('close', () => {
          try {
            const response = JSON.parse(output);
            finish(response.ok ? { content: [{ type: 'text', text: JSON.stringify(response.result) }], structuredContent: response.result } : failure(response.error));
          } catch { finish(failure('artifact_worker_failed')); }
        });
        child.stdin.end(JSON.stringify({ ...input, storage_root: storageRoot, import_id: importId }));
      });
    } finally {
      await rm(join(storageRoot, '.pending-' + importId), { recursive: true, force: true }).catch(() => {});
      busy = false;
    }
  }
  server.registerTool('import_local_artifact', {
    description: '本地导入用户指定 APK/IPA，保存私有快照、计算 SHA-256、验证 ZIP 完整性并清点内容。仅结构识别，不代表可安装或无漏洞。需要 Python 3。',
    inputSchema: z.object({ path: z.string().min(1), expected_platform: z.enum(['auto', 'android', 'ios']).default('auto') }),
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  }, args => run({ operation: 'import', ...args }));
  server.registerTool('inspect_imported_artifact', {
    description: '分页读取已导入安装包的文件、摘要、类别与未分析项。文件类别是候选，不是漏洞判断。',
    inputSchema: z.object({ artifact_id: z.string().regex(/^[a-f0-9]{32}$/), offset: z.number().int().min(0).default(0), limit: z.number().int().min(1).max(200).default(100) }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, args => run({ operation: 'inspect', ...args }));
  server.registerTool('delete_imported_artifact', {
    description: '删除指定 artifact_id 的本地导入快照及清点结果，不删除用户原始安装包。有扫描引用时拒绝，须先 delete_scan。',
    inputSchema: z.object({ artifact_id: z.string().regex(/^[a-f0-9]{32}$/) }),
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
  }, async args => {
    const root = process.env.APP_SECURITY_DATA_DIR ?? join(homedir(), '.app-security', 'artifacts');
    try {
      return await withArtifactLock(root, args.artifact_id, async () => {
        const scanRoot = join(root, '_scans');
        let names: string[] = [];
        try {
          if (!(await lstat(scanRoot)).isDirectory()) throw new Error('invalid_scan_storage');
          names = await readdir(scanRoot);
        } catch (e: any) { if (e.code !== 'ENOENT') throw e; }
        for (const name of names.filter(n => /^[a-f0-9]{32}\.json$/.test(n))) {
          const path = join(scanRoot, name);
          if (!(await lstat(path)).isFile()) throw new Error('invalid_scan_storage');
          const record = JSON.parse(await readFile(path, 'utf8'));
          if (record.artifact_id === args.artifact_id) return failure('artifact_referenced_by_scan');
        }
        return await run({ operation: 'delete', ...args });
      });
    } catch { return failure('artifact_delete_blocked'); }
  });
}
function failure(code: string) { return { isError: true, content: [{ type: 'text' as const, text: `Artifact operation failed: ${code}` }] }; }
