import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

async function reaConfiguration() {
  try {
    let command = process.env.APP_SECURITY_REA_COMMAND;
    let args: unknown, env: unknown = {}, provider: unknown = 'ghidra';
    if (command === undefined) {
      const config = JSON.parse(await readFile(process.env.APP_SECURITY_REA_CONFIG ?? join(homedir(), '.app-security', 'rea.json'), 'utf8'));
      command = config.command; args = config.args ?? []; env = config.env ?? {}; provider = config.native_provider ?? 'ghidra';
    } else args = JSON.parse(process.env.APP_SECURITY_REA_ARGS ?? '[]');
    if (typeof command !== 'string' || !command || !Array.isArray(args) || args.some(x => typeof x !== 'string') || !env || typeof env !== 'object' || Array.isArray(env) || Object.values(env).some(x => typeof x !== 'string') || typeof provider !== 'string') throw Error();
    return { status: 'configured_not_verified', execution_verified: false, version: null, reason: 'provider_and_engines_require_target_verification' };
  } catch {
    return { status: 'missing_or_invalid', execution_verified: false, version: null, reason: 'rea_config_missing_or_invalid' };
  }
}
export function registerCapabilities(server: McpServer, worker: URL) {
  server.registerTool('get_analysis_capabilities', {
    description: '检查本机扫描依赖与已实现范围。区分实际运行的 Python、仅定位到的 Android 分析器和仅有配置的 REA；不保证目标可分析，不启动 REA 或下载引擎。',
    inputSchema: z.object({ platform: z.enum(['android', 'ios']) }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ platform }) => {
    const unavailable = { status: 'unknown', execution_verified: false, version: null, reason: 'dependency_probe_failed' };
    const dependencies: any = await new Promise(resolve => {
      execFile(process.env.APP_SECURITY_PYTHON ?? 'python3', [fileURLToPath(worker)], { timeout: 5000, maxBuffer: 16384, encoding: 'utf8' }, (error, stdout) => {
        if (error) return resolve({ python: { ...unavailable, status: 'unavailable_or_probe_failed' }, aapt2: unavailable, dexdump: unavailable });
        try { const r = JSON.parse(stdout); if (!r.python || !r.aapt2 || !r.dexdump) throw Error(); resolve(r); }
        catch { resolve({ python: unavailable, aapt2: unavailable, dexdump: unavailable }); }
      });
    });
    if (platform === 'ios') { delete dependencies.aapt2; delete dependencies.dexdump; }
    dependencies.static_worker_admission={status:process.platform==='win32'?'unsupported':'implementation_available',scope:'shared_data_directory',kernel_mechanism:'flock',execution_verified:false};
    dependencies.rea = await reaConfiguration();
    dependencies.key_parser={status:'runtime_available',version:process.version,openssl_version:process.versions.openssl,execution_verified:false,reason:'material_specific_parser_validation_required'};
    const value = {
      schema_version: '0.1', platform, checked_at: new Date().toISOString(), scope: 'local_dependency_discovery', dependencies,
      profiles: { 'static-basic': { implemented: true, coverage: 'bounded_partial' }, 'static-deep': { implemented:true, coverage:platform==='android'?'bounded_dex_and_native_corroboration':'bounded_native_corroboration', fallback_profile:'static-basic', reason:'requires_eligible_findings_and_rea' } },
      analysis_surfaces: platform === 'android'
        ? { resources: 'bounded_patterns', sqlite: 'bounded_ordinary_tables_no_wal', key_material:'node_crypto_supported_pem_der_openssh', nested_archives:'bounded_zip_recursion', binary_resources: 'requires_aapt2', dex: 'bounded_constants_requires_dexdump', elf: 'bounded_literals', usage_verification: 'explicit_finding_and_method_or_function_requires_rea' }
        : { resources: 'bounded_patterns', sqlite: 'bounded_ordinary_tables_no_wal', key_material:'node_crypto_supported_pem_der_openssh', nested_archives:'bounded_zip_recursion', macho: 'bounded_literals_unencrypted_slices', usage_verification: 'explicit_finding_and_function_requires_rea' },
      limits: { static_workers_per_process:2,static_workers_per_data_directory:2,verification_concurrency_scope:'per_mcp_process', worker_timeout_seconds: 100, deep_budget_seconds:150, deep_method_limit:{default:3,min:1,max:10},deep_native_limit:{default:2,min:1,max:5}, analysis_budget_seconds: 90, nested_archives:{depth_limit:2,archive_limit:32,entry_limit:5000,member_bytes_limit:8388608,total_discovery_bytes_limit:67108864,discovery_budget_seconds:10},key_parse_attempt_limit:32,key_material_bytes_limit:131072,key_parse_timeout_seconds:3, ...(platform === 'ios' ? { ios_decode_attempt_limit: { default: 2000, min: 1, max: 20000, scope: 'per_slice' } } : {}) },
      limitations: ['可执行文件存在不代表引擎可正常运行；版本未知时返回 null。', 'REA 配置存在不证明 JADX/Ghidra 已可用；在实际定点或自动复核时验证。', '实际覆盖取决于目标、加密状态与扫描预算；缺依赖不等于没有问题。', '跨函数数据流、完整安全用途判断及运行时验证尚未实现。'],
    };
    return { content: [{ type: 'text' as const, text: JSON.stringify(value) }], structuredContent: value };
  });
}
