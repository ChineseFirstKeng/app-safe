import { mkdir, readFile, writeFile, rename, lstat, readdir, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import { corroborateFindings } from './deep-scan.js';
import { withArtifactLock } from './storage-lock.js';
import { findingPage } from './finding-page.js';
import { markdownReport } from './scan-report.js';
import { compareScans } from './scan-comparison.js';
import { verifyDexMethod } from './dex-verification.js';
import { verifyNativeFunction } from './native-verification.js';

const stopWorker = (child: ChildProcess) => {
  try { if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, 'SIGKILL'); else child.kill('SIGKILL'); } catch { child.kill('SIGKILL'); }
};
const pidAlive=(pid:unknown)=>{if(typeof pid!=='number'||!Number.isSafeInteger(pid)||pid<=0)return false;try{process.kill(pid,0);return true;}catch{return false;}};
const id = () => randomUUID().replaceAll('-', '');
const idSchema = z.string().regex(/^[a-f0-9]{32}$/);
const rules = Array.from({ length: 12 }, (_, i) => ({ rule_id: `HC-${String(i + 1).padStart(3, '0')}`, status: 'not_run', reason: 'detector_not_implemented' }));
type RecordData = { [key: string]: any };
export function registerScans(server: McpServer, worker: URL, gateWorker?: URL) {
  const artifactRoot = process.env.APP_SECURITY_DATA_DIR ?? join(homedir(), '.app-security', 'artifacts');
  const scanRoot = join(artifactRoot, '_scans');
  const owned = new Set<string>();
  const deepControllers = new Map<string, AbortController>();
  const workers = new Map<string, ChildProcess>();
  let serial = Promise.resolve();
  function locked<T>(fn: () => Promise<T>): Promise<T> {
    const task = serial.then(fn); serial = task.then(() => {}, () => {}); return task;
  }
  async function directory() {
    await mkdir(scanRoot, { recursive: true, mode: 0o700 });
    if ((await lstat(scanRoot)).isSymbolicLink()) throw new Error('invalid_scan_storage');
  }
  async function save(record: RecordData) {
    await directory();
    const temp = join(scanRoot, `.${id()}.tmp`);
    await writeFile(temp, JSON.stringify(record), { mode: 0o600, flag: 'wx' });
    await rename(temp, join(scanRoot, record.scan_id + '.json'));
  }
  async function load(scanId: string) {
    let record;
    try {
      await directory();
      const path = join(scanRoot, scanId + '.json');
      if (!(await lstat(path)).isFile()) throw new Error('invalid_scan_record');
      record = JSON.parse(await readFile(path, 'utf8'));
    }
    catch { throw new Error('scan_not_found_or_unreadable'); }
    if(record.worker_pid && !pidAlive(record.worker_pid)){record.worker_pid=null;await save(record);}
    if (['queued', 'running'].includes(record.state) && !owned.has(scanId)) {
      // A still-live owner may be another local MCP process; do not take over its job.
      let live = false;
      try { process.kill(record.owner_pid, 0); live = true; } catch {}
      if (!live) {
        record.state = 'failed'; record.stage = 'interrupted'; record.finished_at = new Date().toISOString();
        record.limitations.push('Original MCP owner exited before task completion. Results may be incomplete; a surviving worker keeps its capacity slot until it exits. Start a new scan when capacity is available.');
        await save(record);
      }
    }
    return record;
  }
  async function execute(scanId: string) {
    const request = await locked(async () => {
      const r = await load(scanId);
      if (r.state !== 'queued') return null;
      r.state = 'running'; r.stage = 'static_candidate_detection'; await save(r);
      return { scan_id:scanId, node_executable:process.execPath, storage_root: artifactRoot, artifact_id: r.artifact_id, artifact_sha256: r.artifact_sha256, scan_options: r.scan_options };
    });
    if (!request) return;
    const response = await new Promise<any>(resolve => {
      const child = spawn(process.env.APP_SECURITY_PYTHON ?? 'python3', gateWorker?[fileURLToPath(gateWorker),fileURLToPath(worker)]:[fileURLToPath(worker)], { stdio: ['pipe','pipe','pipe'], detached: process.platform !== 'win32' });
      workers.set(scanId,child);
      let output='', size=0, settled=false;
      const finish=(r:any)=>{if(settled)return;settled=true;clearTimeout(timer);workers.delete(scanId);resolve(r);};
      const timer=setTimeout(()=>{stopWorker(child);finish({ok:false,error:'resource_scan_timeout'});},100000);
      child.stderr.resume();child.stdin.on('error',()=>{});
      child.stdout.on('data', chunk=>{size+=chunk.length;if(size>4*1024*1024){stopWorker(child);finish({ok:false,error:'resource_output_limit'});}else output+=chunk;});
      child.on('error',()=>finish({ok:false,error:'python3_unavailable',_worker_exited:true}));
      child.on('close',()=>{try{finish({...JSON.parse(output),_worker_exited:true});}catch{finish({ok:false,error:'resource_worker_failed',_worker_exited:true});}});
      void locked(async()=>{const r=await load(scanId);if(r.state!=='running'||settled)return false;r.worker_pid=child.pid??null;await save(r);return true;})
        .then(start=>{if(start&&!settled)child.stdin.end(JSON.stringify(request));else stopWorker(child);})
        .catch(()=>{stopWorker(child);finish({ok:false,error:'worker_identity_save_failed'});});
    });
    const deepRecord = await locked(async () => {
      const r=await load(scanId);
      if(r.state!=='running')return;
      if(response._worker_exited)r.worker_pid=null;
      if(response.ok){
        Object.assign(r,response.result);
        if(r.profile==='static-deep') {
          r.stage='automatic_method_corroboration';
          r.limitations=r.limitations.filter((s:string)=>!s.startsWith('Static-deep currently'));
          r.limitations.push('Static-deep adds bounded DEX method corroboration and identity-bound native literal reference/function discovery; full security-use and data-flow verification remain unsupported.');
          await save(r);return r;
        }
        r.state='partial';r.stage='static_pass_finished';
      } else {
        r.state=response.error==='global_scan_capacity_exceeded'?'blocked':'failed';r.stage=response.error==='global_scan_capacity_exceeded'?'static_capacity_exhausted':'resource_scan_failed';r.limitations.push(response.error);
      }
      r.finished_at=new Date().toISOString();await save(r);owned.delete(scanId);
      return null;
    });
    if(!deepRecord)return;
    const controller=new AbortController();deepControllers.set(scanId,controller);
    const timer=setTimeout(()=>controller.abort(),150000);
    try {
      if(verifying)throw new Error('verification_capacity_exceeded');
      verifying=true;
      try {
        await withArtifactLock(artifactRoot,deepRecord.artifact_id,async()=>{
          await corroborateFindings(deepRecord,artifactRoot,controller.signal,async(summary,verifications)=>{
            await locked(async()=>{
              const r=await load(scanId);if(r.state!=='running'){controller.abort();return;}
              r.deep_scan={...summary};r.verifications={...verifications};
              if(summary.recovered_methods||summary.recovered_functions)r.effective_profile='static-basic+rea-'+(summary.recovered_methods&&summary.recovered_functions?'dex-and-native':summary.recovered_functions?'native':'dex')+'-corroboration';
              await save(r);
            });
          },verifyDexMethod,(record,finding,root,signal)=>verifyNativeFunction(record,finding,undefined,root,new URL(record.platform==='ios'?'ios_extract.py':'elf_extract.py',worker),signal));
        });
      }finally{verifying=false;}
    }catch(e){
      await locked(async()=>{const r=await load(scanId);if(r.state!=='running')return;
        r.deep_scan={...r.deep_scan,status:'blocked',reason:e instanceof Error&&/^[a-z_]+$/.test(e.message)?e.message:'deep_verification_failed',usage_confirmed:false};await save(r);});
    }finally{
      clearTimeout(timer);
      try {
        await locked(async()=>{const r=await load(scanId);if(r.state==='running'){
          r.state='partial';r.stage='static_and_corroboration_finished';r.finished_at=new Date().toISOString();await save(r);
        }});
      }finally{deepControllers.delete(scanId);owned.delete(scanId);}
    }
  }
  const result = (value: any) => ({ content: [{ type: 'text' as const, text: JSON.stringify(value) }], structuredContent: value });
  const wrap = (fn: (args: any) => Promise<any>) => async (args: any) => {
    try { return result(await locked(() => fn(args))); }
    catch (e) { return { isError: true, content: [{ type: 'text' as const, text: e instanceof Error && /^[a-z_]+$/.test(e.message) ? e.message : 'scan_operation_failed' }] }; }
  };
  for (const platform of ['android', 'ios']) server.registerTool(`scan_${platform}_hardcoding`, {
    description: `创建 ${platform} 资源硬编码候选检测任务。配置/文本/PEM/DER、Android DEX 常量及 iOS Mach-O 和 Android ELF 分段字符串模式；原生指令用途及运行行为未全面分析；结果为 partial，不是安全合格证明。`,
    inputSchema: z.object({ artifact_id: idSchema, profile: z.enum(['static-basic', 'static-deep']).default('static-basic'), deep_method_limit:z.number().int().min(1).max(10).default(3),deep_native_limit:z.number().int().min(1).max(5).default(2), ...(platform === 'ios' ? { ios_decode_attempt_limit: z.number().int().min(1).max(20000).default(2000).describe('每个 Mach-O 切片的单层字面量解码尝试上限；全局时间和字节限制仍适用。') } : {}) }),
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  }, wrap(async args => {
    if (owned.size >= 2) throw new Error('scan_capacity_exceeded');
    return withArtifactLock(artifactRoot, args.artifact_id, async () => {
    const artifactDir = join(artifactRoot, args.artifact_id);
    if ((await lstat(artifactDir)).isSymbolicLink()) throw new Error('invalid_artifact_storage');
    const inventory = JSON.parse(await readFile(join(artifactDir, 'inventory.json'), 'utf8'));
    if (inventory.platform !== platform) throw new Error('platform_mismatch');
    const r = { schema_version: '0.1', scan_id: id(), artifact_id: args.artifact_id, platform, profile: args.profile, effective_profile: 'static-basic',
      scan_options: { ...(args.profile==='static-deep'?{deep_method_limit:args.deep_method_limit,deep_native_limit:args.deep_native_limit}:{}), ...(platform === 'ios'?{ios_decode_attempt_limit:args.ios_decode_attempt_limit}:{}) },
      state: 'queued', stage: 'preflight_pending', created_at: new Date().toISOString(), finished_at: null, owner_pid: process.pid,
      artifact_sha256: inventory.sha256, coverage: inventory.coverage, rules, finding_count: null, findings: [],
      limitations: [...inventory.limitations], ruleset_version: '0.25-openssh-key', scanner_version: '0.32.0' };
    await save(r); owned.add(r.scan_id);
    setImmediate(() => { void execute(r.scan_id).catch(async () => {
      await locked(async () => { const current = await load(r.scan_id); if (!['queued','running'].includes(current.state)) return;
        current.state='failed'; current.stage='internal_error'; current.finished_at=new Date().toISOString(); await save(current); owned.delete(r.scan_id); }).catch(() => {});
    }); });
    return r;
    });
  }));
  let verifying=false;
  server.registerTool('verify_ios_finding', {
    description:'对 iOS 原生字符串候选所在的未加密 Mach-O 切片，用独立 REA/Ghidra 复核指定函数及字符串地址引用。procedure 必须是已知函数符号或提供方返回的函数地址；不确认运行用途，不输出伪代码明文。',
    inputSchema:z.object({scan_id:idSchema,finding_id:z.string().regex(/^f-[0-9]{4}$/),procedure:z.string().min(1).max(256)}),
    annotations:{readOnlyHint:false,destructiveHint:false,openWorldHint:false},
  },async args=>{
    if(verifying)return result({status:'blocked',reason:'verification_capacity_exceeded'});
    verifying=true;
    try {
      const record=await locked(()=>load(args.scan_id));
      if(record.platform!=='ios')return result({status:'not_applicable',reason:'not_ios'});
      if(['queued','running'].includes(record.state))return result({status:'blocked',reason:'scan_not_finished'});
      const finding=record.findings.find((f:any)=>f.finding_id===args.finding_id);
      if(!finding)return result({status:'blocked',reason:'finding_not_found'});
      return await withArtifactLock(artifactRoot, record.artifact_id, async () => {
      await locked(()=>load(args.scan_id));
      const verification=await verifyNativeFunction(record,finding,args.procedure,artifactRoot,new URL('ios_extract.py',worker));
      await locked(async()=>{const current=await load(args.scan_id);current.verifications??={};current.verifications[args.finding_id]={...verification,checked_at:new Date().toISOString()};await save(current);});
      return result({scan_id:args.scan_id,finding_id:args.finding_id,...verification});
      });
    }catch{return result({status:'blocked',reason:'verification_failed'});}
    finally{verifying=false;}
  });
  server.registerTool('verify_android_native_finding', {
    description:'对 Android ELF 原生字符串候选所在的库，用独立 REA/Ghidra 复核指定函数及字符串地址引用。procedure 必须是已知函数符号或提供方返回的函数地址；不确认运行用途，不输出伪代码明文。',
    inputSchema:z.object({scan_id:idSchema,finding_id:z.string().regex(/^f-[0-9]{4}$/),procedure:z.string().min(1).max(256)}),
    annotations:{readOnlyHint:false,destructiveHint:false,openWorldHint:false},
  },async args=>{
    if(verifying)return result({status:'blocked',reason:'verification_capacity_exceeded'});
    verifying=true;
    try {
      const record=await locked(()=>load(args.scan_id));
      if(record.platform!=='android')return result({status:'not_applicable',reason:'not_android'});
      if(['queued','running'].includes(record.state))return result({status:'blocked',reason:'scan_not_finished'});
      const finding=record.findings.find((f:any)=>f.finding_id===args.finding_id);
      if(!finding)return result({status:'blocked',reason:'finding_not_found'});
      return await withArtifactLock(artifactRoot, record.artifact_id, async () => {
      await locked(()=>load(args.scan_id));
      const verification=await verifyNativeFunction(record,finding,args.procedure,artifactRoot,new URL('elf_extract.py',worker));
      await locked(async()=>{const current=await load(args.scan_id);current.verifications??={};current.verifications[args.finding_id]={...verification,checked_at:new Date().toISOString()};await save(current);});
      return result({scan_id:args.scan_id,finding_id:args.finding_id,...verification});
      });
    }catch{return result({status:'blocked',reason:'verification_failed'});}
    finally{verifying=false;}
  });
  server.registerTool('verify_android_finding', {
    description:'使用独立 REA MCP 复核 DEX 候选的方法身份并恢复方法体。需 APP_SECURITY_REA_COMMAND/ARGS 和 REA 的 JADX/JDK 依赖；不确认凭证用途或漏洞，不输出反编译秘密。',
    inputSchema:z.object({scan_id:idSchema,finding_id:z.string().regex(/^f-[0-9]{4}$/)}),
    annotations:{readOnlyHint:false,destructiveHint:false,openWorldHint:false},
  },async args=>{
    if(verifying)return result({status:'blocked',reason:'verification_capacity_exceeded'});
    verifying=true;
    try {
      const record=await locked(()=>load(args.scan_id));
      if(record.platform!=='android')return result({status:'not_applicable',reason:'not_android'});
      if(['queued','running'].includes(record.state))return result({status:'blocked',reason:'scan_not_finished'});
      const finding=record.findings.find((f:any)=>f.finding_id===args.finding_id);
      if(!finding)return result({status:'blocked',reason:'finding_not_found'});
      return await withArtifactLock(artifactRoot, record.artifact_id, async () => {
      await locked(()=>load(args.scan_id));
      const verification=await verifyDexMethod(record,finding,artifactRoot);
      await locked(async()=>{const current=await load(args.scan_id);current.verifications??={};current.verifications[args.finding_id]={...verification,checked_at:new Date().toISOString()};await save(current);});
      return result({scan_id:args.scan_id,finding_id:args.finding_id,...verification});
      });
    } catch {return result({status:'blocked',reason:'verification_failed'});}
    finally {verifying=false;}
  });
  server.registerTool('get_scan_status', { description: '读取持久化任务状态、覆盖范围、client_identifier_review 标识清点及未执行规则；blocked 不表示安全。', inputSchema: z.object({ scan_id: idSchema }), annotations: { readOnlyHint: true, openWorldHint: false } }, wrap(async args => { const r=await load(args.scan_id); const {findings,...summary}=r; return summary; }));
  server.registerTool('cancel_scan', { description: '取消尚在排队或运行的本地任务；已结束任务保持原结果。', inputSchema: z.object({ scan_id: idSchema }), annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false } }, wrap(async args => {
    const r = await load(args.scan_id);
    if (!['queued','running'].includes(r.state)) return { scan_id: r.scan_id, state: r.state, cancelled: false, reason: 'already_terminal' };
    if (!owned.has(r.scan_id)) throw new Error('scan_owned_by_another_process');
    r.state='cancelled';r.stage='cancelled';r.finished_at=new Date().toISOString();await save(r);const worker=workers.get(r.scan_id);if(worker)stopWorker(worker);deepControllers.get(r.scan_id)?.abort();if(!deepControllers.has(r.scan_id))owned.delete(r.scan_id);
    return {scan_id:r.scan_id,state:r.state,cancelled:true};
  }));
  server.registerTool('list_findings', { description: '按规则、严重度、置信度筛选脱敏候选并分页；cursor 绑定当前结果和筛选条件，源覆盖完整性与翻页完成独立。',
    inputSchema: z.object({scan_id:idSchema,offset:z.number().int().min(0).default(0),limit:z.number().int().min(1).max(100).default(50),
      cursor:z.string().min(1).max(1024).optional(),rule_id:z.string().regex(/^HC-00[1-9]$|^HC-01[0-2]$/).optional(),
      severity:z.enum(['needs_review','critical','high','medium','low','info']).optional(),confidence:z.enum(['low','medium','high']).optional()}),
    annotations:{readOnlyHint:true,openWorldHint:false}},wrap(async args=>findingPage(await load(args.scan_id),args)));
  server.registerTool('get_finding', {description:'读取指定候选的脱敏证据、未知项及修复和复测建议。',inputSchema:z.object({scan_id:idSchema,finding_id:z.string().regex(/^f-[0-9]{4}$/)}),annotations:{readOnlyHint:true,openWorldHint:false}},wrap(async args=>{
    const r=await load(args.scan_id),finding=r.findings.find((f:any)=>f.finding_id===args.finding_id);
    if(!finding)throw new Error('finding_not_found');return {scan_id:r.scan_id,artifact_sha256:r.artifact_sha256,...finding};
  }));
  server.registerTool('read_evidence', {
    description: '按候选 evidence_id 读取持久化脱敏证据及包身份；不读取任意文件，不返回原始秘密。当前每个证据为一个有界结构化记录。',
    inputSchema: z.object({ scan_id: idSchema, evidence_id: z.string().regex(/^e-f-[0-9]{4}$/) }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, wrap(async args => {
    const r = await load(args.scan_id);
    const f = r.findings.find((f: any) => f.evidence_id === args.evidence_id);
    if (!f) throw new Error('evidence_not_found');
    return { schema_version: '0.1', scan_id: r.scan_id, evidence_id: f.evidence_id,
      artifact_id: r.artifact_id, artifact_sha256: r.artifact_sha256,
      scanner_version: r.scanner_version, ruleset_version: r.ruleset_version,
      finding_id: f.finding_id, verification_level: f.verification_level,
      evidence: f.evidence, verification: r.verifications?.[f.finding_id] ?? null,
      next_cursor: null, source_complete: false, limitations: r.limitations };
  }));
  server.registerTool('delete_scan', {
    description: '删除已结束任务及该任务导出的报告。运行任务须先取消；正在复核时拒绝删除。保留共享导入快照和原始安装包。',
    inputSchema: z.object({ scan_id: idSchema }),
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
  }, wrap(async args => {
    const record = await load(args.scan_id);
    return withArtifactLock(artifactRoot, record.artifact_id, async () => {
      const r = await load(args.scan_id);
      if (['queued', 'running'].includes(r.state) || workers.has(r.scan_id) || deepControllers.has(r.scan_id)) throw new Error('scan_still_active');
      if(pidAlive(r.worker_pid))throw new Error('scan_worker_may_still_be_active');
      const names = await readdir(scanRoot);
      const reportPattern = new RegExp('^' + r.scan_id + '-[a-f0-9]{32}\\.(json|md)$');
      let reports = 0;
      for (const name of names.filter(n => reportPattern.test(n))) {
        // unlink removes a symlink itself; it never follows it outside storage.
        await unlink(join(scanRoot, name)); reports++;
      }
      await unlink(join(scanRoot,r.scan_id+'.sensitive.json')).catch((e:any)=>{if(e.code!=='ENOENT')throw e;});
      await unlink(join(scanRoot, r.scan_id + '.json'));
      return { schema_version: '0.1', scan_id: r.scan_id, deleted: true,
        reports_deleted: reports, artifact_id: r.artifact_id, artifact_retained: true };
    });
  }));
  server.registerTool('compare_scans', {description:'比较同平台两次已结束扫描的候选分组与覆盖记录；不比较秘密值，不把未再检出判为已修复。', inputSchema:z.object({before_scan_id:idSchema,after_scan_id:idSchema}), annotations:{readOnlyHint:true,openWorldHint:false}},wrap(async args=>compareScans(await load(args.before_scan_id),await load(args.after_scan_id))));
  server.registerTool('export_report', { description: '逐项导出硬编码内容、位置、风险依据和修复建议；默认脱敏，include_sensitive_values 可生成含捕获原值的本机文件。包含待核查 Key 和覆盖缺口，不是安全合格证明。', inputSchema: z.object({ scan_id: idSchema, format: z.enum(['json','markdown']).default('markdown'),include_sensitive_values:z.boolean().default(false).describe('为用户在本机核查原值生成权限 600 的报告；工具响应只返回路径，聊天默认不复述秘密。') }), annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false } }, wrap(async args => {
    const r = await load(args.scan_id);
    return withArtifactLock(artifactRoot, r.artifact_id, async () => {
    await load(args.scan_id); const reportId=id();
    const path=join(scanRoot,`${r.scan_id}-${reportId}.${args.format==='json'?'json':'md'}`);
    let report=r;
    if(args.include_sensitive_values){
      if(['queued','running'].includes(r.state))throw new Error('scan_not_finished');
      if(!r.private_evidence?.available)throw new Error('scan_has_no_private_values_rescan_required');
      const privatePath=join(scanRoot,r.scan_id+'.sensitive.json');
      if(!(await lstat(privatePath)).isFile())throw new Error('invalid_private_evidence');
      const material=JSON.parse(await readFile(privatePath,'utf8'));
      if(material.scan_id!==r.scan_id||material.artifact_id!==r.artifact_id||material.artifact_sha256!==r.artifact_sha256)throw new Error('private_evidence_identity_mismatch');
      const withValue=(item:any,key:string)=>({...item,value:material.values?.[key]?.value??'[NOT_CAPTURED]',value_encoding:material.values?.[key]?.encoding??null});
      report={...r,contains_sensitive_values:true,findings:r.findings.map((f:any)=>withValue(f,f.finding_id)),
        client_identifier_review:r.client_identifier_review?{...r.client_identifier_review,items:r.client_identifier_review.items.map((i:any)=>withValue(i,i.review_id))}:undefined};
    }
    const text=args.format==='json'?JSON.stringify(report,null,2):markdownReport(report);
    await writeFile(path,text,{mode:0o600,flag:'wx'});return {report_id:reportId,scan_id:r.scan_id,state:r.state,path,format:args.format,contains_sensitive_values:args.include_sensitive_values};
    });
  }));
}
