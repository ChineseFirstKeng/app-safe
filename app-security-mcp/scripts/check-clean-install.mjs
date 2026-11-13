import assert from 'node:assert/strict';
import {mkdtemp,mkdir,cp,readFile,writeFile,rm,stat,realpath} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {tmpdir,homedir} from 'node:os';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {Client} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
const project=fileURLToPath(new URL('..',import.meta.url));
const root=await mkdtemp(join(tmpdir(),'app-security-clean-install-'));
const originalConfig=join(process.env.CODEX_HOME??join(homedir(),'.codex'),'config.toml');
const digest=async path=>{try{return createHash('sha256').update(await readFile(path)).digest('hex');}catch(e){if(e.code==='ENOENT')return null;throw e;}};
const before=await digest(originalConfig);
const summary={scope:'isolated_codex_configuration_on_existing_host',plugin_version:null,discovery:false,scans:[],missing_python:false,original_config_unchanged:false,passed:false};
// Explicit child environment: no credentials or pre-existing app-security settings.
const env={PATH:process.env.PATH??'',...(process.env.HOME?{HOME:process.env.HOME}:{}),...(process.env.TMPDIR?{TMPDIR:process.env.TMPDIR}:{}),CODEX_HOME:join(root,'codex'),APP_SECURITY_DATA_DIR:join(root,'data'),APP_SECURITY_AAPT2:'',APP_SECURITY_DEXDUMP:'',APP_SECURITY_REA_COMMAND:''};
const run=(command,args)=>execFileSync(command,args,{cwd:root,env,encoding:'utf8',timeout:45000,maxBuffer:2*1024*1024,stdio:['ignore','pipe','pipe']});
async function connect(entry,overrides={}){
 const client=new Client({name:'clean-install-validation',version:'1'});
 await client.connect(new StdioClientTransport({command:process.execPath,args:[entry],cwd:root,env:{...env,...overrides},stderr:'ignore'}));return client;
}
try{
 await mkdir(env.CODEX_HOME);await cp(join(project,'artifacts/plugin-marketplace'),join(root,'market'),{recursive:true});
 run('codex',['plugin','marketplace','add',join(root,'market'),'--json']);
 const installed=JSON.parse(run('codex',['plugin','add','app-security@app-security-local','--json']));
 assert.ok((await realpath(installed.installedPath)).startsWith((await realpath(env.CODEX_HOME))+'/'),'installation escaped isolated configuration');
 summary.plugin_version=installed.version;
 const output=run(process.execPath,[join(project,'scripts/check-plugin.mjs')]);assert.ok(output.includes('PASS:'));assert.ok(output.includes(installed.installedPath));summary.discovery=true;
 // Confirm the cache is self-contained after its marketplace source disappears.
 await rm(join(root,'market'),{recursive:true});
 assert.equal(await stat(join(installed.installedPath,'node_modules')).then(()=>true,()=>false),false);
 run('python3',['-c',String.raw`
import sys,zipfile,json,plistlib,struct,hashlib,zlib
from pathlib import Path
root=Path(sys.argv[1])
for platform in ['android','ios']:
 with zipfile.ZipFile(root/(platform+'.zip'),'w') as z:
  prefix='assets/' if platform=='android' else 'Payload/Test.app/'
  if platform=='android':
   z.writestr('AndroidManifest.xml',b'\x03\x00\x08\x00fixture')
   dex=bytearray(112);dex[:8]=b'dex\n035\0'
   struct.pack_into('<III',dex,32,112,112,0x12345678)
   dex[12:32]=hashlib.sha1(dex[32:]).digest();struct.pack_into('<I',dex,8,zlib.adler32(dex[12:])&0xffffffff)
   z.writestr('classes.dex',dex)
  else:z.writestr(prefix+'Info.plist',plistlib.dumps({'CFBundleIdentifier':'example.clean'}))
  z.writestr(prefix+'config.json',json.dumps({'password':'synthetic-clean-install-password'}))
`,root]);
 const entry=join(installed.installedPath,'dist/index.mjs');
 const client=await connect(entry);
 try{
  const call=async(name,args)=>{const r=await client.callTool({name,arguments:args});assert.ok(!r.isError,name+' failed');return r.structuredContent;};
  assert.equal((await client.listTools()).tools.length,23);
  for(const platform of ['android','ios']){
   const caps=await call('get_analysis_capabilities',{platform});assert.equal(caps.dependencies.python.status,'available');assert.equal(caps.dependencies.rea.status,'missing_or_invalid');
   if(platform==='android'){assert.equal(caps.dependencies.aapt2.status,'missing');assert.equal(caps.dependencies.dexdump.status,'missing');}
   const artifact=await call('import_local_artifact',{path:join(root,platform+'.zip'),expected_platform:platform});
   const task=await call('scan_'+platform+'_hardcoding',{artifact_id:artifact.artifact_id});let status;
   for(let i=0;i<200;i++){status=await call('get_scan_status',{scan_id:task.scan_id});if(!['queued','running'].includes(status.state))break;await new Promise(r=>setTimeout(r,50));}
   assert.equal(status.state,'partial');assert.equal(status.finding_count,1);
   if(platform==='android')assert.equal(status.dex_scan.failures.dex_decoder_unavailable,1);
   const result=await call('list_findings',{scan_id:task.scan_id});assert.equal(result.findings[0].rule_id,'HC-001');assert.equal(result.findings[0].value,'[REDACTED]');
   const report=await call('export_report',{scan_id:task.scan_id,format:'json'});assert.ok((await realpath(report.path)).startsWith((await realpath(env.APP_SECURITY_DATA_DIR))+'/'));
   assert.ok(!(await readFile(report.path,'utf8')).includes('synthetic-clean-install-password'));
   summary.scans.push({platform,state:status.state,findings:status.finding_count,dependency_gap_reported:platform==='android'});
  }
 }finally{await client.close();}
 const missing=await connect(entry,{APP_SECURITY_PYTHON:join(root,'absent-python')});
 try{
  const r=await missing.callTool({name:'get_analysis_capabilities',arguments:{platform:'android'}});assert.equal(r.structuredContent.dependencies.python.execution_verified,false);summary.missing_python=true;
 }finally{await missing.close();}
 summary.original_config_unchanged=before===await digest(originalConfig);assert.equal(summary.original_config_unchanged,true);summary.passed=true;
}finally{
 summary.original_config_unchanged=before===await digest(originalConfig);
 await rm(root,{recursive:true,force:true});
 await mkdir(join(project,'artifacts/validation'),{recursive:true});
 await writeFile(join(project,'artifacts/validation/clean-install-summary.json'),JSON.stringify(summary,null,2)+'\n',{mode:0o600});
}
console.log(JSON.stringify(summary));
