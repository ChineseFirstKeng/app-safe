import {test} from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';import {join} from 'node:path';import {tmpdir} from 'node:os';import {execFileSync} from 'node:child_process';
import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
test('private URL boundaries and exact enabled flags avoid public/loopback/documentation values',()=>{
 const output=execFileSync('python3',['-c',String.raw`
import sys
sys.path.insert(0,'workers')
from config_signals import private_urls,debug_enabled
for host in ['10.0.0.1','172.16.0.1','172.31.255.254','192.168.1.2','[fd12::1]','[fc00::1]']:
 assert len(list(private_urls('https://'+host+'/path')))==1,host
for host in ['9.255.255.255','172.15.255.255','172.32.0.1','192.169.1.1','127.0.0.1','localhost','192.0.2.1','[::1]','[2001:db8::1]','10.0.0.1.example.invalid','example.invalid/10.0.0.1','999.0.0.1']:
 assert not list(private_urls('https://'+host)),host
for v in [True,1,'true','ON','yes']:assert debug_enabled('debug',v)
for v in [False,0,'false','true-ish',[],{},None,1.0]:assert not debug_enabled('debug',v)
assert not debug_enabled('debugdescription','true')
print('ok')
`],{encoding:'utf8'});assert.equal(output.trim(),'ok');
});
test('HC-010 Android/iOS resources: private URLs, debug flags, negative controls, redaction and partial coverage',{timeout:30000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'config-signals-'));t.after(()=>rm(root,{recursive:true,force:true}));
 execFileSync('python3',['-c',String.raw`
import sys,zipfile,json,plistlib
from pathlib import Path
p=Path(sys.argv[1])
for platform in ['android','ios']:
 with zipfile.ZipFile(p/(platform+'.zip'),'w') as z:
  prefix='assets/' if platform=='android' else 'Payload/Test.app/'
  if platform=='android':z.writestr('AndroidManifest.xml',b'fixture')
  else:z.writestr(prefix+'Info.plist',plistlib.dumps({'CFBundleIdentifier':'example.fixture'}))
  for n,host in enumerate(['10.0.0.1','172.16.2.3','192.168.2.1','[fd12::1]']):z.writestr(prefix+str(n)+'.json',json.dumps({'endpoint':'https://'+host+'/private-fixture-path'}))
  z.writestr(prefix+'debug.json',json.dumps({'debug':True,'debugdescription':'true'}))
  z.writestr(prefix+'debug.plist',plistlib.dumps({'debugEnabled':True},fmt=plistlib.FMT_BINARY))
  z.writestr(prefix+'negative.json',json.dumps({'debug':False,'debugMode':'false','enableDebug':'true-ish','url':'https://example.invalid','api_key':'public-client-key'}))
  z.writestr(prefix+'negative.conf','# debug=true\n// debugMode=true\n; enableDebug=true\ndebug=false\n')
`,root]);
 const c=new Client({name:'config-signals',version:'1'});await c.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,'store')},stderr:'ignore'}));t.after(()=>c.close());
 const call=async(name,args)=>{const r=await c.callTool({name,arguments:args});assert.ok(!r.isError);return r.structuredContent;};
 for(const platform of ['android','ios']){
  const artifact=await call('import_local_artifact',{path:join(root,platform+'.zip')});const task=await call('scan_'+platform+'_hardcoding',{artifact_id:artifact.artifact_id});let s;
  do{await new Promise(r=>setTimeout(r,20));s=await call('get_scan_status',{scan_id:task.scan_id});}while(['running','queued'].includes(s.state));
  const r=await call('list_findings',{scan_id:task.scan_id,limit:100});assert.equal(r.findings.length,6);assert.ok(r.findings.every(f=>f.rule_id==='HC-010'&&f.value==='[REDACTED]'&&f.verification_level==='candidate'));assert.equal(s.rules.find(r=>r.rule_id==='HC-010').status,'partial');
  const report=await call('export_report',{scan_id:task.scan_id,format:'json'});const body=await readFile(report.path,'utf8');for(const text of ['10.0.0.1','172.16.2.3','192.168.2.1','fd12::1','private-fixture-path'])assert.ok(!body.includes(text));
 }
});
