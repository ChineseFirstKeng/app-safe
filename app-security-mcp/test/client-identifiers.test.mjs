import {test} from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';import {join} from 'node:path';import {tmpdir} from 'node:os';import {execFileSync} from 'node:child_process';
import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
test('HC-012 separate Android/iOS inventory: no automatic secret finding, placeholders, cap and redaction',{timeout:30000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'identifier-review-'));t.after(()=>rm(root,{recursive:true,force:true}));
 execFileSync('python3',['-c',String.raw`
import sys,zipfile,json,plistlib
from pathlib import Path
p=Path(sys.argv[1])
for platform in ['android','ios']:
 for capped in [False,True]:
  with zipfile.ZipFile(p/(platform+str(capped)+'.zip'),'w') as z:
   prefix='assets/' if platform=='android' else 'Payload/Test.app/'
   if platform=='android':z.writestr('AndroidManifest.xml',b'fixture')
   else:z.writestr(prefix+'Info.plist',plistlib.dumps({'CFBundleIdentifier':'example.fixture'}))
   if capped:z.writestr(prefix+'many.json',json.dumps([{'client_id':'fixture-identifier-'+str(i)} for i in range(105)]))
   else:
    z.writestr(prefix+'ids.json',json.dumps({'client_id':'fixture-public-123','api_key':'fixture-ambiguous-456','nested':{'oauth_client_id':'fixture-oauth-789'},'random_key':'opaque-unclassified-value'}))
    z.writestr(prefix+'key.plist',plistlib.dumps({'GOOGLE_API_KEY':'fixture-google-abc'},fmt=plistlib.FMT_BINARY))
    z.writestr(prefix+'text.conf','client_id=fixture-text-id\n# api_key=ignored-comment\n')
    z.writestr(prefix+'negative.json',json.dumps([{'api_key':'$'+'{API_KEY}'},{'client_id':'your_client_id'},{'api_key':'@string/key'},{'client_id':123}]))
`,root]);
 const c=new Client({name:'identifier-review',version:'1'});await c.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,'store')},stderr:'ignore'}));t.after(()=>c.close());
 const call=async(name,args)=>{const r=await c.callTool({name,arguments:args});assert.ok(!r.isError);return r.structuredContent;};
 for(const platform of ['android','ios'])for(const capped of [false,true]){
  const artifact=await call('import_local_artifact',{path:join(root,platform+(capped?'True':'False')+'.zip')});const task=await call('scan_'+platform+'_hardcoding',{artifact_id:artifact.artifact_id});let s;
  do{await new Promise(r=>setTimeout(r,20));s=await call('get_scan_status',{scan_id:task.scan_id});}while(['running','queued'].includes(s.state));
  assert.equal(s.state,'partial');assert.equal(s.finding_count,0);const r=s.client_identifier_review;
  assert.equal(r.item_count,capped?100:5);assert.equal(r.items_truncated,capped);assert.equal(r.misuse_assessment,'not_evaluated');assert.ok(r.items.every(i=>i.value==='[REDACTED]'&&!i.misuse_confirmed&&i.permissions==='unknown'));
  if(!capped)assert.equal(r.items.filter(i=>i.classification==='api_key_role_unknown').length,2);
  assert.equal(s.rules.find(r=>r.rule_id==='HC-012').status,'partial');assert.equal((await call('list_findings',{scan_id:task.scan_id})).findings.length,0);
  for(const format of ['json','markdown']){const report=await call('export_report',{scan_id:task.scan_id,format});const body=await readFile(report.path,'utf8');for(const text of ['fixture-public','fixture-ambiguous','fixture-oauth','fixture-google','fixture-text','fixture-identifier'])assert.ok(!body.includes(text));assert.ok(body.includes('client_identifier_review'));}
 }
});
