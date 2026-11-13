import {test} from 'node:test';import assert from 'node:assert/strict';import {mkdtemp,readFile,writeFile,rm,stat,access,symlink,unlink} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import {execFileSync} from 'node:child_process';import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
test('concrete content reports: private raw values, visible key review, redacted defaults, identity checks and cleanup',{timeout:30000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'private-review-'));t.after(()=>rm(root,{recursive:true,force:true}));
 execFileSync('python3',['-c',String.raw`
import sys,json,zipfile,plistlib,base64
from pathlib import Path
p=Path(sys.argv[1])
for platform in ('android','ios'):
 with zipfile.ZipFile(p/(platform+'.zip'),'w') as z:
  prefix='assets/' if platform=='android' else 'Payload/App.app/'
  if platform=='android':z.writestr('AndroidManifest.xml','fixture')
  else:z.writestr(prefix+'Info.plist',plistlib.dumps({'CFBundleIdentifier':'example.fixture'}))
  z.writestr(prefix+'config.json',json.dumps({'password':'fixture-password-123','client_secret':'fixture-client-secret-456','access_token':'fixture-access-token-789','google_api_key':'fixture-api-key-123456789','url':'http://10.23.7.3/private/session?token=fixture-query-secret','contact':{'full_name':'Isabel Torres','email':'isabel@research.company','unrelated':'should-not-capture'}}))
  z.writestr(prefix+'service.conf','db=postgres://user:fixture-db-password@db.example.invalid/app\nAuthorization: Basic '+base64.b64encode(b'user:fixture-basic-password').decode())
`,root],{stdio:['ignore','pipe','pipe']});
 const c=new Client({name:'private-report-test',version:'1'});await c.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,'store')},stderr:'ignore'}));t.after(()=>c.close());
 const call=async(name,args)=>{const r=await c.callTool({name,arguments:args});assert.ok(!r.isError,JSON.stringify(r));return r.structuredContent;};
 for(const platform of ['android','ios']){
  const imported=await call('import_local_artifact',{path:join(root,platform+'.zip')});const scan=await call('scan_'+platform+'_hardcoding',{artifact_id:imported.artifact_id});let status;
  for(let i=0;i<300;i++){status=await call('get_scan_status',{scan_id:scan.scan_id});if(!['queued','running'].includes(status.state))break;await new Promise(r=>setTimeout(r,20));}
  assert.equal(status.state,'partial');assert.equal(status.private_evidence.available,true);
  const privatePath=join(root,'store','_scans',scan.scan_id+'.sensitive.json');assert.equal((await stat(privatePath)).mode&0o777,0o600);
  const privateText=await readFile(privatePath,'utf8');assert.ok(!privateText.includes('should-not-capture'));const material=JSON.parse(privateText);
  const normal=await call('export_report',{scan_id:scan.scan_id,format:'markdown'});const redacted=await readFile(normal.path,'utf8');assert.ok(redacted.includes('google_api_key'));assert.ok(redacted.includes('待核查的 Key'));assert.equal(normal.contains_sensitive_values,false);
  for(const secret of ['fixture-password-123','fixture-client-secret-456','fixture-access-token-789','fixture-api-key-123456789','fixture-query-secret','fixture-db-password','fixture-basic-password','Isabel Torres','isabel@research.company']){
   assert.ok(!JSON.stringify(status).includes(secret));assert.ok(!redacted.includes(secret));assert.ok(privateText.includes(secret));
  }
  const page=await call('list_findings',{scan_id:scan.scan_id});assert.ok(page.findings.every(f=>f.private_value_available));
  const full=await call('export_report',{scan_id:scan.scan_id,format:'json',include_sensitive_values:true});assert.equal(full.contains_sensitive_values,true);assert.ok(!JSON.stringify(full).includes('fixture-password-123'));assert.equal((await stat(full.path)).mode&0o777,0o600);
  const report=JSON.parse(await readFile(full.path,'utf8'));assert.equal(report.client_identifier_review.items[0].value,'fixture-api-key-123456789');assert.ok(report.findings.some(f=>f.value==='fixture-password-123'));
  assert.ok(report.findings.some(f=>f.value==='http://10.23.7.3/private/session?token=fixture-query-secret'));
  assert.ok(report.findings.some(f=>f.value==='postgres://user:fixture-db-password@db.example.invalid/app'));
  const md=await call('export_report',{scan_id:scan.scan_id,format:'markdown',include_sensitive_values:true});assert.ok((await readFile(md.path,'utf8')).includes('fixture-password-123'));
  await writeFile(privatePath,JSON.stringify({...material,artifact_sha256:'wrong'}));const wrong=await c.callTool({name:'export_report',arguments:{scan_id:scan.scan_id,include_sensitive_values:true}});assert.equal(wrong.isError,true);assert.equal(wrong.content[0].text,'private_evidence_identity_mismatch');
  await unlink(privatePath);await symlink(full.path,privatePath);const invalid=await c.callTool({name:'export_report',arguments:{scan_id:scan.scan_id,include_sensitive_values:true}});assert.equal(invalid.isError,true);assert.equal(invalid.content[0].text,'invalid_private_evidence');await unlink(privatePath);await writeFile(privatePath,privateText,{mode:0o600});
  const deleted=await call('delete_scan',{scan_id:scan.scan_id});assert.equal(deleted.deleted,true);await assert.rejects(access(privatePath));await assert.rejects(access(full.path));
  assert.ok((await readFile(join(root,platform+'.zip'))).length>0);
 }
});
