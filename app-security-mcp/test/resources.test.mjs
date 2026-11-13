import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,chmod,appendFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {execFileSync} from 'node:child_process';
import {Client} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';

test('resource findings: two platforms, negative controls, redaction, reports and snapshot tampering', {timeout:30000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'app-security-resource-test-'));
 t.after(()=>rm(root,{recursive:true,force:true}));
 execFileSync('python3',['-c',String.raw`
import zipfile,sys,json,plistlib,base64,subprocess
from pathlib import Path
p=Path(sys.argv[1])
private_pem=subprocess.check_output([sys.argv[2],'-e',"const c=require('node:crypto');process.stdout.write(c.generateKeyPairSync('ed25519').privateKey.export({format:'pem',type:'pkcs8'}));"]).decode()
for platform in ['android','ios']:
 with zipfile.ZipFile(p/(platform+'.bin'),'w') as z:
  if platform=='android':z.writestr('AndroidManifest.xml',b'fixture')
  else:z.writestr('Payload/Test.app/Info.plist',plistlib.dumps({'CFBundleIdentifier':'example.fixture'}))
  prefix='assets/' if platform=='android' else 'Payload/Test.app/'
  z.writestr(prefix+'config.json',json.dumps({'password':'fixture-password-123','client_secret':'fixture-secret-456','client_id':'public-client-999','api_key':'public-api-key-888','url':'https://example.invalid','placeholder':{'password':'$'+'{PASSWORD}'}}))
  z.writestr(prefix+'auth.plist',plistlib.dumps({'access_token':'fixture-token-789'},fmt=plistlib.FMT_BINARY))
  z.writestr(prefix+'network.conf','db=postgres://user:fixture-db-password@example.invalid/db\n'.replace('\n','\n'))
  z.writestr(prefix+'private.pem',private_pem)
  z.writestr(prefix+'strings.xml','<resources><string name="password">fixture-xml-secret-666</string></resources>')
  z.writestr(prefix+'utf16.ini','password=fixture-utf16-secret-777'.encode('utf-16'))
  z.writestr(prefix+'basic.txt','Authorization: Basic '+base64.b64encode(b'user:fixture-basic-password').decode())
  z.writestr(prefix+'public.pem','-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(bytes(range(64))).decode()+'\n-----END PUBLIC KEY-----')
  z.writestr(prefix+'binary.xml',b'\x00\x01\x00\x02')
  z.writestr(prefix+'broken.json','{"password":"fixture-broken-555",')
with zipfile.ZipFile(p/'capped.apk','w') as z:
 z.writestr('AndroidManifest.xml',b'fixture')
 z.writestr('assets/many.json',json.dumps([{'password':'fixture-many-'+str(i)} for i in range(305)]))
 z.writestr('assets/large.txt',b'x'*(2*1024*1024+1))
`,root,process.execPath],{stdio:['ignore','pipe','pipe']});
 const client=new Client({name:'resource-test',version:'1'});
 const transport=new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,'store')},stderr:'pipe'});
 await client.connect(transport);t.after(()=>client.close());
 const call=(name,args)=>client.callTool({name,arguments:args});
 const wait=async scan_id=>{for(let i=0;i<100;i++){const r=await call('get_scan_status',{scan_id});assert.ok(!r.isError);if(!['queued','running'].includes(r.structuredContent.state))return r.structuredContent;await new Promise(r=>setTimeout(r,10));}throw new Error('scan did not finish');};
 const capped=(await call('import_local_artifact',{path:join(root,'capped.apk')})).structuredContent;
 const capTask=(await call('scan_android_hardcoding',{artifact_id:capped.artifact_id})).structuredContent;
 const capStatus=await wait(capTask.scan_id);
 assert.equal(capStatus.finding_count,300);assert.equal(capStatus.resource_scan.findings_truncated,true);
 assert.equal(capStatus.resource_scan.skip_reason_counts.resource_size_limit,1);
 const firstPage=(await call('list_findings',{scan_id:capTask.scan_id,limit:1})).structuredContent;
 assert.equal(firstPage.findings.length,1);assert.equal(firstPage.next_offset,1);assert.equal(firstPage.findings_truncated,true);
 for(const platform of ['android','ios']){
  const imported=(await call('import_local_artifact',{path:join(root,platform+'.bin')})).structuredContent;
  assert.ok(imported);
  const created=(await call('scan_'+platform+'_hardcoding',{artifact_id:imported.artifact_id,profile:'static-deep'})).structuredContent;
  const status=await wait(created.scan_id);assert.equal(status.state,'partial',JSON.stringify(status));
  const page=(await call('list_findings',{scan_id:created.scan_id,limit:100})).structuredContent;
  assert.deepEqual([...new Set(page.findings.map(f=>f.rule_id))].sort(),['HC-001','HC-002','HC-003','HC-004','HC-006']);
  assert.ok(page.findings.every(f=>f.value==='[REDACTED]'&&f.verification_level==='candidate'&&f.remediation&&f.retest));
  assert.ok(!page.findings.some(f=>f.evidence.path.endsWith('public.pem')));
  assert.ok(status.resource_scan.skip_reason_counts.resource_parse_failed>=1);
  assert.ok(status.resource_scan.skip_reason_counts.binary_resource_not_decoded>=1);
  const one=(await call('get_finding',{scan_id:created.scan_id,finding_id:page.findings[0].finding_id})).structuredContent;
  assert.equal(one.artifact_sha256,imported.sha256);
  for(const format of ['json','markdown']){
   const report=(await call('export_report',{scan_id:created.scan_id,format})).structuredContent;
   const text=await readFile(report.path,'utf8');
   for(const secret of ['fixture-password-123','fixture-secret-456','fixture-token-789','fixture-db-password','fixture-xml-secret-666','fixture-utf16-secret-777','fixture-basic-password','fixture-broken-555'])assert.ok(!text.includes(secret));
   assert.ok(text.includes('remediation')&&text.includes('not_run'));
  }
  // Detect snapshot mutation rather than silently trusting import-time metadata.
  const path=join(root,'store',imported.artifact_id,'package.bin');await chmod(path,0o600);await appendFile(path,'tampered');
  const changed=(await call('scan_'+platform+'_hardcoding',{artifact_id:imported.artifact_id})).structuredContent;
  const failed=await wait(changed.scan_id);assert.equal(failed.state,'failed');assert.ok(failed.limitations.includes('artifact_digest_mismatch'));assert.equal(failed.finding_count,null);
 }
});
