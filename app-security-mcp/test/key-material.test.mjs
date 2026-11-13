import {test} from 'node:test';import assert from 'node:assert/strict';import {generateKeyPairSync,X509Certificate} from 'node:crypto';import {execFileSync} from 'node:child_process';import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {rootCertificates} from 'node:tls';
import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
const fixtures=()=>{
 const rsa=generateKeyPairSync('rsa',{modulusLength:1024}),ec=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),ed=generateKeyPairSync('ed25519');
 const files={'certificate.pem':rootCertificates[0],'certificate.der':new X509Certificate(rootCertificates[0]).raw};for(const [label,pair,type] of [['rsa',rsa,'pkcs1'],['ec',ec,'sec1'],['ed',ed,'pkcs8']])for(const format of ['pem','der'])files[label+'.'+format]=pair.privateKey.export({format,type});
 files['pem.p8']=ed.privateKey.export({format:'pem',type:'pkcs8'});
 files['encrypted.der']=rsa.privateKey.export({format:'der',type:'pkcs8',cipher:'aes-256-cbc',passphrase:'synthetic-fixture-passphrase'});
 files['encrypted.pem']=rsa.privateKey.export({format:'pem',type:'pkcs8',cipher:'aes-256-cbc',passphrase:'synthetic-fixture-passphrase'});
 files['public.pem']=ed.publicKey.export({format:'pem',type:'spki'});files['public.der']=ed.publicKey.export({format:'der',type:'spki'});
 files['fake.pem']='-----BEGIN PRIVATE KEY-----\n'+Buffer.alloc(64,1).toString('base64')+'\n-----END PRIVATE KEY-----';return files;
};
test('key parsing: RSA/EC/Ed25519 PEM and DER, public and invalid negative controls, encrypted unknown',()=>{
 const files=fixtures();for(const [name,data] of Object.entries(files)){
  const format=name.endsWith('.der')?'der':'pem';const parsed=JSON.parse(execFileSync(process.execPath,['workers/key_validate.mjs'],{input:JSON.stringify({format,data:format==='der'?data.toString('base64'):data}),encoding:'utf8'}));
  assert.equal(parsed.status,name.startsWith('certificate')?'public_certificate':name==='fake.pem'?'invalid_or_unsupported':name.startsWith('public')?'public_key':name==='encrypted.pem'?'encrypted_or_unsupported_envelope':name==='encrypted.der'?'encrypted_container_requires_passphrase':'parsed_private_key',name);
  if(parsed.status==='parsed_private_key')assert.equal(parsed.algorithm,name.startsWith('rsa')?'rsa':name.startsWith('ec')?'ec':'ed25519');
  assert.ok(!JSON.stringify(parsed).includes('BEGIN'));
 }
 const out=execFileSync('python3',['-c',String.raw`
import sys,time
sys.path.insert(0,'workers')
from key_material import KeyValidator
v=KeyValidator(sys.argv[1],time.monotonic()+30)
for i in range(32):assert v.validate('invalid','pem')['status']=='invalid_or_unsupported'
assert v.stats['attempts']==32
assert v.validate('x','pem')['status']=='key_parse_budget_or_size_limit'
assert v.stats['budget_skipped']==1
v=KeyValidator(None,time.monotonic()+30)
assert v.validate('x','pem')['status']=='key_parser_unavailable'
print('ok')
`,process.execPath],{encoding:'utf8'});assert.equal(out.trim(),'ok');
});
test('APK/IPA key findings distinguish parsed private material from unresolved envelopes and exclude public keys',{timeout:30000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'key-material-'));t.after(()=>rm(root,{recursive:true,force:true}));const files=fixtures();
 const payload={};for(const [name,data] of Object.entries(files))payload[name]=Buffer.from(data).toString('base64');await writeFile(join(root,'files.json'),JSON.stringify(payload));
 execFileSync('python3',['-c',String.raw`
import sys,json,base64,zipfile,plistlib
from pathlib import Path
p=Path(sys.argv[1]);files=json.loads((p/'files.json').read_text())
for platform in ('android','ios'):
 with zipfile.ZipFile(p/(platform+'.zip'),'w') as z:
  prefix='assets/' if platform=='android' else 'Payload/App.app/'
  if platform=='android':z.writestr('AndroidManifest.xml','fixture')
  else:z.writestr(prefix+'Info.plist',plistlib.dumps({'CFBundleIdentifier':'example.fixture'}))
  for name,data in files.items():z.writestr(prefix+name,base64.b64decode(data))
`,root],{stdio:['ignore','pipe','pipe']});
 const c=new Client({name:'key-validation-test',version:'1'});await c.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,'store')},stderr:'ignore'}));t.after(()=>c.close());
 const call=async(name,args)=>{const r=await c.callTool({name,arguments:args});assert.ok(!r.isError,JSON.stringify(r));return r.structuredContent;};
 for(const platform of ['android','ios']){
  const artifact=await call('import_local_artifact',{path:join(root,platform+'.zip')});const task=await call('scan_'+platform+'_hardcoding',{artifact_id:artifact.artifact_id});let status;
  for(let i=0;i<300;i++){status=await call('get_scan_status',{scan_id:task.scan_id});if(!['queued','running'].includes(status.state))break;await new Promise(r=>setTimeout(r,20));}
  assert.equal(status.state,'partial');assert.equal(status.key_material_scan.parsed,7);assert.equal(status.key_material_scan.public_material,2);assert.equal(status.key_material_scan.unresolved,2);
  const page=await call('list_findings',{scan_id:task.scan_id,limit:100});assert.equal(page.findings.length,9);assert.ok(page.findings.every(f=>f.rule_id==='HC-006'));assert.equal(page.findings.filter(f=>f.evidence.key_validation.status==='parsed_private_key').length,7);
  assert.ok(!page.findings.some(f=>/public|fake|certificate/.test(f.evidence.path)));
  const report=await call('export_report',{scan_id:task.scan_id,format:'json'});const text=await readFile(report.path,'utf8');assert.ok(!text.includes('-----BEGIN'));assert.ok(!text.includes('synthetic-fixture-passphrase'));
 }
});
