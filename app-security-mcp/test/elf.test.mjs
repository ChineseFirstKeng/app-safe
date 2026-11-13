import {test} from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';import {existsSync} from 'node:fs';import {join} from 'node:path';import {tmpdir} from 'node:os';import {execFileSync} from 'node:child_process';
import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
const bin=process.env.TEST_NDK_BIN??'/Users/h1610/Library/Android/sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin';
test('ELF MCP: four compiled ABIs, JNI exports, Base64/hex candidates, corruption, redaction and extraction',{timeout:60000,skip:existsSync(join(bin,'clang'))?false:'Android NDK required'},async t=>{
 const root=await mkdtemp(join(tmpdir(),'app-security-elf-'));t.after(()=>rm(root,{recursive:true,force:true}));
 execFileSync('python3',['test/fixtures/build-elf-fixture.py',root]);
 const c=new Client({name:'elf-test',version:'1'});await c.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,'store'),APP_SECURITY_REA_COMMAND:''},stderr:'ignore'}));
 try{
 const call=async(name,args)=>{const r=await c.callTool({name,arguments:args});assert.ok(!r.isError,JSON.stringify(r));return r.structuredContent;};
 const imported=await call('import_local_artifact',{path:join(root,'fixture.apk')});const task=await call('scan_android_hardcoding',{artifact_id:imported.artifact_id});let status;
 for(let i=0;i<200;i++){status=await call('get_scan_status',{scan_id:task.scan_id});if(!['queued','running'].includes(status.state))break;await new Promise(r=>setTimeout(r,20));}
 assert.equal(status.client_identifier_review.items.filter(i=>i.classification==='client_identifier'&&i.evidence.usage==='elf_literal_only').length,4);
 assert.equal(status.state,'partial');const native=status.android_native_scan;assert.equal(native.files_total,5);assert.equal(native.files_checked,4);assert.equal(native.failures.elf_magic_invalid,1);
 const valid=native.files.filter(f=>f.status!=='blocked');assert.ok(valid.every(f=>f.abi_matches_path&&f.jni_export_count===2&&f.jni_dynamic_registration==='not_analyzed'));
 const {findings}=await call('list_findings',{scan_id:task.scan_id,limit:100});assert.equal(findings.length,12);
 assert.equal(findings.filter(f=>f.evidence.transform==='base64_one_layer').length,4);assert.equal(findings.filter(f=>f.evidence.transform==='hex_one_layer').length,4);
 assert.ok(findings.every(f=>f.value==='[REDACTED]'&&Number.isInteger(f.evidence.file_offset)&&f.evidence.virtual_address.startsWith('0x')));
 const finding=findings.find(f=>f.evidence.architecture==='arm64-v8a'&&f.evidence.transform==='none');
 assert.equal((await call('verify_android_native_finding',{scan_id:task.scan_id,finding_id:finding.finding_id,procedure:'Java_example_Native_secret'})).status,'blocked');
 const e=finding.evidence;const req={storage_root:join(root,'store'),artifact_id:imported.artifact_id,artifact_sha256:imported.sha256,member:e.path,member_sha256:e.member_sha256,output:join(root,'out.so')};
 const extract=r=>JSON.parse(execFileSync('python3',['workers/elf_extract.py'],{input:JSON.stringify(r),encoding:'utf8'}));
 assert.equal(extract(req).ok,true);assert.equal(extract({...req,member_sha256:'0'.repeat(64)}).error,'member_digest_mismatch');
 for(const format of ['json','markdown']){const report=await call('export_report',{scan_id:task.scan_id,format});const body=await readFile(report.path,'utf8');for(const secret of ['fixture-native-elf-789','fixture-encoded-elf-123','fixture-hex-elf-456','public-client-123'])assert.ok(!body.includes(secret));}
 }finally{await c.close();}
});

test('ELF bounds, big endian and sectionless segment fallback',()=>{
 const output=execFileSync('python3',['-c',String.raw`
import sys,struct,time
sys.path.insert(0,'workers')
from android_elf import inspect,parse
for bits in (32,64):
 for endian in ('<','>'):
  wide=bits==64;h=64 if wide else 52;p=56 if wide else 32
  content=b'password=fixture-fallback-123\0'
  size=256+len(content)
  ident=b'\x7fELF'+bytes([2 if wide else 1,1 if endian=='<' else 2,1])+b'\0'*9
  data=ident+struct.pack(endian+('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'),3,183 if wide else 40,1,0,h,0,0,h,p,1,0,0,0)
  data+=struct.pack(endian+('IIQQQQQQ' if wide else 'IIIIIIII'),*([1,4,256,0x100,0x100,len(content),len(content),1] if wide else [1,256,0x100,0x100,len(content),len(content),4,1]))
  data=data.ljust(256,b'\0')+content
  found=[];r=inspect(data,lambda v,c:found.append(c),time.monotonic()+5)
  assert r['status']=='partial' and len(found)==1 and found[0]['file_offset']==256
  broken=bytearray(data);struct.pack_into(endian+('Q' if wide else 'I'),broken,h+(32 if wide else 16),999999)
  try:parse(bytes(broken))
  except ValueError:pass
  else:raise AssertionError('out of bounds accepted')
print('ok')
`],{encoding:'utf8'});assert.equal(output.trim(),'ok');
});
