import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {execFileSync,spawnSync} from 'node:child_process';
import {Client} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
const sdk=spawnSync('xcrun',['--sdk','iphoneos','--show-sdk-path']).status===0;
test('IPA MCP: compiled multi-architecture app/framework, encrypted extension, malformed image and redaction',{timeout:60000,skip:sdk?false:'Xcode iPhoneOS SDK required'},async t=>{
 const root=await mkdtemp(join(tmpdir(),'app-security-ios-'));t.after(()=>rm(root,{recursive:true,force:true}));
 execFileSync('python3',['test/fixtures/build-ios-fixture.py',root]);
 const client=new Client({name:'ios-native-test',version:'1'});
 await client.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,'store'),APP_SECURITY_REA_COMMAND:''},stderr:'ignore'}));
 try{
  const call=async(name,args)=>{const r=await client.callTool({name,arguments:args});assert.ok(!r.isError,JSON.stringify(r));return r.structuredContent;};
  const artifact=await call('import_local_artifact',{path:join(root,'fixture.ipa'),expected_platform:'ios'});
  for(const limit of [0,-1,20001,1.5,true,'2000']){const invalid=await client.callTool({name:'scan_ios_hardcoding',arguments:{artifact_id:artifact.artifact_id,ios_decode_attempt_limit:limit}});assert.ok(invalid.isError);}
  const task=await call('scan_ios_hardcoding',{artifact_id:artifact.artifact_id});let s;
  for(let i=0;i<200;i++){s=await call('get_scan_status',{scan_id:task.scan_id});if(!['queued','running'].includes(s.state))break;await new Promise(r=>setTimeout(r,20));}
  assert.equal(s.state,'partial');assert.equal(s.ios_native_scan.component_count,3);
  assert.equal(s.scan_options.ios_decode_attempt_limit,2000);
  const small=await call('scan_ios_hardcoding',{artifact_id:artifact.artifact_id,ios_decode_attempt_limit:1});let low;
  do{await new Promise(r=>setTimeout(r,20));low=await call('get_scan_status',{scan_id:small.scan_id});}while(['queued','running'].includes(low.state));
  assert.equal(low.state,'partial');assert.equal(low.scan_options.ios_decode_attempt_limit,1);
  const slices=low.ios_native_scan.files.flatMap(f=>f.slices??[]);assert.ok(slices.some(s=>s.literal_decoding?.skipped_budget>0));assert.ok(slices.filter(s=>s.literal_decoding).every(s=>s.literal_decoding.attempt_limit===1&&s.literal_decoding.attempts<=1));assert.ok(low.finding_count<s.finding_count);
  const comparison=await call('compare_scans',{before_scan_id:small.scan_id,after_scan_id:task.scan_id});assert.equal(comparison.settings_match,false);assert.ok(comparison.warnings.includes('scan_options_mismatch_or_missing'));assert.ok(comparison.summary.newly_detected>0);
  const files=s.ios_native_scan.files;
  const main=files.find(f=>f.path==='Payload/Test.app/App');assert.deepEqual(main.slices.map(s=>s.architecture).sort(),['arm64','x86_64']);
  assert.ok(main.slices.every(s=>s.status==='literal_pass_finished'));
  const extension=files.find(f=>f.path.endsWith('/Share'));assert.equal(extension.status,'blocked');assert.equal(extension.slices[0].reason,'encrypted_macho_slice');assert.equal(extension.slices[0].strings_checked,0);
  assert.equal(files.find(f=>f.path.endsWith('Bad.dylib')).status,'blocked');
  const {findings}=await call('list_findings',{scan_id:task.scan_id,limit:100});assert.equal(findings.length,9);
  assert.ok(findings.every(f=>f.value==='[REDACTED]'&&['native_literal_only','native_decoded_literal_only'].includes(f.evidence.usage)));
  assert.equal(findings.filter(f=>f.evidence.transform==='base64_one_layer').length,3);assert.equal(findings.filter(f=>f.evidence.transform==='hex_one_layer').length,3);assert.equal(extension.slices[0].literal_decoding.attempts,0);
  assert.ok(!findings.some(f=>f.evidence.component_role==='extension'));
  assert.ok(findings.some(f=>f.evidence.component_role==='framework'));
  assert.ok(findings.every(f=>f.evidence.member_sha256&&f.evidence.slice_sha256&&Number.isInteger(f.evidence.file_offset)&&f.evidence.virtual_address.startsWith('0x')));
  const chosen=findings.find(f=>f.evidence.path==='Payload/Test.app/App'&&f.evidence.architecture==='arm64').evidence;
  const extractArgs={storage_root:join(root,'store'),artifact_id:artifact.artifact_id,artifact_sha256:artifact.sha256,member:chosen.path,member_sha256:chosen.member_sha256,slice_index:chosen.slice_index,slice_sha256:chosen.slice_sha256,output:join(root,'selected.macho')};
  const extract=args=>JSON.parse(execFileSync('python3',['workers/ios_extract.py'],{input:JSON.stringify(args),encoding:'utf8'}));
  assert.equal(extract(extractArgs).ok,true);
  assert.equal(createHash('sha256').update(await readFile(extractArgs.output)).digest('hex'),chosen.slice_sha256);
  assert.equal(extract({...extractArgs,slice_sha256:'0'.repeat(64),output:join(root,'bad.macho')}).error,'macho_slice_digest_mismatch');
  assert.equal(extract({...extractArgs,artifact_sha256:'0'.repeat(64)}).error,'artifact_digest_mismatch');
  assert.equal(extract({...extractArgs,member:extension.path,member_sha256:extension.member_sha256,slice_index:0,slice_sha256:extension.slices[0].slice_sha256,output:join(root,'encrypted.macho')}).error,'encrypted_macho_slice');
  const verification=await call('verify_ios_finding',{scan_id:task.scan_id,finding_id:findings[0].finding_id,procedure:'_fixture_secret'});assert.equal(verification.status,'blocked');
  for(const format of ['json','markdown']){const report=await call('export_report',{scan_id:task.scan_id,format});const body=await readFile(report.path,'utf8');assert.ok(!body.includes('fixture-ios-secret-123')&&!body.includes('public-ios-client-456'));assert.ok(!body.includes('fixture-ios-encoded-token')&&!body.includes('fixture-ios-hex-secret'));assert.ok(body.includes('encrypted_macho_slice'));}
  execFileSync('python3',['-c',String.raw`
import sys,zipfile,plistlib
from pathlib import Path
p=Path(sys.argv[1])
with zipfile.ZipFile(p/'wrapped.ipa','w') as z:
 z.writestr('Payload/Wrapper.app/Info.plist',plistlib.dumps({'CFBundleIdentifier':'example.wrapper'}))
 z.writestr('Payload/Wrapper.app/assets/embedded.zip',(p/'fixture.ipa').read_bytes())
`,root]);
  const wrapped=await call('import_local_artifact',{path:join(root,'wrapped.ipa')});const nested=await call('scan_ios_hardcoding',{artifact_id:wrapped.artifact_id});let nestedStatus;
  do{await new Promise(r=>setTimeout(r,20));nestedStatus=await call('get_scan_status',{scan_id:nested.scan_id});}while(['queued','running'].includes(nestedStatus.state));
  assert.equal(nestedStatus.state,'partial');assert.equal(nestedStatus.nested_archive_scan.archives_checked,1);
  const nestedPage=await call('list_findings',{scan_id:nested.scan_id,limit:100});assert.equal(nestedPage.findings.length,9);
  const n=nestedPage.findings.find(f=>f.evidence.architecture==='arm64'&&f.evidence.member_path==='Payload/Test.app/App').evidence;
  assert.equal(n.archive_chain.length,1);assert.ok(n.path.includes('embedded.zip!/'));
  const nestedArgs={...extractArgs,artifact_id:wrapped.artifact_id,artifact_sha256:wrapped.sha256,member:n.member_path,archive_chain:n.archive_chain,member_sha256:n.member_sha256,slice_index:n.slice_index,slice_sha256:n.slice_sha256,output:join(root,'nested.macho')};
  assert.equal(extract(nestedArgs).ok,true);assert.equal(createHash('sha256').update(await readFile(nestedArgs.output)).digest('hex'),n.slice_sha256);
  assert.equal(extract({...nestedArgs,archive_chain:[{...n.archive_chain[0],sha256:'0'.repeat(64)}],output:join(root,'bad-nested.macho')}).error,'nested_digest_mismatch');
 }finally{await client.close();}
});

test('Mach-O boundaries: 32/64 endian, fat64 offsets, overlap, bad load commands and UTF16',()=>{
 const result=execFileSync('python3',['-c',String.raw`
import sys,struct,time
sys.path.insert(0,'workers')
from ios_macho import inspect

def thin(endian='<',bits=64,utf16=False):
 h=32 if bits==64 else 28;seg=72 if bits==64 else 56;sect=80 if bits==64 else 68
 content='password=fixture-unit-secret'.encode('utf-16-le' if endian=='<' else 'utf-16-be')+b'\0\0' if utf16 else b'password=fixture-unit-secret\0'
 size=512+len(content);cpu=0x100000c if bits==64 else 12
 head=struct.pack(endian+'IIIIIII',0xfeedfacf if bits==64 else 0xfeedface,cpu,0,2,1,seg+sect,0)+(b'\0'*4 if bits==64 else b'')
 command=struct.pack(endian+'II16s',0x19 if bits==64 else 1,seg+sect,b'__TEXT')
 command+=struct.pack(endian+('QQQQIIII' if bits==64 else 'IIIIIIII'),0x1000,size,0,size,7,5,1,0)
 section=struct.pack('16s16s',b'__ustring' if utf16 else b'__cstring',b'__TEXT')
 section+=struct.pack(endian+('QQIIIIIIII' if bits==64 else 'IIIIIIIII'),0x1200,len(content),512,0,0,0,0 if utf16 else 2,0,0,*([0] if bits==64 else []))
 return (head+command+section).ljust(512,b'\0')+content
for endian in ('<','>'):
 for bits in (32,64):
  for utf16 in (False,True):
   seen=[];r=inspect(thin(endian,bits,utf16),lambda v,c:seen.append((v,c)),time.monotonic()+5)
   assert r[0]['status']=='literal_pass_finished',r
   assert len(seen)==1 and seen[0][1]['file_offset']==512 and seen[0][1]['virtual_address']=='0x1200'
blob=thin();fat=struct.pack('>II',0xcafebabf,1)+struct.pack('>IIQQII',0x100000c,0,4096,len(blob),12,0)
seen=[];r=inspect(fat.ljust(4096,b'\0')+blob,lambda v,c:seen.append(c),time.monotonic()+5);assert seen[0]['file_offset']==4608
bad=bytearray(blob);struct.pack_into('<I',bad,36,0);r=inspect(bad,lambda *a:None,time.monotonic()+5);assert r[0]['status']=='blocked'
fat=struct.pack('>II',0xcafebabe,2)+struct.pack('>IIIII',0x100000c,0,4096,len(blob),12)*2
try:inspect(fat.ljust(4096,b'\0')+blob,lambda *a:None,time.monotonic()+5)
except ValueError as e:assert str(e)=='macho_slices_overlap'
else:raise AssertionError('overlap accepted')
print('ok')
`],{encoding:'utf8'});assert.equal(result.trim(),'ok');
});
