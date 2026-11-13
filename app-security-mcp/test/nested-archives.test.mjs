import {test} from 'node:test';import assert from 'node:assert/strict';import {mkdtemp,rm,readFile,access} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import {execFileSync} from 'node:child_process';import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
test('nested ZIP validation: CRC, entry budget, immutable chain and digest mismatch',()=>{
 const result=execFileSync('python3',['-c',String.raw`
import sys,io,zipfile,hashlib,time
sys.path.insert(0,'workers')
from nested_archives import NestedArchiveView,read_chained_member

def archive(entries):
 b=io.BytesIO()
 with zipfile.ZipFile(b,'w') as z:
  for name,data in entries:z.writestr(name,data)
 return b.getvalue()
def view(data):
 outer=archive([('inner.zip',data)])
 return zipfile.ZipFile(io.BytesIO(outer)),{'inner.zip':{'sha256':hashlib.sha256(data).hexdigest()}}
blob=archive([('config.json',b'fixture-crc-payload')]);root,expected=view(blob)
with root,NestedArchiveView(root,expected,time.monotonic()+10) as z:
 assert z.stats['archives_checked']==1 and z.stats['nested_entries']==1
 key=next(k for k in z.metadata)
 assert z.read(key)==b'fixture-crc-payload'
 chain=z.metadata[key]['archive_chain']
 assert read_chained_member(root,chain,'config.json',100)==b'fixture-crc-payload'
 try:read_chained_member(root,[dict(chain[0],sha256='wrong')],'config.json',100);raise AssertionError('wrong chain accepted')
 except ValueError as e:assert str(e)=='nested_digest_mismatch'
root,expected=view(blob)
expected['inner.zip']['sha256']='wrong'
with root:
 try:NestedArchiveView(root,expected,time.monotonic()+10);raise AssertionError('wrong source accepted')
 except ValueError as e:assert str(e)=='member_digest_mismatch'
corrupt=bytearray(blob);corrupt[corrupt.index(b'fixture-crc-payload')]=ord('X')
root,expected=view(corrupt)
with root,NestedArchiveView(root,expected,time.monotonic()+10) as z:
 assert z.stats['archives_checked']==0 and z.stats['archives_blocked']==1
 assert z.stats['failures'][0]['reason']=='nested_invalid_zip_or_crc'
root,expected=view(archive([(str(i),b'') for i in range(5001)]))
with root,NestedArchiveView(root,expected,time.monotonic()+10) as z:
 assert z.stats['failures'][0]['reason']=='nested_entry_count_limit'
print('ok')
`],{encoding:'utf8'});assert.equal(result.trim(),'ok');
});
test('APK/IPA nested resources: recursion, archive identity, ambiguous display paths, hostile entries and redaction',{timeout:30000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'nested-resource-'));t.after(()=>rm(root,{recursive:true,force:true}));
 execFileSync('python3',['-c',String.raw`
import io,sys,zipfile,json,plistlib,stat,warnings
from pathlib import Path
warnings.simplefilter('ignore')
p=Path(sys.argv[1])
def arc(entries):
 b=io.BytesIO()
 with zipfile.ZipFile(b,'w') as z:
  for name,data in entries:z.writestr(name,data)
 return b.getvalue()
third=arc([('unread.json',json.dumps({'password':'fixture-unread-secret'}))])
inner=arc([('deep.plist',plistlib.dumps({'access_token':'fixture-deep-token'})),('third.zip',third)])
outer=arc([('config.json',json.dumps({'password':'fixture-nested-password'})),('inner.zip',inner)])
link=zipfile.ZipInfo('link');link.create_system=3;link.external_attr=(stat.S_IFLNK|0o777)<<16
for platform in ('android','ios'):
 with zipfile.ZipFile(p/(platform+'.zip'),'w') as z:
  prefix='assets/' if platform=='android' else 'Payload/Test.app/'
  if platform=='android':z.writestr('AndroidManifest.xml','fixture')
  else:z.writestr(prefix+'Info.plist',plistlib.dumps({'CFBundleIdentifier':'example.fixture'}))
  z.writestr(prefix+'bundle.bin',outer)
  z.writestr(prefix+'bundle.bin!/config.json',json.dumps({'password':'fixture-root-password'}))
  z.writestr(prefix+'bad.zip',arc([('../escape.json',json.dumps({'password':'fixture-escape-password'}))]))
  z.writestr(prefix+'duplicate.zip',arc([('dup.json','{}'),('dup.json','{}')]))
  z.writestr(prefix+'symlink.zip',arc([(link,'target')]))
  z.writestr(prefix+'token=fixture-label-secret.zip',arc([('value.json',json.dumps({'password':'fixture-redacted-path-value'}))]))
`,root],{stdio:['ignore','pipe','pipe']});
 const c=new Client({name:'nested-resource-test',version:'1'});await c.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,'store')},stderr:'ignore'}));t.after(()=>c.close());
 const call=async(name,args)=>{const r=await c.callTool({name,arguments:args});assert.ok(!r.isError,JSON.stringify(r));return r.structuredContent;};
 for(const platform of ['android','ios']){
  const imported=await call('import_local_artifact',{path:join(root,platform+'.zip')});const scan=await call('scan_'+platform+'_hardcoding',{artifact_id:imported.artifact_id});let status;
  for(let i=0;i<300;i++){status=await call('get_scan_status',{scan_id:scan.scan_id});if(!['queued','running'].includes(status.state))break;await new Promise(r=>setTimeout(r,20));}
  assert.equal(status.state,'partial');assert.equal(status.nested_archive_scan.archives_checked,3);assert.equal(status.nested_archive_scan.archives_blocked,4);
  assert.deepEqual(status.nested_archive_scan.failures.map(f=>f.reason).sort(),['nested_depth_limit','nested_duplicate_entry','nested_special_entry','nested_unsafe_path']);
  const page=await call('list_findings',{scan_id:scan.scan_id,limit:100});assert.equal(page.findings.length,4);
  const collision=page.findings.filter(f=>f.evidence.path.endsWith('bundle.bin!/config.json'));assert.equal(collision.length,2);assert.equal(collision.filter(f=>f.evidence.archive_chain?.length===1).length,1);
  const comparison=await call('compare_scans',{before_scan_id:scan.scan_id,after_scan_id:scan.scan_id});assert.equal(comparison.groups.length,4);
  const deep=page.findings.find(f=>f.rule_id==='HC-002');assert.equal(deep.evidence.archive_chain.length,2);assert.equal(deep.evidence.member_path,'deep.plist');
  const redacted=page.findings.find(f=>f.evidence.archive_path_redacted);assert.ok(redacted);
  const evidence=await call('read_evidence',{scan_id:scan.scan_id,evidence_id:deep.evidence_id});assert.equal(evidence.evidence.archive_chain[0].sha256.length,64);
  const report=await call('export_report',{scan_id:scan.scan_id,format:'json'});const text=await readFile(report.path,'utf8');
  for(const value of ['fixture-nested-password','fixture-deep-token','fixture-unread-secret','fixture-root-password','fixture-escape-password','fixture-label-secret','fixture-redacted-path-value'])assert.ok(!text.includes(value));
 }
 await assert.rejects(access(join(root,'escape.json')));
});
