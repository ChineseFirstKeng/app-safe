import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

test('artifact import: real MCP, content identity, pagination, dangerous ZIP rejection and deletion', { timeout: 30000 }, async t => {
 const root=await mkdtemp(join(tmpdir(),'app-security-artifacts-'));
 t.after(()=>rm(root,{recursive:true,force:true}));
 execFileSync('python3',['-c',`
import zipfile,sys,os,stat
from pathlib import Path
p=Path(sys.argv[1])
def make(name,entries):
 with zipfile.ZipFile(p/name,'w') as z:
  for n,v in entries:z.writestr(n,v)
make('android.bin',[('AndroidManifest.xml',b'fixture'),('classes.dex',b'dex fixture'),('assets/data.json',b'{}')])
make('ios.ipa',[('Payload/Test.app/Info.plist',b'fixture'),('Payload/Test.app/Test',b'binary fixture')])
make('bad.apk',[('hello.txt',b'x')])
make('traversal.apk',[('AndroidManifest.xml',b'fixture'),('../escape',b'x')])
make('conflict.apk',[('AndroidManifest.xml',b'fixture'),('assets',b'x'),('assets/file',b'x')])
make('duplicate.apk',[('AndroidManifest.xml',b'a'),('AndroidManifest.xml',b'b')])
i=zipfile.ZipInfo('link');i.create_system=3;i.external_attr=(stat.S_IFLNK|0o777)<<16
make('symlink.apk',[('AndroidManifest.xml',b'fixture'),(i,b'/etc/passwd')])
make('crc.apk',[('AndroidManifest.xml',b'UNIQUE_MARKER')])
f=p/'crc.apk';f.write_bytes(f.read_bytes().replace(b'UNIQUE_MARKER',b'BROKEN_MARKER'))
with zipfile.ZipFile(p/'bomb.apk','w',compression=zipfile.ZIP_DEFLATED) as z:
 z.writestr('AndroidManifest.xml',b'x'*1000000)
os.symlink(p/'android.bin',p/'link.apk')
`,root],{stdio:['ignore','pipe','pipe']});
 const client=new Client({name:'artifact-test',version:'1'});
 const transport=new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY ?? new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,'store')},stderr:'pipe'});
 await client.connect(transport);t.after(()=>client.close());
 const call=(name,args)=>client.callTool({name,arguments:args});
 for(const [file,platform] of [['android.bin','android'],['ios.ipa','ios']]) {
  const r=await call('import_local_artifact',{path:join(root,file),expected_platform:platform});assert.ok(!r.isError,JSON.stringify(r));
  const data=r.structuredContent;
  assert.equal(data.sha256,createHash('sha256').update(await readFile(join(root,file))).digest('hex'));
  assert.equal(data.platform,platform);assert.equal(data.coverage.hardcoding_detection,'not_run');assert.equal(data.format_confidence,'structural_candidate');
  const wrong=await call(platform==='android'?'scan_ios_hardcoding':'scan_android_hardcoding',{artifact_id:data.artifact_id});
  assert.equal(wrong.isError,true);assert.equal(wrong.content[0].text,'platform_mismatch');
  const start=await call(`scan_${platform}_hardcoding`,{artifact_id:data.artifact_id});
  assert.equal(start.structuredContent.state,'queued');
  const scanId=start.structuredContent.scan_id;
  let status;
  for(let i=0;i<30;i++) {
    status=(await call('get_scan_status',{scan_id:scanId})).structuredContent;
    if(!['queued','running'].includes(status.state))break;
    await new Promise(r=>setTimeout(r,10));
  }
  assert.equal(status.state,'partial');assert.equal(status.finding_count,0);
  assert.equal(status.rules.length,12);assert.equal(status.rules.filter(r=>r.status==='not_run').length,4);
  assert.equal(status.artifact_sha256,data.sha256);
  // Seed persisted in-flight records to exercise cancellation and crashed-owner recovery deterministically.
  const queuedId=platform==='android'?'a'.repeat(32):'b'.repeat(32);
  await writeFile(join(root,'store','_scans',queuedId+'.json'),JSON.stringify({...status,scan_id:queuedId,state:'queued',owner_pid:process.pid}));
  assert.equal((await call('cancel_scan',{scan_id:queuedId})).content[0].text,'scan_owned_by_another_process');
  await writeFile(join(root,'store','_scans',queuedId+'.json'),JSON.stringify({...status,scan_id:queuedId,state:'queued',owner_pid:2147483647}));
  assert.equal((await call('get_scan_status',{scan_id:queuedId})).structuredContent.state,'failed');
  const deadId=platform==='android'?'c'.repeat(32):'d'.repeat(32);
  await writeFile(join(root,'store','_scans',deadId+'.json'),JSON.stringify({...status,scan_id:deadId,state:'running',owner_pid:2147483647}));
  assert.equal((await call('get_scan_status',{scan_id:deadId})).structuredContent.state,'failed');

  assert.equal((await call('cancel_scan',{scan_id:scanId})).structuredContent.reason,'already_terminal');
  for(const format of ['json','markdown']) {
    const report=(await call('export_report',{scan_id:scanId,format})).structuredContent;
    const body=await readFile(report.path,'utf8');
    assert.ok(body.includes('not_run')&&body.includes('partial'));
    if(format==='json')assert.equal(JSON.parse(body).finding_count,0);
  }
  // Another server process must be able to read completed persisted results.
  const reader=new Client({name:'persisted-scan-reader',version:'1'});
  const readerTransport=new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY ?? new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,'store')},stderr:'pipe'});
  try {
    await reader.connect(readerTransport);
    assert.equal((await reader.callTool({name:'get_scan_status',arguments:{scan_id:scanId}})).structuredContent.state,'partial');
  } finally {await reader.close();}
  const page=await call('inspect_imported_artifact',{artifact_id:data.artifact_id,limit:1});assert.equal(page.structuredContent.entries.length,1);assert.equal(page.structuredContent.next_offset,1);
  const last=await call('inspect_imported_artifact',{artifact_id:data.artifact_id,offset:1});assert.equal(last.structuredContent.entries.length,data.entry_count-1);
  assert.equal((await call('delete_imported_artifact',{artifact_id:data.artifact_id})).isError,true);
  for(const scan_id of [scanId,queuedId,deadId])assert.equal((await call('delete_scan',{scan_id})).structuredContent.deleted,true);
  assert.equal((await call('delete_imported_artifact',{artifact_id:data.artifact_id})).structuredContent.deleted,true);
  assert.equal((await call('inspect_imported_artifact',{artifact_id:data.artifact_id})).isError,true);
  assert.ok((await readFile(join(root,file))).length>0);
 }
 for(const [file,reason] of [['bad.apk','unrecognized_package_layout'],['traversal.apk','unsafe_entry_path'],['conflict.apk','file_directory_conflict'],['duplicate.apk','duplicate_entry'],['symlink.apk','special_entry_not_supported'],['crc.apk','invalid_or_unsupported_zip'],['bomb.apk','compression_ratio_limit'],['link.apk','source_symlink']]) {
  const r=await call('import_local_artifact',{path:join(root,file)});assert.equal(r.isError,true,file);assert.ok(r.content[0].text.includes(reason),JSON.stringify(r));
 }
 assert.equal((await call('import_local_artifact',{path:join(root,'android.bin'),expected_platform:'ios'})).isError,true);
 assert.equal((await call('import_local_artifact',{path:'/dev/null'})).isError,true);
 assert.deepEqual((await readdir(join(root,'store'))).sort(),['_capacity','_locks','_scans']);
 assert.equal((await call('get_scan_status',{scan_id:'0'.repeat(32)})).isError,true);
});
