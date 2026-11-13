import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

 test('persisted evidence and deletion: references, other processes, leases and exact report scope', {timeout:15000}, async t => {
  const root=await mkdtemp(join(tmpdir(),'scan-storage-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const clients=[];
  for(let i=0;i<2;i++) {
    const c=new Client({name:'storage-test',version:'1'});
    await c.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:root},stderr:'ignore'}));
    clients.push(c);t.after(()=>c.close());
  }
  const call=async(name,args,index=0)=>clients[index].callTool({name,arguments:args});
  const ok=async(name,args,index=0)=>{const r=await call(name,args,index);assert.notEqual(r.isError,true,JSON.stringify(r));return r.structuredContent;};
  const fails=async(name,args,reason,index=0)=>{const r=await call(name,args,index);assert.equal(r.isError,true);assert.ok(r.content[0].text.includes(reason),r.content[0].text);};
  const artifact='a'.repeat(32), scan='b'.repeat(32), other='c'.repeat(32);
  const scanRoot=join(root,'_scans');await mkdir(scanRoot);await mkdir(join(root,artifact));
  await writeFile(join(root,artifact,'inventory.json'),'{}');
  const record={schema_version:'0.1',scan_id:scan,artifact_id:artifact,artifact_sha256:'d'.repeat(64),state:'partial',platform:'android',scanner_version:'fixture',ruleset_version:'fixture',limitations:['fixture'],finding_count:1,findings:[{finding_id:'f-0001',evidence_id:'e-f-0001',verification_level:'candidate',value:'[REDACTED]',evidence:{path:'assets/config.json',location:1,member_sha256:'e'.repeat(64)}}]};
  const save=()=>writeFile(join(scanRoot,scan+'.json'),JSON.stringify(record));await save();
  const e=await ok('read_evidence',{scan_id:scan,evidence_id:'e-f-0001'});
  assert.equal(e.artifact_sha256,record.artifact_sha256);assert.deepEqual(e.evidence,record.findings[0].evidence);assert.equal(e.next_cursor,null);assert.equal(e.source_complete,false);
  await fails('read_evidence',{scan_id:scan,evidence_id:'e-f-0002'},'evidence_not_found');
  await fails('read_evidence',{scan_id:scan,evidence_id:'../../outside'},'');
  await fails('delete_imported_artifact',{artifact_id:artifact},'artifact_referenced_by_scan',1);
  record.state='running';record.owner_pid=process.pid;await save();
  await fails('delete_scan',{scan_id:scan},'scan_still_active');
  await fails('cancel_scan',{scan_id:scan},'scan_owned_by_another_process',1);
  record.state='partial';await save();
  // A held lease models a verifier in either process. All conflicting mutations fail closed.
  await mkdir(join(root,'_locks',artifact));
  await fails('delete_scan',{scan_id:scan},'artifact_operation_busy',1);
  await fails('export_report',{scan_id:scan},'artifact_operation_busy');
  await fails('delete_imported_artifact',{artifact_id:artifact},'artifact_delete_blocked');
  await rm(join(root,'_locks',artifact),{recursive:true});
  const json=await ok('export_report',{scan_id:scan,format:'json'});
  const md=await ok('export_report',{scan_id:scan,format:'markdown'},1);
  const unrelated=join(scanRoot,other+'-'+other+'.json');await writeFile(unrelated,'keep');
  const outside=join(root,'outside');await writeFile(outside,'keep');
  await symlink(outside,join(scanRoot,scan+'-'+other+'.md'));
  const deleted=await ok('delete_scan',{scan_id:scan},1);
  assert.equal(deleted.reports_deleted,3);assert.equal(deleted.artifact_retained,true);
  for(const path of [json.path,md.path,join(scanRoot,scan+'.json')])await assert.rejects(access(path));
  assert.equal(await readFile(outside,'utf8'),'keep');assert.equal(await readFile(unrelated,'utf8'),'keep');await access(join(root,artifact));
  await fails('get_scan_status',{scan_id:scan},'scan_not_found_or_unreadable');
  await fails('delete_scan',{scan_id:scan},'scan_not_found_or_unreadable');
  await ok('delete_imported_artifact',{artifact_id:artifact});await assert.rejects(access(join(root,artifact)));
 });
