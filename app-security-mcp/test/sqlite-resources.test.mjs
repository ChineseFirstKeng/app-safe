import {test} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {Client} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';

test('SQLite reader: budgets, hostile views, generated columns, bad headers and deadline',()=>{
 const output=execFileSync('python3',['-c',String.raw`
import sys,sqlite3,tempfile,time
from pathlib import Path
sys.path.insert(0,'workers')
from sqlite_resources import inspect
with tempfile.TemporaryDirectory() as root:
 p=Path(root)/'x.db';c=sqlite3.connect(str(p))
 c.execute('create table records(password text, payload blob, huge text)')
 c.executemany('insert into records values(?,?,?)',[('synthetic-fixture-password',b'x','y'*4097)]*1001)
 c.execute("create view a_view as select load_extension('/must-not-run')")
 c.commit();c.close();rows=[]
 r=inspect(p.read_bytes(),lambda row,context:rows.append((row,context)),time.monotonic()+5)
 assert r['tables_skipped']==1 and r['row_limit_reached'] and r['rows_checked']==1000
 assert r['cells_skipped']==2000 and len(rows)==1000
 assert rows[0][0]=={'password':'synthetic-fixture-password'}
 for data in (b'encrypted or not a database',b'SQLite format 3\x00'+b'x'*100):
  try:inspect(data,lambda *a:None,time.monotonic()+5);raise AssertionError('accepted bad data')
  except ValueError:pass
 try:inspect(p.read_bytes(),lambda *a:None,time.monotonic()-1);raise AssertionError('missed deadline')
 except ValueError:pass
 if sqlite3.sqlite_version_info >= (3,31,0):
  p2=Path(root)/'generated.db';c=sqlite3.connect(str(p2));c.execute('create table t(password text, computed text generated always as (upper(password)))');c.execute("insert into t(password) values('synthetic-secret')");c.commit();c.close()
  r=inspect(p2.read_bytes(),lambda *a:(_ for _ in ()).throw(AssertionError('evaluated generated column')),time.monotonic()+5)
  assert r['tables_skipped']==1
print('ok')
`],{encoding:'utf8'});assert.equal(output.trim(),'ok');
});

test('SQLite packaged in APK/IPA: credentials, contacts, negative controls, evidence and redaction',{timeout:30000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'sqlite-resources-'));t.after(()=>rm(root,{recursive:true,force:true}));
 execFileSync('python3',['-c',String.raw`
import sqlite3,zipfile,plistlib,sys
from pathlib import Path
p=Path(sys.argv[1]);c=sqlite3.connect(str(p/'fixture.db'))
c.execute('create table settings(password text, client_secret text, access_token text, url text, api_key text)')
c.execute('insert into settings values(?,?,?,?,?)',('fixture-db-password-543','fixture-db-secret-321','fixture-db-token-654','redis://user:fixture-redis-secret@localhost','fixture-public-key-456'))
c.execute('create table people(fullname text,email text)');c.execute('insert into people values(?,?)',('Lena Morrison','lena@business.org'))
c.execute('create table negative(password text)');c.executemany('insert into negative values(?)',[('placeholder',),('$'+'{PASSWORD}',)])
c.execute("create view hostile as select load_extension('/must-not-run')")
c.commit();c.close()
for platform in ('android','ios'):
 with zipfile.ZipFile(p/(platform+'.zip'),'w',compression=zipfile.ZIP_STORED) as z:
  prefix='assets/' if platform=='android' else 'Payload/Test.app/'
  if platform=='android':z.writestr('AndroidManifest.xml','fixture')
  else:z.writestr(prefix+'Info.plist',plistlib.dumps({'CFBundleIdentifier':'example.fixture'}))
  z.writestr(prefix+'offline-data', (p/'fixture.db').read_bytes())
  z.writestr(prefix+'encrypted.db', b'opaque fake database fixture')
`,root],{stdio:['ignore','pipe','pipe']});
 const c=new Client({name:'sqlite-test',version:'1'});await c.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,'store')},stderr:'ignore'}));t.after(()=>c.close());
 const call=async(name,args)=>{const r=await c.callTool({name,arguments:args});assert.ok(!r.isError,JSON.stringify(r));return r.structuredContent;};
 for(const platform of ['android','ios']){
  const artifact=await call('import_local_artifact',{path:join(root,platform+'.zip')});const scan=await call('scan_'+platform+'_hardcoding',{artifact_id:artifact.artifact_id});let status;
  for(let i=0;i<200;i++){status=await call('get_scan_status',{scan_id:scan.scan_id});if(!['queued','running'].includes(status.state))break;await new Promise(r=>setTimeout(r,20));}
  assert.equal(status.state,'partial');assert.equal(status.sqlite_scan.files.length,2);
  assert.equal(status.sqlite_scan.files.find(f=>f.path.endsWith('encrypted.db')).reason,'sqlite_header_invalid_or_encrypted');
  const file=status.sqlite_scan.files.find(f=>f.path.endsWith('offline-data'));assert.equal(file.tables_checked,3,JSON.stringify(file));assert.equal(file.tables_skipped,1);
  const page=await call('list_findings',{scan_id:scan.scan_id,limit:100});assert.deepEqual(page.findings.map(f=>f.rule_id).sort(),['HC-001','HC-002','HC-003','HC-004','HC-011']);
  for(const f of page.findings){const e=await call('read_evidence',{scan_id:scan.scan_id,evidence_id:f.evidence_id});assert.equal(e.evidence.usage,'sqlite_table_record');assert.ok(e.evidence.member_sha256);}
  const report=await call('export_report',{scan_id:scan.scan_id,format:'json'});const body=await readFile(report.path,'utf8');
  for(const value of ['fixture-db-password-543','fixture-db-secret-321','fixture-db-token-654','fixture-redis-secret','fixture-public-key-456','Lena Morrison','lena@business.org'])assert.ok(!body.includes(value));
 }
});
