import {test} from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';import {join} from 'node:path';import {tmpdir} from 'node:os';import {execFileSync} from 'node:child_process';
import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
test('contact candidates require same-object explicit fields and reject supported placeholders',()=>{
 const output=execFileSync('python3',['-c',String.raw`
import sys
sys.path.insert(0,'workers')
from personal_records import contact_categories as c,email,phone
assert c({'full_name':'Fictional Person','email':'synthetic.contact@unit-fixture.net'})==['person_name','email']
assert c({'联系人姓名':'合成人物甲','手机号':'+86 139 2468 7531'})==['person_name','international_phone_shape']
for r in [{'name':'Library','email':'synthetic.contact@unit-fixture.net'},{'fullname':'Fictional Person'},{'email':'synthetic.contact@unit-fixture.net'},{'fullname':'Fictional Person','child':{'email':'synthetic.contact@unit-fixture.net'}},{'fullname':'test','email':'synthetic.contact@unit-fixture.net'},{'fullname':'$'+'{NAME}','phone':'+8613924687531'},{'fullname':'Fictional Person','phone':13924687531}]:assert c(r)==[],r
for e in ['a@example.com','a@sub.example.org','a@service.invalid','a@local.test','test@unit-fixture.net','bad..dots@unit-fixture.net','a@-bad.net','a@local','a@bad..net']:assert not email(e),e
for p in ['+12025550123','+8613000000000','12345678','+1234567890','+00012345678','$'+'{PHONE}']:assert not phone(p),p
print('ok')
`],{encoding:'utf8'});assert.equal(output.trim(),'ok');
});
test('HC-011 JSON/plist records on Android/iOS: grouped fields, negative controls, report redaction',{timeout:30000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'contact-records-'));t.after(()=>rm(root,{recursive:true,force:true}));
 execFileSync('python3',['-c',String.raw`
import sys,zipfile,json,plistlib
from pathlib import Path
p=Path(sys.argv[1])
positive=[{'full_name':'Fictional Person Alpha','email':'synthetic.contact@unit-fixture.net'},{'contact_name':'Fictional Person Beta','mobile':'+8613924687531'}]
negative=[{'fullname':'Fictional Person Gamma'},{'email':'synthetic.other@unit-fixture.net'},{'full_name':'Example Person','email':'person@example.com'},{'full_name':'Nested Person','child':{'email':'synthetic.nested@unit-fixture.net'}},{'name':'Package','email':'synthetic.package@unit-fixture.net'}]
for platform in ['android','ios']:
 with zipfile.ZipFile(p/(platform+'.zip'),'w') as z:
  prefix='assets/' if platform=='android' else 'Payload/Test.app/'
  if platform=='android':z.writestr('AndroidManifest.xml',b'fixture')
  else:z.writestr(prefix+'Info.plist',plistlib.dumps({'CFBundleIdentifier':'example.fixture'}))
  z.writestr(prefix+'records.json',json.dumps(positive))
  z.writestr(prefix+'record.plist',plistlib.dumps(positive[0],fmt=plistlib.FMT_BINARY))
  z.writestr(prefix+'negative.json',json.dumps(negative))
`,root]);
 const c=new Client({name:'contact-records',version:'1'});await c.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,'store')},stderr:'ignore'}));t.after(()=>c.close());
 const call=async(name,args)=>{const r=await c.callTool({name,arguments:args});assert.ok(!r.isError);return r.structuredContent;};
 for(const platform of ['android','ios']){
  const artifact=await call('import_local_artifact',{path:join(root,platform+'.zip')});const task=await call('scan_'+platform+'_hardcoding',{artifact_id:artifact.artifact_id});let s;
  do{await new Promise(r=>setTimeout(r,20));s=await call('get_scan_status',{scan_id:task.scan_id});}while(['running','queued'].includes(s.state));
  const r=await call('list_findings',{scan_id:task.scan_id,limit:100});assert.equal(r.findings.length,3);assert.ok(r.findings.every(f=>f.rule_id==='HC-011'&&f.value==='[REDACTED]'&&f.evidence.record_authenticity==='unknown'&&f.evidence.data_categories.includes('person_name')));assert.equal(s.rules.find(r=>r.rule_id==='HC-011').status,'partial');
  for(const format of ['json','markdown']){const report=await call('export_report',{scan_id:task.scan_id,format});const body=await readFile(report.path,'utf8');for(const text of ['Fictional Person','synthetic.contact','unit-fixture.net','13924687531'])assert.ok(!body.includes(text));}
 }
});
