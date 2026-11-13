import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, writeFile, readFile, rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir, homedir} from 'node:os';
import {existsSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {Client} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';

const aapt=execFileSync('python3',['-c','import sys;sys.path.insert(0,"workers");from android_resources import find_aapt2;print(find_aapt2() or "")'],{encoding:'utf8'}).trim();
const sdk=process.env.ANDROID_SDK_ROOT||process.env.ANDROID_HOME||join(homedir(),'Library/Android/sdk');
const framework=process.env.TEST_ANDROID_JAR||join(sdk,'platforms/android-36/android.jar');
test('compiled Android resources: actual AAPT2, references, redaction, missing decoder and corrupt binary XML', {timeout:30000,skip:!aapt||!existsSync(framework)?'Android SDK AAPT2/framework required':false},async t=>{
 const root=await mkdtemp(join(tmpdir(),'app-security-android-'));t.after(()=>rm(root,{recursive:true,force:true}));
 await mkdir(join(root,'res/values'),{recursive:true});
 await writeFile(join(root,'res/values/strings.xml'),`<resources>
 <string name="password">fixture-resource-password-123</string>
 <string name="client_secret">fixture-resource-secret-456</string>
 <string name="opaque">fixture-referenced-token-789</string>
 <string name="client_id">public-client-123</string>
 <string name="placeholder">\u0024{PASSWORD}</string>
 </resources>`);
 await writeFile(join(root,'AndroidManifest.xml'),`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.resources"><application>
 <meta-data android:name="access_token" android:value="@string/opaque"/>
 <meta-data android:name="db_password" android:value="fixture-xml-password-888"/>
 <meta-data android:name="password" android:value="@string/placeholder"/>
 </application></manifest>`);
 execFileSync(aapt,['compile','--dir',join(root,'res'),'-o',join(root,'compiled.zip')]);
 execFileSync(aapt,['link','-o',join(root,'fixture.apk'),'--manifest',join(root,'AndroidManifest.xml'),'-I',framework,join(root,'compiled.zip')]);
 for(const missing of [false,true]){
  const client=new Client({name:'android-resource-test',version:'1'});
  await client.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,missing?'missing-store':'store'),APP_SECURITY_AAPT2:missing?join(root,'absent'):aapt},stderr:'pipe'}));
  try{
   const call=async(name,args)=>{const r=await client.callTool({name,arguments:args});assert.ok(!r.isError,JSON.stringify(r));return r.structuredContent;};
   const run=async path=>{
    const imp=await call('import_local_artifact',{path,expected_platform:'android'});
    const task=await call('scan_android_hardcoding',{artifact_id:imp.artifact_id});
    for(let i=0;i<100;i++){const status=await call('get_scan_status',{scan_id:task.scan_id});if(!['queued','running'].includes(status.state))return status;await new Promise(r=>setTimeout(r,30));}
    assert.fail('scan timeout');
   };
   const status=await run(join(root,'fixture.apk'));
   assert.equal(status.state,'partial');
   const dec=status.resource_scan.android_resources;
   if(missing){assert.equal(dec.available,false);assert.equal(status.finding_count,0);assert.equal(dec.failures.android_decoder_unavailable,2);continue;}
   assert.equal(dec.resource_tables_decoded,1);assert.equal(dec.binary_xml_decoded,1);
   assert.deepEqual(dec.failures,{});
   const {findings}=await call('list_findings',{scan_id:status.scan_id});
   assert.deepEqual(findings.map(f=>f.rule_id).sort(),['HC-001','HC-001','HC-002','HC-003']);
   assert.ok(findings.every(f=>f.evidence.location.startsWith('aapt2-')&&f.value==='[REDACTED]'));
   const report=await call('export_report',{scan_id:status.scan_id,format:'json'});
   const text=await readFile(report.path,'utf8');assert.ok(!text.includes('fixture-resource-')&&!text.includes('fixture-referenced-')&&!text.includes('fixture-xml-'));
   execFileSync('python3',['-c',`import zipfile,sys
with zipfile.ZipFile(sys.argv[1],'w') as z:z.writestr('AndroidManifest.xml',b'\\x03\\x00\\x08\\x00broken')`,join(root,'broken.apk')]);
   const broken=await run(join(root,'broken.apk'));assert.equal(broken.resource_scan.android_resources.failures.android_decode_failed,1);
  }finally{await client.close();}
 }
});

test('decoder bounds output and time, suppresses stderr',async()=>{
 const result=execFileSync('python3',['-c',`import sys,tempfile,pathlib,time,os
sys.path.insert(0,'workers')
from android_resources import dump
with tempfile.TemporaryDirectory() as d:
 p=pathlib.Path(d)/'decoder'
 for body,expected in [('print("x"*(9*1024*1024))','android_decode_output_limit'),('import time;time.sleep(2)','android_decode_timeout')]:
  p.write_text('#!'+sys.executable+'\\n'+body+'\\n');p.chmod(0o700)
  try:dump(str(p),'unused','resources',time.monotonic()+(4 if expected=='android_decode_output_limit' else .3))
  except ValueError as e:assert str(e)==expected,(e,expected)
  else:raise AssertionError('limit not enforced')
print('ok')`],{encoding:'utf8'});
 assert.equal(result.trim(),'ok');
});
