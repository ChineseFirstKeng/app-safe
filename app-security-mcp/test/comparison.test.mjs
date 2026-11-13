import {test} from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';import {join} from 'node:path';import {tmpdir} from 'node:os';import {execFileSync} from 'node:child_process';
import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
import {compareScans} from '../dist/tools/scan-comparison.js';
test('comparison refuses failed/cancelled/running and cross platform; exposes truncation and incompatible settings',()=>{
 const a={scan_id:'a',platform:'android',state:'partial',findings:[],resource_scan:{findings_truncated:true},scanner_version:'1',ruleset_version:'1',profile:'basic',scan_options:{}};
 for(const state of ['failed','cancelled','running','queued','blocked'])assert.throws(()=>compareScans(a,{...a,state}));
 assert.throws(()=>compareScans(a,{...a,platform:'ios'}));
 const r=compareScans(a,{...a,scanner_version:'2'});assert.equal(r.settings_match,false);assert.ok(r.warnings.includes('before_findings_truncated'));assert.equal(r.repair_confirmed,false);
 const changed=compareScans({...a,scan_options:{ios_decode_attempt_limit:1}},{...a,scan_options:{ios_decode_attempt_limit:10000}});assert.equal(changed.settings_match,false);assert.ok(changed.warnings.includes('scan_options_mismatch_or_missing'));assert.equal(changed.coverage.after.scan_options.ios_decode_attempt_limit,10000);
 assert.equal(compareScans(a,{...a,scan_options:undefined}).settings_match,false);
});
test('MCP compares rebuilt Android and iOS fixtures without claiming secret identity or repair',{timeout:30000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'comparison-'));t.after(()=>rm(root,{recursive:true,force:true}));
 execFileSync('python3',['-c',String.raw`
import zipfile,json,sys,plistlib
from pathlib import Path
root=Path(sys.argv[1])
for platform in ['android','ios']:
 for version in ['before','after']:
  with zipfile.ZipFile(root/(platform+'-'+version+'.zip'),'w') as z:
   prefix='assets/' if platform=='android' else 'Payload/Test.app/'
   if platform=='android':z.writestr('AndroidManifest.xml',b'fixture')
   else:z.writestr(prefix+'Info.plist',plistlib.dumps({'CFBundleIdentifier':'example.compare'}))
   z.writestr(prefix+'keep.json',json.dumps({'password':'fixture-changed-'+version}))
   if version=='before':z.writestr(prefix+'removed.json',json.dumps({'client_secret':'fixture-removed-123'}))
   else:z.writestr(prefix+'new.json',json.dumps({'access_token':'fixture-added-456'}))
`,root]);
 const c=new Client({name:'comparison-test',version:'1'});await c.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,'store')},stderr:'ignore'}));t.after(()=>c.close());
 const call=async(name,args)=>{const r=await c.callTool({name,arguments:args});assert.ok(!r.isError);return r.structuredContent;};
 for(const platform of ['android','ios']){
  const ids=[];
  for(const v of ['before','after']){
   const artifact=await call('import_local_artifact',{path:join(root,platform+'-'+v+'.zip')});const task=await call('scan_'+platform+'_hardcoding',{artifact_id:artifact.artifact_id});ids.push(task.scan_id);
   let s;do{await new Promise(r=>setTimeout(r,20));s=await call('get_scan_status',{scan_id:task.scan_id});}while(['queued','running'].includes(s.state));assert.equal(s.state,'partial');
  }
  const r=await call('compare_scans',{before_scan_id:ids[0],after_scan_id:ids[1]});assert.deepEqual(r.summary,{still_detected:1,newly_detected:1,not_redetected:1});assert.equal(r.repair_confirmed,false);assert.equal(r.settings_match,true);assert.ok(r.coverage.before.resource_scan);assert.ok(r.coverage.after.resource_scan);assert.ok(!JSON.stringify(r).includes('fixture-changed-'));assert.notEqual(r.before_artifact_sha256,r.after_artifact_sha256);
  const same=await call('compare_scans',{before_scan_id:ids[0],after_scan_id:ids[0]});assert.ok(same.warnings.includes('same_artifact_not_a_repair_build'));
 }
});
