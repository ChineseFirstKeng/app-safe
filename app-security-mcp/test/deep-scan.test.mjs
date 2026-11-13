import {test} from 'node:test';import assert from 'node:assert/strict';
import {corroborateFindings} from '../dist/tools/deep-scan.js';
import {mkdtemp,mkdir,writeFile,readFile,rm,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join} from 'node:path';import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
const findings=Array.from({length:4},(_,i)=>({finding_id:`f-000${i+1}`,verification_level:'candidate',evidence:{path:'classes.dex',class_descriptor:'Ltest/Sample;',method:'method'+Math.max(0,i-1),prototype:'()V'}}));
test('deep scheduling: method deduplication, budgets, unsupported scope and blocked provider',async()=>{
 const record={platform:'android',scan_options:{deep_method_limit:1},findings};let calls=0;let saved;
 const summary=await corroborateFindings(record,'unused',new AbortController().signal,async(s,v)=>saved=structuredClone(v),async()=>{calls++;return {status:'method_body_recovered',usage_confirmed:false};});
 assert.equal(calls,1);assert.equal(summary.eligible_methods,3);assert.equal(summary.remaining_methods,2);assert.equal(summary.reason,'deep_method_budget_reached');assert.deepEqual(Object.keys(saved),['f-0001','f-0002']);assert.equal(saved['f-0002'].usage_confirmed,false);
 const blocked=await corroborateFindings({...record,scan_options:{deep_method_limit:10}},'',new AbortController().signal,async()=>{},async()=>({status:'blocked',reason:'missing'}));assert.equal(blocked.attempted_methods,1);assert.equal(blocked.reason,'verification_blocked');
 const ios=await corroborateFindings({...record,platform:'ios'},'',new AbortController().signal,async()=>{},async()=>{throw Error('must not run');});assert.equal(ios.reason,'automatic_native_verification_not_implemented');
 const controller=new AbortController();controller.abort();const aborted=await corroborateFindings(record,'',controller.signal,async()=>{},async()=>{throw Error('must not run');});assert.equal(aborted.attempted_methods,0);
});

test('deep MCP lifecycle: real adapter protocol, missing dependency, cancellation and persisted redaction',{timeout:20000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'deep-scan-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const worker=join(root,'worker.py');await writeFile(worker,`import json,sys\nr=json.load(sys.stdin)\nprint(json.dumps({'ok':True,'result':{'findings':json.loads(${JSON.stringify(JSON.stringify(findings))}),'finding_count':4,'limitations':[]}}))\n`);
 const entry=join(root,'server.mjs');await writeFile(entry,`import {McpServer} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server'))};import {serveStdio} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server/stdio'))};import {registerScans} from ${JSON.stringify(new URL('../dist/tools/scans.js',import.meta.url).href)};serveStdio(()=>{const s=new McpServer({name:'deep-test',version:'1'});registerScans(s,new URL(${JSON.stringify(pathToFileURL(worker).href)}));return s;});`);
 const mock=join(root,'rea.mjs');await writeFile(mock,`import {McpServer} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server'))};import {serveStdio} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server/stdio'))};import * as z from ${JSON.stringify(import.meta.resolve('zod/v4'))};import {readFile,writeFile} from 'node:fs/promises';import {createHash} from 'node:crypto';
serveStdio(()=>{const s=new McpServer({name:'rea-test',version:'1'});for(const name of ['search_android_classes','inspect_android_class','inspect_android_method'])s.registerTool(name,{inputSchema:z.object({path:z.string(),query:z.string().optional(),class_name:z.string().optional(),method_name:z.string().optional(),overload_index:z.number().optional()})},async a=>{
if(process.argv[2]==='slow'){await writeFile(process.argv[3],String(process.pid));await new Promise(()=>{});}
const normalized_result=name==='search_android_classes'?{matches:['test.Sample']}:name==='inspect_android_class'?{methods:[0,1,2].map(i=>({name:'method'+i,dex_descriptor:'()V',overload_index:0}))}:{method:{dex_descriptor:'()V',overload_index:0},body_status:'available',source:{text:'synthetic-plaintext-must-not-leak',status:'complete'},engine:{name:'fixture'},representation:'java'};
const r={subject:{digest:{sha256:createHash('sha256').update(await readFile(a.path)).digest('hex')}},normalized_result,evidence_id:'fixture',provider:{id:'fixture'}};return {structuredContent:r,content:[{type:'text',text:JSON.stringify(r)}]};});return s;});`);
 const wait=async fn=>{for(let i=0;i<300;i++){const value=await fn();if(value)return value;await new Promise(r=>setTimeout(r,20));}throw Error('condition timeout');};
 for(const mode of ['ok','missing','slow']){
 const store=join(root,mode);const artifact='a'.repeat(32);await mkdir(join(store,artifact),{recursive:true});await writeFile(join(store,artifact,'package.bin'),'fixture');await writeFile(join(store,artifact,'inventory.json'),JSON.stringify({platform:'android',sha256:createHash('sha256').update('fixture').digest('hex'),coverage:{},limitations:[]}));
 const marker=join(store,'started');const c=new Client({name:'deep-test',version:'1'});await c.connect(new StdioClientTransport({command:process.execPath,args:[entry],env:{...process.env,APP_SECURITY_DATA_DIR:store,APP_SECURITY_REA_COMMAND:mode==='missing'?'':process.execPath,APP_SECURITY_REA_ARGS:JSON.stringify([mock,mode,marker])},stderr:'ignore'}));
 const call=async(name,args)=>{const r=await c.callTool({name,arguments:args});assert.ok(!r.isError,JSON.stringify(r));return r.structuredContent;};
 try{
 const scan=await call('scan_android_hardcoding',{artifact_id:artifact,profile:'static-deep',deep_method_limit:1});
 if(mode==='slow'){
  const pid=Number(await wait(()=>readFile(marker,'utf8').catch(()=>null)));
  assert.equal((await call('get_scan_status',{scan_id:scan.scan_id})).stage,'automatic_method_corroboration');
  assert.equal((await call('cancel_scan',{scan_id:scan.scan_id})).cancelled,true);
  await wait(async()=>{try{process.kill(pid,0);return false;}catch{return true;}});
  await wait(async()=>!(await readdir(join(store,'_scans'))).some(n=>n.startsWith('.rea-')));
  assert.equal((await call('get_scan_status',{scan_id:scan.scan_id})).state,'cancelled');
  await wait(async()=>{const r=await c.callTool({name:'delete_scan',arguments:{scan_id:scan.scan_id}});return !r.isError;});
  assert.equal(await readFile(join(store,artifact,'package.bin'),'utf8'),'fixture');
 }else{
  const status=await wait(async()=>{const s=await call('get_scan_status',{scan_id:scan.scan_id});return s.state==='partial'?s:null;});
  assert.equal(status.deep_scan.attempted_methods,1);assert.equal(status.finding_count,4);
  assert.equal(status.effective_profile,mode==='ok'?'static-basic+rea-dex-corroboration':'static-basic');
  const verification=status.verifications['f-0001'];assert.equal(verification.status,mode==='ok'?'method_body_recovered':'blocked');
  assert.equal(status.deep_scan.reason,mode==='ok'?'deep_method_budget_reached':'verification_blocked');
  if(mode==='ok')assert.equal(verification.usage_confirmed,false);
  const stored=await readFile(join(store,'_scans',scan.scan_id+'.json'),'utf8');assert.ok(!stored.includes('synthetic-plaintext-must-not-leak'));
 }
 }finally{await c.close();}
 }
});

test('native scheduling deduplicates literal evidence, excludes decoded values and honors its own budget',async()=>{
 const raw=[0,0,1,2].map((offset,i)=>({finding_id:'f-'+String(i+1).padStart(4,'0'),evidence:{usage:'native_literal_only',path:'Payload/App.app/App',member_sha256:'hash',slice_sha256:'slice',slice_index:0,file_offset:offset,transform:'none'}}));
 raw.push({finding_id:'f-0005',evidence:{...raw[0].evidence,usage:'native_decoded_literal_only',transform:'base64'}});
 let saved;let called=0;
 const result=await corroborateFindings({platform:'ios',scan_options:{deep_method_limit:1,deep_native_limit:1},findings:raw},'',new AbortController().signal,async(s,v)=>saved=structuredClone(v),async()=>{throw Error('must not run DEX');},async()=>{called++;return {status:'function_body_recovered',usage_confirmed:false};});
 assert.equal(called,1);assert.equal(result.eligible_methods,0);assert.equal(result.eligible_native_literals,3);assert.equal(result.eligible_findings,4);assert.equal(result.unsupported_findings,1);assert.equal(result.attempted_native_literals,1);assert.equal(result.remaining_native_literals,2);assert.equal(result.recovered_functions,1);assert.equal(result.reason,'deep_candidate_budget_reached');assert.deepEqual(Object.keys(saved),['f-0001','f-0002']);
});
