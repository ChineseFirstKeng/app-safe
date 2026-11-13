import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join} from 'node:path';import {pathToFileURL} from 'node:url';
import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';

test('live workers: capacity, cancellation kills descendants, output/error isolation and slot recovery',{timeout:20000,skip:process.platform==='win32'?'POSIX process group assertion':false},async t=>{
 const root=await mkdtemp(join(tmpdir(),'scan-lifecycle-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const ids=['a','b','c','d'].map(c=>c.repeat(32));
 for(const artifact of ids){await mkdir(join(root,artifact));await writeFile(join(root,artifact,'inventory.json'),JSON.stringify({platform:'android',sha256:'0'.repeat(64),coverage:{},limitations:[]}));}
 const worker=join(root,'worker.py');
 await writeFile(worker,`import json,sys,time,subprocess,os\nfrom pathlib import Path\nr=json.load(sys.stdin)\nmode=r['artifact_id'][0]\nif mode in ('a','b'):\n child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])\n Path(r['storage_root'],mode+'.pid').write_text(str(child.pid))\n time.sleep(30)\nelif mode=='c':\n sys.stdout.write('x'*(5*1024*1024));sys.stdout.flush()\nelse:\n print('not valid worker json')\n`);
 const entry=join(root,'server.mjs');
 await writeFile(entry,`import {McpServer} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server'))};\nimport {serveStdio} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server/stdio'))};\nimport {registerScans} from ${JSON.stringify(new URL('../dist/tools/scans.js',import.meta.url).href)};\nserveStdio(()=>{const s=new McpServer({name:'lifecycle-test',version:'1'});registerScans(s,new URL(${JSON.stringify(pathToFileURL(worker).href)}));return s;});`);
 const c=new Client({name:'lifecycle-test',version:'1'});await c.connect(new StdioClientTransport({command:process.execPath,args:[entry],env:{...process.env,APP_SECURITY_DATA_DIR:root},stderr:'ignore'}));t.after(()=>c.close());
 const call=async(name,args)=>{const r=await c.callTool({name,arguments:args});assert.ok(!r.isError,JSON.stringify(r));return r.structuredContent;};
 const wait=async fn=>{for(let i=0;i<200;i++){const r=await fn();if(r)return r;await new Promise(r=>setTimeout(r,20));}assert.fail('condition timed out');};
 const tasks=[];const pids=[];
 t.after(()=>{for(const pid of pids)try{process.kill(pid,'SIGKILL');}catch{}});
 for(const id of ids.slice(0,2)){tasks.push(await call('scan_android_hardcoding',{artifact_id:id}));pids.push(Number(await wait(()=>readFile(join(root,id[0]+'.pid'),'utf8').catch(()=>null))));}
 const full=await c.callTool({name:'scan_android_hardcoding',arguments:{artifact_id:ids[2]}});assert.equal(full.isError,true);assert.equal(full.content[0].text,'scan_capacity_exceeded');
 for(const task of tasks){assert.equal((await call('cancel_scan',{scan_id:task.scan_id})).cancelled,true);assert.equal((await call('get_scan_status',{scan_id:task.scan_id})).state,'cancelled');}
 for(const pid of pids)await wait(async()=>{try{process.kill(pid,0);return false;}catch{return true;}});
 for(const [id,reason] of [[ids[2],'resource_output_limit'],[ids[3],'resource_worker_failed']]){
  const task=await call('scan_android_hardcoding',{artifact_id:id});const s=await wait(async()=>{const r=await call('get_scan_status',{scan_id:task.scan_id});return ['queued','running'].includes(r.state)?null:r;});assert.equal(s.state,'failed');assert.equal(s.finding_count,null);assert.ok(s.limitations.includes(reason));
 }
 for(const task of tasks)assert.equal((await call('get_scan_status',{scan_id:task.scan_id})).state,'cancelled');
});
