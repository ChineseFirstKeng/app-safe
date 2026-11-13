import {test} from 'node:test';import assert from 'node:assert/strict';import {mkdtemp,mkdir,writeFile,readFile,rm,readdir} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import {pathToFileURL} from 'node:url';import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
test('shared static capacity: separate MCP processes, owner crash, kernel-held orphan slot, cancellation and reuse',{timeout:20000,skip:process.platform==='win32'?'POSIX admission gate':false},async t=>{
 const root=await mkdtemp(join(tmpdir(),'global-capacity-'));t.after(()=>rm(root,{recursive:true,force:true}));const ids=['a','b','c'].map(x=>x.repeat(32));
 for(const id of ids){await mkdir(join(root,id));await writeFile(join(root,id,'inventory.json'),JSON.stringify({platform:'android',sha256:'0'.repeat(64),coverage:{},limitations:[]}));}
 const worker=join(root,'worker.py');await writeFile(worker,"import json,sys,os,time\nfrom pathlib import Path\nr=json.load(sys.stdin)\nPath(r['storage_root'],r['artifact_id'][0]+'.pid').write_text(str(os.getpid()))\ntime.sleep(30)\nprint(json.dumps({'ok':True,'result':{'findings':[],'finding_count':0}}))\n");
 const entry=join(root,'server.mjs');await writeFile(entry,`import {McpServer} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server'))};import {serveStdio} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server/stdio'))};import {registerScans} from ${JSON.stringify(new URL('../dist/tools/scans.js',import.meta.url).href)};serveStdio(()=>{const s=new McpServer({name:'capacity-test',version:'1'});registerScans(s,new URL(${JSON.stringify(pathToFileURL(worker).href)}),new URL(${JSON.stringify(new URL('../workers/scan_gate.py',import.meta.url).href)}));return s;});`);
 const cs=[];const transports=[];const pids=[];
 t.after(()=>{for(const pid of pids)try{process.kill(-pid,'SIGKILL');}catch{}});
 for(let i=0;i<2;i++){const c=new Client({name:'capacity-test',version:'1'}),transport=new StdioClientTransport({command:process.execPath,args:[entry],env:{...process.env,APP_SECURITY_DATA_DIR:root},stderr:'ignore'});await c.connect(transport);cs.push(c);transports.push(transport);t.after(()=>c.close());}
 const call=async(i,name,args)=>{const r=await cs[i].callTool({name,arguments:args});assert.ok(!r.isError,JSON.stringify(r));return r.structuredContent;};
 const wait=async fn=>{for(let i=0;i<300;i++){const r=await fn();if(r)return r;await new Promise(r=>setTimeout(r,20));}throw Error('condition timeout');};
 const tasks=[];for(let i=0;i<2;i++){tasks.push(await call(i,'scan_android_hardcoding',{artifact_id:ids[i]}));pids.push(Number(await wait(()=>readFile(join(root,ids[i][0]+'.pid'),'utf8').catch(()=>null))));}
 process.kill(transports[0].pid,'SIGKILL');await wait(async()=>{try{process.kill(transports[0].pid,0);return false;}catch{return true;}});
 assert.equal((await call(1,'get_scan_status',{scan_id:tasks[0].scan_id})).state,'failed');assert.doesNotThrow(()=>process.kill(pids[0],0));
 const deletion=await cs[1].callTool({name:'delete_scan',arguments:{scan_id:tasks[0].scan_id}});assert.equal(deletion.isError,true);assert.equal(deletion.content[0].text,'scan_worker_may_still_be_active');
 const blocked=await call(1,'scan_android_hardcoding',{artifact_id:ids[2]});const status=await wait(async()=>{const r=await call(1,'get_scan_status',{scan_id:blocked.scan_id});return r.state==='blocked'?r:null;});assert.ok(status.limitations.includes('global_scan_capacity_exceeded'));assert.equal(status.finding_count,null);
 process.kill(-pids[0],'SIGKILL');await wait(async()=>{try{process.kill(pids[0],0);return false;}catch{return true;}});
 const recovered=await call(1,'scan_android_hardcoding',{artifact_id:ids[2]});pids.push(Number(await wait(()=>readFile(join(root,'c.pid'),'utf8').catch(()=>null))));
 assert.equal((await call(1,'cancel_scan',{scan_id:tasks[1].scan_id})).cancelled,true);assert.equal((await call(1,'cancel_scan',{scan_id:recovered.scan_id})).cancelled,true);
 for(const pid of pids.slice(1))await wait(async()=>{try{process.kill(pid,0);return false;}catch{return true;}});
 assert.deepEqual((await readdir(join(root,'_capacity'))).sort(),['scan-0.lock','scan-1.lock']);
});
