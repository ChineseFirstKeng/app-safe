// Production 100-second timeout verification. Kept separate from fast regression.
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join} from 'node:path';import {pathToFileURL} from 'node:url';
import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
if(process.platform==='win32')throw Error('POSIX descendant verification requires POSIX host');
const root=await mkdtemp(join(tmpdir(),'scan-hard-timeout-'));const artifact='a'.repeat(32);let client;let descendant;
try {
 await mkdir(join(root,artifact));await writeFile(join(root,artifact,'inventory.json'),JSON.stringify({platform:'android',sha256:'0'.repeat(64),coverage:{},limitations:[]}));
 const worker=join(root,'worker.py');await writeFile(worker,"import json,sys,time,subprocess\nfrom pathlib import Path\nr=json.load(sys.stdin)\nchild=subprocess.Popen([sys.executable,'-c','import time;time.sleep(150)'])\nPath(r['storage_root'],'descendant.pid').write_text(str(child.pid))\ntime.sleep(150)\n");
 const entry=join(root,'server.mjs');await writeFile(entry,`import {McpServer} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server'))};\nimport {serveStdio} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server/stdio'))};\nimport {registerScans} from ${JSON.stringify(new URL('../dist/tools/scans.js',import.meta.url).href)};\nserveStdio(()=>{const s=new McpServer({name:'timeout-check',version:'1'});registerScans(s,new URL(${JSON.stringify(pathToFileURL(worker).href)}));return s;});`);
 client=new Client({name:'timeout-check',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[entry],env:{...process.env,APP_SECURITY_DATA_DIR:root},stderr:'ignore'}));
 const call=async(name,args)=>{const r=await client.callTool({name,arguments:args});assert.ok(!r.isError);return r.structuredContent;};
 const started=Date.now();const scan=await call('scan_android_hardcoding',{artifact_id:artifact});let status;
 for(let i=0;i<115;i++){
  await new Promise(r=>setTimeout(r,1000));status=await call('get_scan_status',{scan_id:scan.scan_id});
  if(!['queued','running'].includes(status.state))break;
 }
 const elapsed=Date.now()-started;assert.equal(status.state,'failed');assert.ok(status.limitations.includes('resource_scan_timeout'));assert.ok(elapsed>=99000&&elapsed<115000);
 descendant=Number(await readFile(join(root,'descendant.pid'),'utf8'));let gone=false;
 for(let i=0;i<50;i++){try{process.kill(descendant,0);}catch{gone=true;break;}await new Promise(r=>setTimeout(r,100));}assert.ok(gone,'descendant survived timeout');
 const deleted=await call('delete_scan',{scan_id:scan.scan_id});assert.equal(deleted.deleted,true);
 await mkdir(new URL('../artifacts/validation/',import.meta.url),{recursive:true});
 const summary={passed:true,scope:'production_100_second_worker_timeout_posix',elapsed_ms:elapsed,state:status.state,reason:'resource_scan_timeout',descendant_terminated:true,result_cleanup:true};
 await writeFile(new URL('../artifacts/validation/worker-timeout-summary.json',import.meta.url),JSON.stringify(summary,null,2),{mode:0o600});console.log(JSON.stringify(summary));
}finally{
 if(descendant)try{process.kill(descendant,'SIGKILL');}catch{}
 if(client)await client.close();await rm(root,{recursive:true,force:true});
}
