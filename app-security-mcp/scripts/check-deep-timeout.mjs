// Verify the production 150-second automatic REA budget with a nonresponding provider.
import assert from 'node:assert/strict';import {mkdtemp,mkdir,writeFile,readFile,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join} from 'node:path';import {pathToFileURL} from 'node:url';import {createHash} from 'node:crypto';
import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
const root=await mkdtemp(join(tmpdir(),'deep-hard-timeout-'));let client;let providerPid;
try{
 const artifact='a'.repeat(32);await mkdir(join(root,artifact));await writeFile(join(root,artifact,'package.bin'),'fixture');await writeFile(join(root,artifact,'inventory.json'),JSON.stringify({platform:'android',sha256:createHash('sha256').update('fixture').digest('hex'),coverage:{},limitations:[]}));
 const worker=join(root,'worker.py');await writeFile(worker,`import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'ok':True,'result':{'findings':[{'finding_id':'f-0001','evidence':{'path':'classes.dex','class_descriptor':'Ltest/Sample;','method':'method','prototype':'()V'}}],'finding_count':1,'limitations':[]}}))\n`);
 const marker=join(root,'provider.pid'),provider=join(root,'provider.mjs');await writeFile(provider,`import {writeFileSync} from 'node:fs';writeFileSync(${JSON.stringify(marker)},String(process.pid));setInterval(()=>{},1000);`);
 const entry=join(root,'server.mjs');await writeFile(entry,`import {McpServer} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server'))};import {serveStdio} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server/stdio'))};import {registerScans} from ${JSON.stringify(new URL('../dist/tools/scans.js',import.meta.url).href)};serveStdio(()=>{const s=new McpServer({name:'timeout-test',version:'1'});registerScans(s,new URL(${JSON.stringify(pathToFileURL(worker).href)}));return s;});`);
 client=new Client({name:'timeout-test',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[entry],env:{...process.env,APP_SECURITY_DATA_DIR:root,APP_SECURITY_REA_COMMAND:process.execPath,APP_SECURITY_REA_ARGS:JSON.stringify([provider])},stderr:'ignore'}));
 const call=async(name,args)=>{const r=await client.callTool({name,arguments:args});assert.ok(!r.isError);return r.structuredContent;};
 const start=Date.now();const scan=await call('scan_android_hardcoding',{artifact_id:artifact,profile:'static-deep'});let status;
 for(let i=0;i<170;i++){await new Promise(r=>setTimeout(r,1000));status=await call('get_scan_status',{scan_id:scan.scan_id});if(!['queued','running'].includes(status.state))break;}
 const elapsed=Date.now()-start;providerPid=Number(await readFile(marker,'utf8'));
 assert.equal(status.state,'partial');assert.equal(status.finding_count,1);assert.equal(status.effective_profile,'static-basic');assert.equal(status.deep_scan.reason,'deep_cancelled_or_timeout');assert.ok(elapsed>=149000&&elapsed<170000);
 assert.throws(()=>process.kill(providerPid,0));assert.ok(!(await readdir(join(root,'_scans'))).some(n=>n.startsWith('.rea-')));
 assert.equal((await call('delete_scan',{scan_id:scan.scan_id})).deleted,true);
 const summary={passed:true,scope:'production_150_second_automatic_rea_budget',elapsed_ms:elapsed,state:status.state,reason:status.deep_scan.reason,candidates_retained:1,provider_terminated:true,temporary_files_removed:true};
 await writeFile(new URL('../artifacts/validation/deep-timeout-summary.json',import.meta.url),JSON.stringify(summary,null,2),{mode:0o600});console.log(JSON.stringify(summary));
}finally{if(!providerPid)providerPid=Number(await readFile(join(root,'provider.pid'),'utf8').catch(()=>0));if(providerPid)try{process.kill(providerPid,'SIGKILL');}catch{}if(client)await client.close();await rm(root,{recursive:true,force:true});}
