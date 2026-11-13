import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {verifyDexMethod} from '../dist/tools/dex-verification.js';

test('REA adapter checks input identity and overload, preserves candidate, removes plaintext and temp files',async t=>{
 const root=await mkdtemp(join(tmpdir(),'app-security-rea-test-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const before={command:process.env.APP_SECURITY_REA_COMMAND,args:process.env.APP_SECURITY_REA_ARGS};
 t.after(()=>{for(const [k,v] of [['APP_SECURITY_REA_COMMAND',before.command],['APP_SECURITY_REA_ARGS',before.args]]){if(v===undefined)delete process.env[k];else process.env[k]=v;}});
 await mkdir(join(root,'artifact'));await mkdir(join(root,'_scans'));await writeFile(join(root,'artifact/package.bin'),'fixture');
 const sha=createHash('sha256').update('fixture').digest('hex');
 const mock=join(root,'mock.mjs');
 await writeFile(mock,`import {McpServer} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server'))};
import {serveStdio} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server/stdio'))};
import * as z from ${JSON.stringify(import.meta.resolve('zod/v4'))};
const mode=process.argv[2];
serveStdio(()=>{const server=new McpServer({name:'mock-rea',version:'1'});
for(const name of ['search_android_classes','inspect_android_class','inspect_android_method'])server.registerTool(name,{inputSchema:z.object({path:z.string(),query:z.string().optional(),class_name:z.string().optional(),method_name:z.string().optional(),overload_index:z.number().optional()})},async args=>{
 let normalized_result;
 if(name==='search_android_classes')normalized_result={matches:mode==='duplicate'?['test.Sample','test.Sample']:['test.Sample']};
 else if(name==='inspect_android_class')normalized_result={methods:[{name:'method',dex_descriptor:'()V',overload_index:1},{name:'method',dex_descriptor:'(I)V',overload_index:0}]};
 else {if(args.overload_index!==1)throw Error('wrong overload');normalized_result={method:{dex_descriptor:mode==='wrong-method'?'(I)V':'()V',overload_index:1},body_status:'available',source:{status:'complete',text:'fixture-plaintext-secret'},representation:'java',engine:{name:'mock',version:'1'}};}
 const result={evidence_id:'ev_mock',subject:{digest:{sha256:mode==='wrong-digest'?'incorrect':${JSON.stringify(sha)}}},provider:{id:'mock'},normalized_result};
 return {content:[{type:'text',text:JSON.stringify(result)}],structuredContent:result};});return server;});`);
 process.env.APP_SECURITY_REA_COMMAND=process.execPath;
 const record={artifact_id:'artifact',artifact_sha256:sha};
 const finding={evidence:{class_descriptor:'Ltest/Sample;',method:'method',prototype:'()V'}};
 for(const [mode,status,reason] of [['ok','method_body_recovered',undefined],['wrong-digest','blocked','rea_artifact_identity_mismatch'],['duplicate','blocked','rea_class_alias_or_duplicates_unresolved'],['wrong-method','blocked','rea_method_identity_mismatch']]){
 process.env.APP_SECURITY_REA_ARGS=JSON.stringify([mock,mode]);
 const result=await verifyDexMethod(record,finding,root);assert.equal(result.status,status);assert.equal(result.reason,reason);assert.ok(!JSON.stringify(result).includes('fixture-plaintext-secret'));
 if(mode==='ok'){assert.equal(result.usage_confirmed,false);assert.equal(result.verification_level,'candidate');assert.equal(result.overload_index,1);}
 assert.deepEqual(await readdir(join(root,'_scans')),[]);
 }
 // A provider that never answers initialize must also be reaped on cancellation.
 const marker=join(root,'stalled.pid'),stalled=join(root,'stalled.mjs');
 await writeFile(stalled,`import {writeFileSync} from 'node:fs';writeFileSync(${JSON.stringify(marker)},String(process.pid));setInterval(()=>{},1000);`);
 process.env.APP_SECURITY_REA_ARGS=JSON.stringify([stalled]);
 const controller=new AbortController();const pending=verifyDexMethod(record,finding,root,controller.signal);
 let pid;
 for(let i=0;i<100;i++){try{pid=Number(await readFile(marker,'utf8'));break;}catch{await new Promise(r=>setTimeout(r,20));}}
 assert.ok(pid);controller.abort();
 const cancelled=await pending;assert.equal(cancelled.status,'blocked');assert.equal(cancelled.reason,'rea_cancelled');
 assert.throws(()=>process.kill(pid,0));assert.deepEqual(await readdir(join(root,'_scans')),[]);

});
