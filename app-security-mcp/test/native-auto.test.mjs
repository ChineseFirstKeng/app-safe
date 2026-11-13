import {test} from 'node:test';import assert from 'node:assert/strict';import {mkdtemp,mkdir,writeFile,readFile,rm,readdir} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import {pathToFileURL} from 'node:url';import {createHash} from 'node:crypto';
import {verifyNativeFunction} from '../dist/tools/native-verification.js';
test('automatic native adapter: ELF and thin Mach-O identity, discovery, function body and redaction',{timeout:20000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'native-auto-'));t.after(()=>rm(root,{recursive:true,force:true}));await mkdir(join(root,'_scans'));
 const previous={command:process.env.APP_SECURITY_REA_COMMAND,args:process.env.APP_SECURITY_REA_ARGS};t.after(()=>{for(const [k,v] of [['APP_SECURITY_REA_COMMAND',previous.command],['APP_SECURITY_REA_ARGS',previous.args]])if(v===undefined)delete process.env[k];else process.env[k]=v;});
 const hash=createHash('sha256').update('fixture').digest('hex');const worker=join(root,'extract.py');await writeFile(worker,"import json,sys\nfrom pathlib import Path\nr=json.load(sys.stdin)\nPath(r['output']).write_bytes(b'fixture')\nprint(json.dumps({'ok':True}))\n");
 const mock=join(root,'mock.mjs');await writeFile(mock,`import {McpServer} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server'))};import {serveStdio} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/server/stdio'))};import * as z from ${JSON.stringify(import.meta.resolve('zod/v4'))};
const mode=process.argv[2],hash=${JSON.stringify(hash)};const body={available:true,ranges:[{start:'0x1000',end:'0x1020'}]};
serveStdio(()=>{const s=new McpServer({name:'native-fixture',version:'1'});for(const name of ['open_binary','close_binary','address_to_file_offset','list_strings','xrefs','resolve_containing_procedure','analyze_function'])s.registerTool(name,{inputSchema:z.object({path:z.string().optional(),provider_id:z.string().optional(),address:z.string().optional(),procedure:z.string().optional()})},async a=>{
 const normalized_result=name==='address_to_file_offset'?{address:a.address,file_offset:12}:name==='xrefs'?['0x1010']:name==='resolve_containing_procedure'?{found:true,query_address:a.address,procedure:{address:'0x1000',body}}:name==='list_strings'?[]:{pseudocode:'synthetic-private-text',procedure:{address:mode==='bad-function'?'0x2000':'0x1000',body},referenced_strings:[{address:'0x2010'}]};
 const r=name==='open_binary'?{result:{sha256:mode==='bad-open'?'wrong':hash}}:{subject:{digest:{sha256:mode==='bad-identity'?'wrong':hash}},provider:{id:mode==='bad-provider'?'other':'ghidra'},evidence_id:'fixture',normalized_result};return {content:[{type:'text',text:JSON.stringify(r)}],structuredContent:r};});return s;});`);
 process.env.APP_SECURITY_REA_COMMAND=process.execPath;
 for(const platform of ['android','ios'])for(const mode of ['ok','bad-open','bad-identity','bad-provider','bad-function']){
  process.env.APP_SECURITY_REA_ARGS=JSON.stringify([mock,mode]);const e={path:'native',usage:platform==='android'?'elf_literal_only':'native_literal_only',transform:'none',member_sha256:hash,slice_sha256:hash,slice_index:0,slice_offset:100,file_offset:platform==='android'?12:112,virtual_address:'0x2010'};
  const result=await verifyNativeFunction({platform,artifact_id:'fixture',artifact_sha256:hash},{evidence:e},undefined,root,pathToFileURL(worker));
  if(mode==='ok'){assert.equal(result.status,'function_body_recovered');assert.equal(result.usage_confirmed,false);assert.equal(result.string_reference_observed,true);assert.equal(result.discovery.procedure,'0x1000');}
  else assert.ok(result.status==='blocked'||result.status==='partial');
  assert.ok(!JSON.stringify(result).includes('synthetic-private-text'));assert.deepEqual(await readdir(join(root,'_scans')),[]);
 }
 const controller=new AbortController();controller.abort();assert.equal((await verifyNativeFunction({}, {}, undefined,root,pathToFileURL(worker),controller.signal)).reason,'rea_native_cancelled');
});

test('native extraction cancellation terminates Python before launching REA and removes temporary output',{timeout:10000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'native-extract-cancel-'));t.after(()=>rm(root,{recursive:true,force:true}));await mkdir(join(root,'_scans'));
 const previous=process.env.APP_SECURITY_REA_COMMAND;process.env.APP_SECURITY_REA_COMMAND=process.execPath;t.after(()=>{if(previous===undefined)delete process.env.APP_SECURITY_REA_COMMAND;else process.env.APP_SECURITY_REA_COMMAND=previous;});
 const worker=join(root,'extract.py'),marker=join(root,'pid');await writeFile(worker,`import json,sys,time,os\nfrom pathlib import Path\njson.load(sys.stdin)\nPath(${JSON.stringify(marker)}).write_text(str(os.getpid()))\ntime.sleep(30)\n`);
 const controller=new AbortController();const pending=verifyNativeFunction({platform:'android',artifact_id:'fixture'},{evidence:{usage:'elf_literal_only',transform:'none',member_sha256:'hash'}},undefined,root,pathToFileURL(worker),controller.signal);
 let pid;for(let i=0;i<100;i++){try{pid=Number(await readFile(marker,'utf8'));if(pid)break;}catch{}await new Promise(r=>setTimeout(r,20));}
 assert.ok(pid);controller.abort();const result=await pending;assert.equal(result.reason,'rea_native_cancelled');assert.throws(()=>process.kill(pid,0));assert.deepEqual(await readdir(join(root,'_scans')),[]);
});
