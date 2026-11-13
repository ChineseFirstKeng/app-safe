import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { discoverNativeProcedure, containsAddress } from './native-discovery.js';
import { awaitableTransportClose } from './rea-transport.js';
import { mapElfReference } from './native-reference.js';
import { Client } from '@modelcontextprotocol/client';
import { createHash } from 'node:crypto';
import { mkdtemp,readFile,rm } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export async function verifyNativeFunction(record:any,finding:any,procedure:string|undefined,root:string,extractWorker:URL,signal?:AbortSignal) {
  if(signal?.aborted)return {status:'blocked',reason:'rea_native_cancelled'};
  const e=finding.evidence;
  if(e?.archive_path_redacted)return {status:'not_applicable',reason:'redacted_archive_path_not_resolvable'};
  const automatic=procedure===undefined;
  if(automatic && e?.transform!==undefined && e.transform!=='none')return {status:'not_applicable',reason:'decoded_value_not_a_direct_literal'};
  const isElf=record.platform==='android';
  const identity=isElf?e?.member_sha256:e?.slice_sha256;
  if(isElf?!['elf_literal_only','elf_decoded_literal_only'].includes(e?.usage):!['native_literal_only','native_decoded_literal_only'].includes(e?.usage)||!e.slice_sha256||e.slice_index===undefined)return {status:'not_applicable',reason:'finding_has_no_native_literal'};
  let command=process.env.APP_SECURITY_REA_COMMAND,args:string[]=[],env:Record<string,string>={},provider='ghidra';
  try {
    if(command===undefined){const config=JSON.parse(await readFile(process.env.APP_SECURITY_REA_CONFIG??join(homedir(),'.app-security','rea.json'),'utf8'));command=config.command;args=config.args??[];env=config.env??{};provider=config.native_provider??'ghidra';}
    else args=JSON.parse(process.env.APP_SECURITY_REA_ARGS??'[]');
    if(typeof command!=='string'||!command||!Array.isArray(args)||args.some(x=>typeof x!=='string')||!env||Array.isArray(env)||typeof env!=='object'||Object.values(env).some(x=>typeof x!=='string')||typeof provider!=='string')throw Error();
  }catch{return {status:'blocked',reason:'rea_config_missing_or_invalid'};}
  const directory=await mkdtemp(join(root,'_scans','.rea-native-')),path=join(directory,isElf?'target.so':'target.macho');
  const client=new Client({name:'app-security-native-verifier',version:'0.9.0'});
  const transport=new StdioClientTransport({command,args,env:{...process.env,...env} as Record<string,string>,stderr:'ignore',maxBufferSize:4*1024*1024});
  awaitableTransportClose(transport);
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),150000);let opened=false;
  const combined=signal?AbortSignal.any([signal,controller.signal]):controller.signal;
  try {
    combined.throwIfAborted();
    const extraction:any=await new Promise(resolve=>{
      const child=spawn(process.env.APP_SECURITY_PYTHON??'python3',[fileURLToPath(extractWorker)],{stdio:['pipe','pipe','ignore']});
      let output='',settled=false;const done=(r:any)=>{if(settled)return;settled=true;clearTimeout(timeout);combined.removeEventListener('abort',abort);resolve(r);};
      const timeout=setTimeout(()=>{child.kill('SIGKILL');done({ok:false,error:'macho_extract_timeout'});},20000);
      const abort=()=>child.kill('SIGKILL');combined.addEventListener('abort',abort,{once:true});if(combined.aborted)abort();
      child.stdin.on('error',()=>{});child.stdout.on('data',b=>{output+=b;if(output.length>8192){child.kill('SIGKILL');done({ok:false,error:'macho_extract_output_limit'});}});
      child.on('error',()=>done({ok:false,error:'python3_unavailable'}));child.on('close',()=>{if(combined.aborted){done({ok:false,error:'rea_native_cancelled'});return;}try{done(JSON.parse(output));}catch{done({ok:false,error:'macho_extract_failed'});}});
      child.stdin.end(JSON.stringify({storage_root:root,artifact_id:record.artifact_id,artifact_sha256:record.artifact_sha256,member:e.member_path??e.path,archive_chain:e.archive_chain??[],member_sha256:e.member_sha256,slice_index:e.slice_index,slice_sha256:e.slice_sha256,output:path}));
    });
    if(!extraction.ok)return {status:'blocked',reason:extraction.error};
    await client.connect(transport,{signal:combined,timeout:150000});
    const call=async(name:string,arguments_:any)=>{
      const r:any=await client.callTool({name,arguments:arguments_},{signal:combined,timeout:150000});
      if(r.isError)throw Error('rea_native_provider_failed');
      return r.structuredContent??JSON.parse(r.content.find((c:any)=>c.type==='text').text);
    };
    const target=await call('open_binary',{path,provider_id:provider});opened=true;
    if(target.result.sha256!==identity)throw Error('rea_slice_identity_mismatch');
    const discovery=automatic?await discoverNativeProcedure(e,identity,provider,isElf,call):null;
    if(discovery && discovery.status!=='selected')return {status:'partial',reason:discovery.reason,discovery,usage_confirmed:false};
    const selected=discovery?.procedure??procedure;
    const dossier=await call('analyze_function',{procedure:selected});
    if(dossier.subject?.digest?.sha256!==identity)throw Error('rea_slice_identity_mismatch');
    const r=dossier.normalized_result,source=r.pseudocode??'';
    if(automatic && (dossier.provider?.id!==provider || typeof r.procedure?.address!=='string' || !/^0x[0-9a-f]+$/i.test(r.procedure.address) || BigInt(r.procedure.address)!==BigInt(selected!) || !containsAddress(r.procedure.body,discovery.reference_source_address)))throw Error('rea_native_function_identity_mismatch');
    const equalAddress=(a:any,b:any)=>{try{return typeof a==='string'&&typeof b==='string'&&/^0x[0-9a-f]+$/i.test(a)&&/^0x[0-9a-f]+$/i.test(b)&&BigInt(a)===BigInt(b);}catch{return false;}};
    const mapping=isElf?await mapElfReference(e,r.referenced_strings,identity,dossier.provider?.id,call):null;
    const directLiteral=e.transform===undefined||e.transform==='none';
    const referenced=isElf?mapping!.observed:directLiteral&&Array.isArray(r.referenced_strings)&&r.referenced_strings.some((s:any)=>equalAddress(s.address,discovery?.string_address??e.virtual_address));
    return {status:source?'function_body_recovered':'partial',verification_level:'candidate',usage_confirmed:false,
      artifact_sha256:record.artifact_sha256,member_sha256:e.member_sha256,...(isElf?{address_model:'elf_link_time',transform:e.transform}:{slice_sha256:e.slice_sha256,slice_index:e.slice_index,transform:e.transform??'none'}),
      ...(discovery?{discovery}:{}),evidence_id:dossier.evidence_id,provider:dossier.provider,procedure_address:r.procedure?.address??null,
      procedure_body:r.procedure?.body??null,...(mapping?{reference_mapping:mapping}:{}),string_address:e.virtual_address,direct_literal_reference_applicable:directLiteral,string_reference_observed:referenced,
      pseudocode_sha256:createHash('sha256').update(source).digest('hex'),pseudocode_bytes:Buffer.byteLength(source),
      limitations:['A selected function and any exact-address string reference are static observations, not proof of sensitive use, runtime execution or exploitability.','A false string_reference_observed means no exact match in returned referenced_strings, not proof that the function never uses the value.','Pseudocode text and literal values are not retained in reports. ELF references are joined by identity-bound original file offsets, limited to 32 returned addresses. Missing mappings or references remain unknown; decoded literals are not treated as direct references to the decoded value.']};
  }catch(error){return {status:'blocked',reason:combined.aborted?'rea_native_cancelled':error instanceof Error&&/^rea_[a-z_]+$/.test(error.message)?error.message:'rea_native_unavailable_or_timeout'};}
  finally {
    if(opened&&!combined.aborted)await client.callTool({name:'close_binary',arguments:{}},{timeout:5000}).catch(()=>{});
    clearTimeout(timer);await client.close().catch(()=>{});await transport.close().catch(()=>{});await rm(directory,{recursive:true,force:true});
  }
}
