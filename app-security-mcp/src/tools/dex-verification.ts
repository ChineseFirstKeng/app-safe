import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { awaitableTransportClose } from './rea-transport.js';
import { Client } from '@modelcontextprotocol/client';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { copyFile, chmod, mkdtemp, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

/** Optional second-engine corroboration. Does not upgrade a candidate to a vulnerability. */
export async function verifyDexMethod(record:any, finding:any, artifactRoot:string, signal?:AbortSignal) {
  if(signal?.aborted)return {status:'blocked',reason:'rea_cancelled'};
  const e=finding.evidence;
  if(e?.archive_chain?.length)return {status:'not_applicable',reason:'nested_dex_verification_not_supported'};
  if(!e?.class_descriptor||!e?.method||!e?.prototype)return {status:'not_applicable',reason:'finding_has_no_dex_method'};
  let command=process.env.APP_SECURITY_REA_COMMAND;
  let args:string[]=[];let providerEnv:Record<string,string>={};
  try {
    if(command===undefined){
      const config=JSON.parse(await readFile(process.env.APP_SECURITY_REA_CONFIG??join(homedir(),'.app-security','rea.json'),'utf8'));
      command=config.command;args=config.args??[];providerEnv=config.env??{};
    }else args=JSON.parse(process.env.APP_SECURITY_REA_ARGS??'[]');
    if(typeof command!=='string'||!command)return {status:'blocked',reason:'rea_command_not_configured'};
    if(!Array.isArray(args)||args.some(x=>typeof x!=='string')||!providerEnv||Array.isArray(providerEnv)||typeof providerEnv!=='object'||Object.values(providerEnv).some(v=>typeof v!=='string'))throw Error();
  } catch {return {status:'blocked',reason:'rea_config_missing_or_invalid'};}
  const source=join(artifactRoot,record.artifact_id,'package.bin');
  const hash=createHash('sha256');for await(const chunk of createReadStream(source)){if(signal?.aborted)return {status:'blocked',reason:'rea_cancelled'};hash.update(chunk);}
  if(hash.digest('hex')!==record.artifact_sha256)return {status:'blocked',reason:'artifact_digest_mismatch'};
  const directory=await mkdtemp(join(artifactRoot,'_scans','.rea-'));
  const path=join(directory,'target.apk');
  const client=new Client({name:'app-security-dex-verifier',version:'0.5.0'});
  const transport=new StdioClientTransport({command,args,env:{...process.env,...providerEnv} as Record<string,string>,stderr:'ignore'});
  awaitableTransportClose(transport);
  const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),150000);
  const combined=signal?AbortSignal.any([signal,controller.signal]):controller.signal;
  try {
    combined.throwIfAborted();
    await copyFile(source,path);await chmod(path,0o600);
    // Start draining diagnostics immediately; never expose provider source/credentials in errors.
    await client.connect(transport,{signal:combined,timeout:150000});
    const call=async(name:string,arguments_:any)=>{
      const r:any=await client.callTool({name,arguments:arguments_},{signal:combined,timeout:150000});
      if(r.isError)throw Error('rea_provider_failed');
      const result=r.structuredContent??JSON.parse(r.content.find((c:any)=>c.type==='text').text);
      if(result.subject?.digest?.sha256!==record.artifact_sha256)throw Error('rea_artifact_identity_mismatch');
      return result;
    };
    const rawClass=e.class_descriptor.replace(/^L/,'').replace(/;$/,'').replaceAll('/','.');
    const query=rawClass.split('.').at(-1);
    const inventory=await call('search_android_classes',{path,query});
    const names=inventory.normalized_result.matches;
    const matching=names.filter((n:string)=>n===rawClass||(!rawClass.includes('.')&&n===`defpackage.${rawClass}`));
    if(matching.length!==1)return {status:'blocked',reason:'rea_class_alias_or_duplicates_unresolved'};
    const class_name=matching[0];
    const klass=await call('inspect_android_class',{path,class_name});
    const candidates=klass.normalized_result.methods.filter((m:any)=>m.name===e.method&&m.dex_descriptor===e.prototype);
    if(candidates.length!==1)return {status:'blocked',reason:'rea_method_identity_unresolved'};
    const method=await call('inspect_android_method',{path,class_name,method_name:e.method,overload_index:candidates[0].overload_index});
    const result=method.normalized_result;
    if(result.method.dex_descriptor!==e.prototype)throw Error('rea_method_identity_mismatch');
    // Only persist bounded metadata and source digest, never decompiled source/raw_result.
    const sourceText=result.source.text;
    return {status:result.body_status==='available'?'method_body_recovered':'partial',
      verification_level:'candidate',evidence_id:method.evidence_id,artifact_sha256:record.artifact_sha256,
      class_name,method:e.method,prototype:e.prototype,overload_index:result.method.overload_index,
      representation:result.representation,source_status:result.source.status,
      source_sha256:createHash('sha256').update(sourceText).digest('hex'),source_bytes:Buffer.byteLength(sourceText),
      engine:result.engine,provider:method.provider,
      usage_confirmed:false,
      limitations:['REA corroborates method identity and recovers a body; it does not verify the scanner value flow or establish runtime use, credential validity or exploitability.','Decompiler text is not retained in the report to avoid leaking secrets. Evidence metadata and source digest are retained.']};
  } catch(e) {
    const reason=signal?.aborted?'rea_cancelled':e instanceof Error&&/^rea_[a-z_]+$/.test(e.message)?e.message:'rea_unavailable_or_timeout';
    return {status:'blocked',reason};
  } finally {clearTimeout(timeout);await client.close().catch(()=>{});await transport.close().catch(()=>{});await rm(directory,{recursive:true,force:true});}
}
