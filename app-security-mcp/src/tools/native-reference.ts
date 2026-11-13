// Join provider string references to the immutable ELF file, never guess a load bias.
export async function mapElfReference(e: any, references: any, identity: string, providerId: string, call: (name:string,args:any)=>Promise<any>) {
  const base={method:'provider_address_to_original_file_offset',candidate_file_offset:e.file_offset,checked:0,failed:0,truncated:false,matches:[] as any[]};
  if(e.transform!=='none')return {...base,status:'not_applicable',reason:'decoded_value_not_a_direct_literal',observed:false};
  if(!Number.isSafeInteger(e.file_offset)||e.file_offset<0)return {...base,status:'unknown',reason:'candidate_file_offset_invalid',observed:false};
  if(!Array.isArray(references))return {...base,status:'unknown',reason:'provider_references_unavailable',observed:false};
  const addresses=[...new Set(references.map((r:any)=>r?.address).filter((a:any)=>typeof a==='string'&&/^0x[0-9a-f]+$/i.test(a)))];
  base.truncated=addresses.length>32;
  if(references.some((r:any)=>typeof r?.address!=='string'||!/^0x[0-9a-f]+$/i.test(r.address)))base.failed++;
  for(const address of addresses.slice(0,32)) {
    base.checked++;
    try {
      const m=await call('address_to_file_offset',{address});const v=m.normalized_result;
      if(m.subject?.digest?.sha256!==identity||m.provider?.id!==providerId||!v||typeof v.address!=='string'||!/^0x[0-9a-f]+$/i.test(v.address)||BigInt(v.address)!==BigInt(address)||!Number.isSafeInteger(v.file_offset)||v.file_offset<0||typeof m.evidence_id!=='string')throw Error('mapping_not_bound');
      if(v.file_offset===e.file_offset)base.matches.push({provider_address:v.address,file_offset:v.file_offset,evidence_id:m.evidence_id});
    } catch {base.failed++;}
  }
  return {...base,status:base.matches.length?'matched':base.failed||base.truncated?'partial':'no_match_in_returned_references',observed:base.matches.length>0};
}
