import {test} from 'node:test';import assert from 'node:assert/strict';
import {discoverNativeProcedure} from '../dist/tools/native-discovery.js';
const e={transform:'none',file_offset:0x240,virtual_address:'0x240'};
const body={available:true,ranges:[{start:'0x1000',end:'0x101f'}]};
const bound=r=>({subject:{digest:{sha256:'identity'}},provider:{id:'ghidra'},evidence_id:'evidence',normalized_result:r});
function provider(mode='ok') {return async(name,args)=>{
 if(name==='address_to_file_offset')return bound({address:args.address,file_offset:args.address==='0x8240'?0x240:0});
 if(name==='list_strings')return mode==='wrong-id'?{...bound([]),subject:{digest:{sha256:'other'}}}:bound([{address:'0x8200',value:'must-not-retain'},{address:'0x8240',value:'must-not-retain'}]);
 if(name==='xrefs')return bound(mode==='no-refs'?[]:['0x1008']);
 if(name==='resolve_containing_procedure')return bound({found:true,query_address:mode==='wrong-query'?'0x1004':args.address,procedure:{address:'0x1000',body:mode==='outside-body'?{available:true,ranges:[{start:'0x2000',end:'0x2010'}]}:body,classification:{external:mode==='external'}}});
 throw Error('unexpected operation');
};}
test('native discovery binds original offsets, uses containing function and rejects guessed or unbound results',async()=>{
 const r=await discoverNativeProcedure(e,'identity','ghidra',true,provider());assert.equal(r.status,'selected');assert.equal(r.procedure,'0x1000');assert.equal(r.string_address,'0x8240');assert.equal(r.original_file_offset,0x240);assert.ok(!JSON.stringify(r).includes('must-not-retain'));
 for(const mode of ['no-refs','wrong-query','outside-body','external'])assert.equal((await discoverNativeProcedure(e,'identity','ghidra',true,provider(mode))).status,'partial');
 await assert.rejects(discoverNativeProcedure(e,'identity','ghidra',true,provider('wrong-id')),/identity_mismatch/);
 let calls=0;const no=()=>{calls++;throw Error('must not call provider');};
 assert.equal((await discoverNativeProcedure({...e,transform:'base64'},'identity','ghidra',true,no)).reason,'decoded_value_not_a_direct_literal');
 assert.equal((await discoverNativeProcedure({...e,file_offset:-1},'identity','ghidra',true,no)).reason,'candidate_file_offset_invalid');assert.equal(calls,0);
 const ios=await discoverNativeProcedure({...e,file_offset:0x1240,slice_offset:0x1000},'identity','ghidra',false,provider());assert.equal(ios.original_file_offset,0x240);
});
test('native discovery enforces string mapping and xref budgets',async()=>{
 let mapped=0;const p=async(name,args)=>{if(name==='list_strings')return bound(Array.from({length:200},(_,i)=>({address:'0x'+(i+1000).toString(16)})));if(name==='address_to_file_offset'){mapped++;return bound({address:args.address,file_offset:99});}throw Error('unexpected');};
 const r=await discoverNativeProcedure(e,'identity','ghidra',true,p);assert.equal(r.reason,'candidate_address_not_mapped');assert.equal(r.strings_truncated,true);assert.equal(mapped,129);
 let resolved=0;const x=async(name,args)=>{if(name==='address_to_file_offset')return bound({address:args.address,file_offset:0x240});if(name==='xrefs')return bound(Array.from({length:100},(_,i)=>'0x'+(i+1000).toString(16)));if(name==='resolve_containing_procedure'){resolved++;return bound({found:false});}throw Error('unexpected');};
 const v=await discoverNativeProcedure(e,'identity','ghidra',true,x);assert.equal(v.references_truncated,true);assert.equal(resolved,32);
});
