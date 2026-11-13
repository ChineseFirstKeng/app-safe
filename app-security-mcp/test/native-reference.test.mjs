import {test} from 'node:test';import assert from 'node:assert/strict';
import {mapElfReference} from '../dist/tools/native-reference.js';
const candidate={transform:'none',file_offset:974,virtual_address:'0x3ce'};
const refs=[{address:'0x1003ce',value:'must-not-be-retained'}];
const response={subject:{digest:{sha256:'fixture-digest'}},provider:{id:'ghidra'},evidence_id:'ev-map',normalized_result:{address:'0x1003ce',file_offset:974}};
const map=(e=candidate,r=refs,fn=async()=>response)=>mapElfReference(e,r,'fixture-digest','ghidra',fn);
test('ELF reference joins rebased address by file offset, preserves evidence and suppresses literals',async()=>{
 const result=await map();assert.equal(result.observed,true);assert.equal(result.status,'matched');assert.equal(result.matches[0].evidence_id,'ev-map');assert.ok(!JSON.stringify(result).includes('must-not-be-retained'));
 assert.equal((await map(candidate,refs,async()=>({...response,normalized_result:{address:'0x1003ce',file_offset:975}}))).observed,false);
});
test('ELF mapping rejects wrong binary/provider/address, unavailable mapping and decoded literals',async()=>{
 for(const bad of [{...response,subject:{digest:{sha256:'other'}}},{...response,provider:{id:'other'}},{...response,normalized_result:{address:'0xdead',file_offset:974}},{...response,normalized_result:{address:'0x1003ce',file_offset:NaN}}]){const r=await map(candidate,refs,async()=>bad);assert.equal(r.observed,false);assert.equal(r.status,'partial');}
 assert.equal((await map(candidate,refs,async()=>{throw Error('unsupported');})).status,'partial');
 for(const transform of ['base64_one_layer','hex_one_layer'])assert.equal((await map({...candidate,transform},refs,async()=>{assert.fail('must not map decoded value');})).status,'not_applicable');
 assert.equal((await map(candidate,null)).status,'unknown');
});
test('ELF mapping deduplicates and bounds provider work',async()=>{
 let calls=0;const r=await map(candidate,Array.from({length:40},(_,i)=>({address:'0x'+(1000+i).toString(16)})),async()=>{calls++;throw Error('unmapped');});assert.equal(calls,32);assert.equal(r.truncated,true);assert.equal(r.status,'partial');
 assert.equal((await map(candidate,[...refs,...refs])).checked,1);
});
