import {test} from 'node:test';
import assert from 'node:assert/strict';
import {findingPage} from '../dist/tools/finding-page.js';
test('finding pagination binds scan, filters and snapshot; exhaustion never claims full source coverage',()=>{
 const r={scan_id:'scan-a',state:'partial',finding_count:4,findings:[
  {finding_id:'1',rule_id:'HC-001',severity:'needs_review',confidence:'medium'},
  {finding_id:'2',rule_id:'HC-002',severity:'needs_review',confidence:'medium'},
  {finding_id:'3',rule_id:'HC-001',severity:'needs_review',confidence:'medium'},
  {finding_id:'4',rule_id:'HC-001',severity:'needs_review',confidence:'low'},
 ],resource_scan:{findings_truncated:true}};
 const args={limit:1,rule_id:'HC-001',confidence:'medium'};
 const first=findingPage(r,args);assert.equal(first.filtered_count,2);assert.equal(first.finding_count,4);assert.equal(first.findings[0].finding_id,'1');
 const second=findingPage(r,{...args,cursor:first.next_cursor});assert.equal(second.findings[0].finding_id,'3');assert.equal(second.next_cursor,null);assert.equal(second.source_complete,false);assert.equal(second.findings_truncated,true);
 for(const [record,params] of [[r,{...args,confidence:'low'}],[{...r,scan_id:'scan-b'},args],[{...r,findings:r.findings.slice(1)},args],[r,{...args,offset:1}]]) {
  assert.throws(()=>findingPage(record,{...params,cursor:first.next_cursor}),/invalid_or_stale_cursor/);
 }
 assert.throws(()=>findingPage(r,{limit:1,cursor:'bad'}),/invalid_or_stale_cursor/);
 assert.equal(findingPage(r,{limit:1,severity:'high'}).filtered_count,0);
 assert.equal(findingPage(r,{limit:1,offset:2}).findings[0].finding_id,'3');
});
