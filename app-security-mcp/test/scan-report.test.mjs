import {test} from 'node:test';import assert from 'node:assert/strict';
import {markdownReport} from '../dist/tools/scan-report.js';
test('human-readable report preserves remediation, unknowns and coverage while escaping package labels',()=>{
 const report=markdownReport({scan_id:'scan',platform:'ios',state:'partial',finding_count:1,profile:'static-deep',effective_profile:'static-basic',coverage:{hardcoding_detection:'partial'},rules:[{status:'not_run'}],limitations:['No runtime validation.'],findings:[{
  finding_id:'f-0001',rule_id:'HC-001',title:'candidate',severity:'needs_review',confidence:'medium',verification_level:'candidate',evidence_id:'e-f-0001',
  evidence:{path:'[click](https://invalid)\n# malicious <script> ```',location:'line:1'},observations:['[REDACTED]'],unknowns:['Permission unknown'],remediation:'Remove shared credential.',retest:'Verify rotation and rebuild.'
 }]});
 for(const text of ['## 覆盖与缺口','## 候选与修复','**修复建议**','**复测方法**','Permission unknown','not_run','effective_profile','No runtime validation'])assert.ok(report.includes(text));
 assert.ok(!report.includes('\n# malicious'));assert.ok(!report.includes('<script>'));assert.ok(!report.split('```json')[0].includes('[click](https://invalid)'));
 assert.equal(report.split('```').length,3,'only appendix code fence remains');
});
