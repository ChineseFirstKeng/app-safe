import {test} from 'node:test';import assert from 'node:assert/strict';import {execFileSync} from 'node:child_process';
test('HC-009 entry-prefix provenance: rejects clobbers, non-parameters, loops, extra branches and unknown calls',()=>{
 const result=execFileSync('python3',['-c',String.raw`
import sys
sys.path.insert(0,'workers')
from android_auth import inspect_guard
base={'method':'checkPassword','class_descriptor':'LFixture;','prototype':'(Ljava/lang/String;)V'}
ops=[(100,0,'const-string v0, "hidden" // string@0000'),(104,2,'invoke-virtual {v0, v2}, Ljava/lang/String;.equals:(Ljava/lang/Object;)Z // method@0001'),(110,5,'move-result v0'),(112,6,'if-eqz v0, 0009 // +0003'),(116,8,'return-void'),(118,9,'return-void')]
def run(o=ops,b=base,p=(2,)):
 out=[];inspect_guard(o,[('synthetic-fixed-comparison',0)],b,p,lambda *a:out.append(a));return out
r=run();assert len(r)==1 and r[0][3]=='HC-009'
assert r[0][0]=='synthetic-fixed-comparison' # Internal callback preserves the comparison value; MCP redaction is verified by dex.test.mjs.
assert r[0][2]['comparison_file_offset']==104 and r[0][2]['file_offset']==112
assert not run(p=())
assert not run(b={**base,'method':'checkTheme'})
assert not run(ops[:3]+[(112,6,'if-eqz v0, 0000 // -0006')]+ops[4:])
assert not run(ops+[(120,10,'if-eqz v2, 0009 // -0001')])
assert not run(ops+[(120,10,'goto 0000 // -000a')])
assert not run(ops[:1]+[(102,1,'move-object v0, v2')]+ops[1:])
assert not run(ops[:3]+[(111,5,'const/4 v0, #int 1 // #1')]+ops[3:])
assert not run(ops[:1]+[(102,1,'invoke-static {}, LFixture;.unknown:()V // method@0002')]+ops[1:])
print('ok')
`],{encoding:'utf8'});assert.equal(result.trim(),'ok');
});
