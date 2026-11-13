import {test} from 'node:test';import assert from 'node:assert/strict';import {execFileSync} from 'node:child_process';
test('leaf method summary: exact signature, static flag, register match and bounded value',()=>{
 const r=execFileSync('python3',['-c',String.raw`
import sys
sys.path.insert(0,'workers')
from dex_method_summary import summarize
ops=[(100,0,'const-string v0, "redacted" // string@0000'),(104,2,'return-object v0')]
pool=[('synthetic-value',50)]
def run(ops=ops,pool=pool,proto='()Ljava/lang/String;',static=True):return summarize(ops,pool,'LTest;','secret',proto,static)
assert run()[0]=='LTest;.secret:()Ljava/lang/String;'
assert run()[1]['provenance']['callee_literal_file_offset']==100
assert run(static=False) is None
assert run(proto='(I)Ljava/lang/String;') is None
assert run(ops=ops[:-1]+[(104,2,'return-object v1')]) is None
assert run(ops=ops+[(106,3,'return-object v0')]) is None
assert run(ops=[(98,0,'invoke-static {}, LTest;.other:()V // method@0001')]+ops) is None
assert run(pool=[]) is None
assert run(pool=[('a'*8193,50)]) is None
assert run(ops=[(98,0,'nop')]+ops)
print('ok')
`],{encoding:'utf8'});assert.equal(r.trim(),'ok');
});

test('wrapper summaries: bounded chain, missing target, cycles and exact forwarding instructions',()=>{
 const r=execFileSync('python3',['-c',String.raw`
import sys
sys.path.insert(0,'workers')
from dex_method_summary import summarize,resolve_summaries
proto='()Ljava/lang/String;'
leaf=summarize([(100,0,'const-string v0, "redacted" // string@0000'),(104,2,'return-object v0')],[('synthetic-value',50)],'LTest;','leaf',proto,True)
def wrapper(name,target,reg='v0'):
 return summarize([(200,0,'invoke-static {}, LTest;.'+target+':'+proto+' // method@0000'),(206,3,'move-result-object v0'),(208,4,'return-object '+reg)],[],'LTest;',name,proto,True)
rows=dict([leaf]);previous='leaf'
for i in range(1,6):
 name='wrap'+str(i);k,v=wrapper(name,previous);rows[k]=v;previous=name
for name,target in [('cycleA','cycleB'),('cycleB','cycleA'),('missing','absent')]:
 k,v=wrapper(name,target);rows[k]=v
assert wrapper('bad','leaf','v1') is None
result,count=resolve_summaries(dict(reversed(list(rows.items()))))
assert result['LTest;.wrap4:'+proto]['provenance']['wrapper_depth']==4
assert result['LTest;.wrap4:'+proto]['value']=='synthetic-value'
for name in ['wrap5','cycleA','cycleB','missing']:assert result['LTest;.'+name+':'+proto] is None
assert count==4
assert result[leaf[0]]['provenance']['wrapper_depth']==0
print('ok')
`],{encoding:'utf8'});assert.equal(r.trim(),'ok');
});
