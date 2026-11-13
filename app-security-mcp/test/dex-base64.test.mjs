import {test} from 'node:test';import assert from 'node:assert/strict';import {execFileSync} from 'node:child_process';
test('DEX Base64 subset: padding, whitespace policy, invalid alphabet, one layer and input budget',()=>{
 const result=execFileSync('python3',['-c',String.raw`
import sys,base64
sys.path.insert(0,'workers')
from dex_base64 import decode_literal as d
assert d('YQ==')==b'a' and d('YQ')==b'a' and d('YWI')==b'ab'
assert d(' YQ==\n',True)==b'a'
assert d(' YQ==\n') is None
for s in ['A','YQ=','YQ===','YQ==x','YW%Jj','-_8=','====','éééé','A'*8193]:assert d(s) is None,s[:20]
assert d(None) is None and d({'value':'YQ=='}) is None
assert len(d('A'*8192))==6144
nested=base64.b64encode(b'YQ==').decode();assert d(nested)==b'YQ=='
print('ok')
`],{encoding:'utf8'});assert.equal(result.trim(),'ok');
});
