import {test} from 'node:test';import assert from 'node:assert/strict';import {execFileSync} from 'node:child_process';
test('iOS literal decoding: explicit/implicit input, one layer, printable text, invalid data and per-slice budget',()=>{
 const r=execFileSync('python3',['-c',String.raw`
import sys,base64
sys.path.insert(0,'workers')
from ios_literal_decode import LiteralDecoder
text='password=synthetic-ios-value';encoded=base64.b64encode(text.encode()).decode()
d=LiteralDecoder()
assert d.decode(encoded)==(text,'base64_one_layer')
assert d.decode('base64:'+encoded)==(text,'base64_one_layer')
assert d.decode('hex:'+text.encode().hex())==(text,'hex_one_layer')
assert d.decode(base64.b64encode(encoded.encode()).decode())[0]==encoded
for value in ['ordinary public string','base64:'+'%'*24,'hex:'+'z'*32,'base64:'+base64.b64encode(b'\x00'*24).decode(),'hex:'+'ff'*20]:assert d.decode(value) is None
assert d.decode('base64:'+'A'*8193) is None and d.stats['skipped_size']==1
budget=LiteralDecoder()
for _ in range(2000):assert budget.decode(encoded)
assert budget.decode(encoded) is None and budget.stats['attempts']==2000 and budget.stats['skipped_budget']==1
assert LiteralDecoder().stats['attempts']==0
for invalid in [0,-1,20001,1.5,True,'2000',None]:
 try:LiteralDecoder(invalid)
 except ValueError:pass
 else:raise AssertionError('invalid budget accepted')
for limit in [1,20000]:
 decoder=LiteralDecoder(limit)
 assert decoder.stats['attempt_limit']==limit
 for _ in range(limit):assert decoder.decode(encoded)
 assert decoder.decode(encoded) is None and decoder.stats['skipped_budget']==1
print('ok')
`],{encoding:'utf8'});assert.equal(r.trim(),'ok');
});
