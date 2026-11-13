import {test} from 'node:test';import assert from 'node:assert/strict';import {execFileSync} from 'node:child_process';
test('UTF8 String restoration: exact slice, multibyte boundary, invalid input and budget',()=>{
 const r=execFileSync('python3',['-c',String.raw`
import sys
sys.path.insert(0,'workers')
from dex_utf8_string import restore_utf8
assert restore_utf8(b'xhello!',1,5)=='hello'
assert restore_utf8('中文'.encode(),0,6)=='中文'
assert restore_utf8('中文'.encode(),1,5) is None
assert restore_utf8(b'\xff',0,1) is None
assert restore_utf8(b'',0,0)==''
assert restore_utf8(b'a'*8192,0,8192)=='a'*8192
for data,start,length in [(None,0,0),(b'a',-1,1),(b'a',0,-1),(b'a',1,1),(b'a',False,1),(b'a',0,1.5),(b'a'*8193,0,1)]:assert restore_utf8(data,start,length) is None
print('ok')
`],{encoding:'utf8'});assert.equal(r.trim(),'ok');
});
