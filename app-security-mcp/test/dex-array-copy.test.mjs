import {test} from 'node:test';import assert from 'node:assert/strict';import {execFileSync} from 'node:child_process';
test('byte array copy: truncation, padding, empty boundary and invalid/oversize inputs',()=>{
 const r=execFileSync('python3',['-c',String.raw`
import sys
sys.path.insert(0,'workers')
from dex_array_copy import copy_bytes
assert copy_bytes(b'abcd',1,3)==(b'bc',0)
assert copy_bytes(b'abcd',0,6)==(b'abcd\0\0',2)
assert copy_bytes(b'abcd',4,6)==(b'\0\0',2)
assert copy_bytes(b'',0,2)==(b'\0\0',2)
assert copy_bytes(b'abcd',0,0)==(b'',0)
assert copy_bytes(b'a',0,8192)==(b'a'+b'\0'*8191,8191)
for source,start,end in [(None,0,2),(b'ab',-1,1),(b'ab',3,4),(b'ab',2,1),(b'ab',0,8193),(b'a'*8193,0,1),(b'ab',True,2),(b'ab',0,1.5)]:assert copy_bytes(source,start,end) is None
print('ok')
`],{encoding:'utf8'});assert.equal(r.trim(),'ok');
});
