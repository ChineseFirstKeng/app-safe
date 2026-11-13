import {test} from 'node:test';import assert from 'node:assert/strict';import {generateKeyPairSync} from 'node:crypto';import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import {execFileSync} from 'node:child_process';
import {parseOpenSsh} from '../workers/openssh_key.mjs';import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
const u=n=>{const b=Buffer.alloc(4);b.writeUInt32BE(n);return b;};
const s=b=>{b=Buffer.from(b);return Buffer.concat([u(b.length),b]);};
const mp=b=>{b=Buffer.from(b,'base64url');while(b.length>1&&b[0]===0)b=b.subarray(1);if(b[0]&128)b=Buffer.concat([Buffer.from([0]),b]);return s(b);};
const armor=b=>'-----BEGIN OPENSSH PRIVATE KEY-----\n'+b.toString('base64').match(/.{1,70}/g).join('\n')+'\n-----END OPENSSH PRIVATE KEY-----';
function fixture(kind,{comment='fixture',badCheck=false,badPublic=false,badPadding=false,encrypted=false}={}){
 const type=kind==='rsa'?'ssh-rsa':kind==='ed25519'?'ssh-ed25519':'ecdsa-sha2-nistp256';
 const pair=kind==='rsa'?generateKeyPairSync('rsa',{modulusLength:1024}):kind==='ed25519'?generateKeyPairSync('ed25519'):generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const jwk=pair.privateKey.export({format:'jwk'});let pub,priv;
 if(kind==='rsa'){pub=Buffer.concat([s(type),mp(jwk.e),mp(jwk.n)]);priv=Buffer.concat([s(type),mp(jwk.n),mp(jwk.e),mp(jwk.d),mp(jwk.qi),mp(jwk.p),mp(jwk.q)]);}
 else if(kind==='ed25519'){const point=Buffer.from(jwk.x,'base64url');pub=Buffer.concat([s(type),s(point)]);priv=Buffer.concat([s(type),s(point),s(Buffer.concat([Buffer.from(jwk.d,'base64url'),point]))]);}
 else{const point=Buffer.concat([Buffer.from([4]),Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]);pub=Buffer.concat([s(type),s('nistp256'),s(point)]);priv=Buffer.concat([s(type),s('nistp256'),s(point),mp(jwk.d)]);}
 if(badPublic){pub=Buffer.from(pub);pub[pub.length-1]^=1;}
 let block=Buffer.concat([u(0x12345678),u(badCheck?123:0x12345678),priv,s(comment)]);let padding=(8-block.length%8)%8;if(badPadding&&!padding)padding=8;block=Buffer.concat([block,Buffer.from(Array.from({length:padding},(_,i)=>badPadding?255:i+1))]);
 const outer=Buffer.concat([Buffer.from('openssh-key-v1\0'),s(encrypted?'aes256-ctr':'none'),s(encrypted?'bcrypt':'none'),s(encrypted?Buffer.concat([s(Buffer.alloc(16,1)),u(16)]):Buffer.alloc(0)),u(1),s(pub),s(encrypted?Buffer.alloc(16,7):block)]);
 return {pem:armor(outer),bytes:outer,padding};
}
test('OpenSSH unencrypted Ed25519/RSA/ECDSA conversion validates public identity, checks, padding and malformed bounds',()=>{
 for(const kind of ['ed25519','rsa','ec']){const good=parseOpenSsh(fixture(kind).pem);assert.ok(good.key);assert.equal(good.key.asymmetricKeyType,kind==='ec'?'ec':kind);for(const options of [{badCheck:true},{badPublic:true},{badPadding:true}])assert.equal(parseOpenSsh(fixture(kind,options).pem).status,'invalid_or_unsupported');}
 for(let i=0;i<8;i++){const sample=fixture('ed25519',{comment:'x'.repeat(i)});assert.ok(parseOpenSsh(sample.pem).key);}
 const good=fixture('ed25519');for(const b of [good.bytes.subarray(0,-1),Buffer.from('invalid'),Buffer.concat([good.bytes,Buffer.from([0])])])assert.equal(parseOpenSsh(armor(b)).status,'invalid_or_unsupported');
 assert.equal(parseOpenSsh(fixture('ed25519',{encrypted:true}).pem).status,'encrypted_container_requires_passphrase');
});
test('packaged OpenSSH private keys: both platforms, invalid/public controls and redacted results',{timeout:30000},async t=>{
 const root=await mkdtemp(join(tmpdir(),'openssh-key-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const files={};for(const kind of ['ed25519','rsa','ec'])files[kind+'.key']=fixture(kind).pem;
 files['encrypted.key']=fixture('ed25519',{encrypted:true}).pem;files['invalid.key']=fixture('ed25519',{badPublic:true}).pem;
 await writeFile(join(root,'files.json'),JSON.stringify(files));execFileSync('python3',['-c',String.raw`
import sys,json,zipfile,plistlib
from pathlib import Path
p=Path(sys.argv[1]);files=json.loads((p/'files.json').read_text())
for platform in ('android','ios'):
 with zipfile.ZipFile(p/(platform+'.zip'),'w') as z:
  prefix='assets/' if platform=='android' else 'Payload/App.app/'
  if platform=='android':z.writestr('AndroidManifest.xml','fixture')
  else:z.writestr(prefix+'Info.plist',plistlib.dumps({'CFBundleIdentifier':'example.fixture'}))
  for name,data in files.items():z.writestr(prefix+name,data)
`,root],{stdio:['ignore','pipe','pipe']});
 const c=new Client({name:'openssh-test',version:'1'});await c.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_DATA_DIR:join(root,'store')},stderr:'ignore'}));t.after(()=>c.close());
 const call=async(name,args)=>{const r=await c.callTool({name,arguments:args});assert.ok(!r.isError,JSON.stringify(r));return r.structuredContent;};
 for(const platform of ['android','ios']){const imported=await call('import_local_artifact',{path:join(root,platform+'.zip')});const scan=await call('scan_'+platform+'_hardcoding',{artifact_id:imported.artifact_id});let status;do{await new Promise(r=>setTimeout(r,20));status=await call('get_scan_status',{scan_id:scan.scan_id});}while(['queued','running'].includes(status.state));assert.equal(status.state,'partial');assert.equal(status.key_material_scan.parsed,3);assert.equal(status.key_material_scan.unresolved,1);
 const page=await call('list_findings',{scan_id:scan.scan_id,limit:100});assert.equal(page.findings.length,4);assert.ok(!page.findings.some(f=>f.evidence.path.endsWith('invalid.key')));
 const report=await call('export_report',{scan_id:scan.scan_id,format:'json'});assert.ok(!(await readFile(report.path,'utf8')).includes('BEGIN OPENSSH'));
 }
});
