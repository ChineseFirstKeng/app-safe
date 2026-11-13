// Builtin OpenSSL parser. No export, signing, decryption, networking or error text.
import { parseOpenSsh } from './openssh_key.mjs';
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
let input='';for await(const chunk of process.stdin){input+=chunk;if(input.length>200000)process.exit(2);}
try{
 const r=JSON.parse(input);const data=r.format==='der'?Buffer.from(r.data,'base64'):r.data;
 let key,needsPassphrase=false;
 if(r.format==='pem'&&data.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----')){const parsed=parseOpenSsh(data);if(!parsed.key){console.log(JSON.stringify(parsed));process.exit(0);}key=parsed.key;}
 if(!key)for(const type of r.format==='der'?['pkcs8','pkcs1','sec1']:[undefined]){
  try{key=createPrivateKey({key:data,format:r.format,...(type?{type}:{})});break;}catch(e){if(e.code==='ERR_MISSING_PASSPHRASE')needsPassphrase=true;}
 }
 if(key){const algorithm=key.asymmetricKeyType;const bits=key.asymmetricKeyDetails?.modulusLength;
  console.log(JSON.stringify({status:'parsed_private_key',algorithm, ...(Number.isSafeInteger(bits)?{modulus_bits:bits}:{})}));
 }else{
  let status=needsPassphrase?'encrypted_container_requires_passphrase':'invalid_or_unsupported';
  try{new X509Certificate(data);status='public_certificate';}catch{}
  if(status!=='public_certificate')for(const type of r.format==='der'?['spki','pkcs1']:[undefined])try{createPublicKey({key:data,format:r.format,...(type?{type}:{})});status='public_key';break;}catch{}
  if(r.format==='pem' && (data.startsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----') || data.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----') || /^-----BEGIN (?:RSA |EC )PRIVATE KEY-----[\s\S]*Proc-Type:\s*4,ENCRYPTED/.test(data)))status='encrypted_or_unsupported_envelope';
  console.log(JSON.stringify({status}));
 }
}catch{console.log(JSON.stringify({status:'parse_request_failed'}));}
