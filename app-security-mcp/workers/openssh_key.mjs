import { createPrivateKey, createPublicKey } from 'node:crypto';
const tlv=(tag,b)=>{let len=b.length<128?Buffer.from([b.length]):(()=>{let s=b.length.toString(16);if(s.length%2)s='0'+s;const n=Buffer.from(s,'hex');return Buffer.concat([Buffer.from([0x80|n.length]),n]);})();return Buffer.concat([Buffer.from([tag]),len,b]);};
const integer=n=>{if(n<0n)throw Error();let hex=n.toString(16);if(hex.length%2)hex='0'+hex;let b=Buffer.from(hex,'hex');if(b[0]&0x80)b=Buffer.concat([Buffer.from([0]),b]);return tlv(2,b);};
class Reader {
 constructor(data){this.data=data;this.offset=0;}
 u32(){if(this.offset+4>this.data.length)throw Error();const n=this.data.readUInt32BE(this.offset);this.offset+=4;return n;}
 bytes(){const n=this.u32();if(n>131072||this.offset+n>this.data.length)throw Error();const b=this.data.subarray(this.offset,this.offset+n);this.offset+=n;return b;}
 text(){const b=this.bytes();if(b.length>128||[...b].some(c=>c<32||c>126))throw Error();return b.toString('ascii');}
 mpint(){let b=this.bytes();if(!b.length||b.length>1025||b[0]&0x80||b.length>1&&b[0]===0&&!(b[1]&0x80))throw Error();return BigInt('0x'+b.toString('hex'));}
 end(){if(this.offset!==this.data.length)throw Error();}
}
/** Validate structure and derive public material from an unencrypted private key.
 * Output is a KeyObject or an explicit encrypted-container state, never key bytes. */
export function parseOpenSsh(pem){
 try{
  const m=/^-----BEGIN OPENSSH PRIVATE KEY-----\s*([A-Za-z0-9+/=\r\n]+)\s*-----END OPENSSH PRIVATE KEY-----$/.exec(pem.trim());if(!m)throw Error();
  const encoded=m[1].replace(/\s/g,'');const bytes=Buffer.from(encoded,'base64');if(bytes.toString('base64')!==encoded||bytes.length>131072||!bytes.subarray(0,15).equals(Buffer.from('openssh-key-v1\0')))throw Error();
  const outer=new Reader(bytes.subarray(15)),cipher=outer.text(),kdf=outer.text(),options=outer.bytes();const count=outer.u32();if(count>1&&count<=16)return {status:'encrypted_or_unsupported_envelope'};if(count!==1)throw Error();
  const publicBlob=outer.bytes(),privateBlob=outer.bytes();outer.end();
  if(cipher!=='none'){
   if(kdf!=='bcrypt'||!privateBlob.length||!publicBlob.length)throw Error();
   const opts=new Reader(options);const salt=opts.bytes();const rounds=opts.u32();opts.end();if(!salt.length||salt.length>1024||!rounds)throw Error();
   return {status:'encrypted_container_requires_passphrase'};
  }
  if(kdf!=='none'||options.length||privateBlob.length%8)throw Error();
  const priv=new Reader(privateBlob);if(priv.u32()!==priv.u32())throw Error();const type=priv.text(),pub=new Reader(publicBlob);if(pub.text()!==type)throw Error();let key;
  if(type==='ssh-ed25519'){
   const publicKey=priv.bytes(),privateKey=priv.bytes(),outside=pub.bytes();pub.end();
   if(publicKey.length!==32||privateKey.length!==64||!outside.equals(publicKey)||!privateKey.subarray(32).equals(publicKey))throw Error();
   key=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),privateKey.subarray(0,32)]),format:'der',type:'pkcs8'});
   if(!createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32).equals(publicKey))throw Error();
  }else if(type==='ssh-rsa'){
   const n=priv.mpint(),e=priv.mpint(),d=priv.mpint(),qi=priv.mpint(),p=priv.mpint(),q=priv.mpint();
   if(pub.mpint()!==e||pub.mpint()!==n)throw Error();pub.end();
   if(p<=1n||q<=1n||p*q!==n||qi*q%p!==1n)throw Error();
   let a=p-1n,b=q-1n;while(b){const t=a%b;a=b;b=t;}if(d*e%((p-1n)/a*(q-1n))!==1n)throw Error();
   key=createPrivateKey({key:tlv(0x30,Buffer.concat([0n,n,e,d,p,q,d%(p-1n),d%(q-1n),qi].map(integer))),format:'der',type:'pkcs1'});
  }else if(type.startsWith('ecdsa-sha2-')){
   const curves={nistp256:{size:32,oid:'06082a8648ce3d030107'},nistp384:{size:48,oid:'06052b81040022'},nistp521:{size:66,oid:'06052b81040023'}};
   const curve=priv.text(),point=priv.bytes(),d=priv.mpint(),spec=curves[curve];
   if(!Object.hasOwn(curves,curve)||!spec||type!=='ecdsa-sha2-'+curve||pub.text()!==curve||!pub.bytes().equals(point)||point.length!==1+2*spec.size||point[0]!==4)throw Error();pub.end();
   let hex=d.toString(16).padStart(spec.size*2,'0');if(hex.length>spec.size*2||d===0n)throw Error();
   key=createPrivateKey({key:tlv(0x30,Buffer.concat([integer(1n),tlv(4,Buffer.from(hex,'hex')),tlv(0xa0,Buffer.from(spec.oid,'hex'))])),format:'der',type:'sec1'});
   if(!createPublicKey(key).export({format:'der',type:'spki'}).subarray(-point.length).equals(point))throw Error();
  }else return {status:'encrypted_or_unsupported_envelope'};
  priv.bytes(); // comment is untrusted, transient data, never emitted.
  const padding=privateBlob.subarray(priv.offset);if(padding.length>8||padding.some((b,i)=>b!==i+1))throw Error();
  return {key};
 }catch{return {status:'invalid_or_unsupported'};}
}
