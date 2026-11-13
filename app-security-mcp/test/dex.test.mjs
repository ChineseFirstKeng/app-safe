import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {execFileSync} from 'node:child_process';
import {Client} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
const dexdump=execFileSync('python3',['-c','import sys;sys.path.insert(0,"workers");from android_dex import find_dexdump;print(find_dexdump() or "")'],{encoding:'utf8'}).trim();
const javaHome=process.env.TEST_JAVA_HOME||'/Applications/Android Studio.app/Contents/jbr/Contents/Home';
const androidJar=process.env.TEST_ANDROID_JAR||'/Users/h1610/Library/Android/sdk/platforms/android-36/android.jar';
const d8=dexdump?join(dirname(dexdump),'d8'):'';

test('DEX MCP: real compilation, multidex, fields, concat, arrays, usage, conservative branches and redaction',{timeout:60000,skip:!existsSync(join(javaHome,'bin/javac'))||!existsSync(d8)||!existsSync(androidJar)?'JDK and Android SDK d8/dexdump required':false},async t=>{
 const root=await mkdtemp(join(tmpdir(),'app-security-dex-test-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const source=`public class DexFixture {
 public static final String password="fixture-static-password-123";
 public static final String client_id="public-client-id";
 public static String client_secret;
 public static void checkPassword(String input){if("fixture-fixed-auth-code".equals(input))field();}
 public static void verifyPin(String input){if(input.equals("fixture-fixed-pin-code"))field();}
 public static void checkTheme(String input){if("fixture-theme-name".equals(input))field();}
 public static void verifyOtp(boolean enabled,String input){if(!enabled)return;if("fixture-fixed-otp".equals(input))field();}
 public static void verifyPasscode(String input){boolean ok="fixture-fixed-passcode".equals(input);ok=input.isEmpty();if(ok)field();}
 public static boolean validatePassword(String input){return "fixture-return-only".equals(input);}
 public static void field(){client_secret="fixture-field-secret-456";}
 public static String zSecret(){return "synthetic-method-secret";}
 public static String zKey(){return "0123456789abcdef";}
 public static String zSecret(String input){return input;}
 public static String zBranch(boolean b){return b?"synthetic-branch-a":"synthetic-branch-b";}
 public static String zWrapper(){return zSecret();}
 public static String zWrapper2(){return zWrapper();}
 public static String zWrapper3(){return zWrapper2();}
 public static String zWrapper4(){return zWrapper3();}
 public static String zWrapper5(){return zWrapper4();}
 public static String zCycle(){return zCycleOther();}
 public static String zCycleOther(){return zCycle();}
 public static String zExtra(){field();return zSecret();}
 public static void methodWrapper4(){client_secret=zWrapper4();}
 public static void methodTooDeep(){client_secret=zWrapper5();}
 public static void methodCycle(){client_secret=zCycle();}
 public static void methodExtra(){client_secret=zExtra();}
 public String zInstance(){return "synthetic-instance";}
 public static String zEncoded(){return "MDEyMzQ1Njc4OWFiY2RlZg==";}
 public static String zEncodedWrapper(){return zEncoded();}
 public static void methodUtf8Key(){new javax.crypto.spec.SecretKeySpec(zKey().getBytes(java.nio.charset.StandardCharsets.UTF_8),"AES");}
 public static void methodNamedKey() throws Exception {new javax.crypto.spec.SecretKeySpec(zKey().getBytes("UTF-8"),"AES");}
 public static void methodBase64Key(){new javax.crypto.spec.SecretKeySpec(java.util.Base64.getDecoder().decode(zEncodedWrapper()),"AES");}
 public static void methodAndroidBase64Key(){new javax.crypto.spec.SecretKeySpec(android.util.Base64.decode(zEncoded(),0),"AES");}
 public static void methodBase64Iv(){new javax.crypto.spec.IvParameterSpec(java.util.Base64.getDecoder().decode(zEncoded()));}
 public static void methodOtherCharset(){new javax.crypto.spec.SecretKeySpec(zKey().getBytes(java.nio.charset.StandardCharsets.UTF_16),"AES");}
 public static void methodOtherFlags(){new javax.crypto.spec.SecretKeySpec(android.util.Base64.decode(zEncoded(),8),"AES");}
 public static void doubleDecode(){String text=new String(java.util.Base64.getDecoder().decode("TURFeU16UTFOamM0T1dGaVkyUmxaZz09"),java.nio.charset.StandardCharsets.UTF_8);new javax.crypto.spec.SecretKeySpec(java.util.Base64.getDecoder().decode(text),"AES");}
 public static void methodField(){client_secret=zSecret();}
 public static void methodKey(){new javax.crypto.spec.SecretKeySpec(zKey().getBytes(),"AES");}
 public static void methodOverload(String input){client_secret=zSecret(input);}
 public static void methodBranch(boolean b){client_secret=zBranch(b);}
 public static void methodWrapper(){client_secret=zWrapper();}
 public static void methodInstance(DexFixture obj){client_secret=obj.zInstance();}
 public static void restoredField(){client_secret=new String(java.util.Base64.getDecoder().decode("c3ludGhldGljLXJlc3RvcmVkLXNlY3JldA=="),java.nio.charset.StandardCharsets.UTF_8);}
 public static String restoredNamed() throws Exception {return new String(java.util.Base64.getDecoder().decode("YWNjZXNzX3Rva2VuPXN5bnRoZXRpYy10b2tlbg=="),"UTF-8");}
 public static String restoredSlice(){return new String(java.util.Base64.getDecoder().decode("eHBhc3N3b3JkPXN5bnRoZXRpYy1zbGljZS15"),1,25,java.nio.charset.StandardCharsets.UTF_8);}
 public static void restoredUnknown(byte[] input){client_secret=new String(input,java.nio.charset.StandardCharsets.UTF_8);}
 public static void restoredOther(){client_secret=new String(new byte[]{65,66,67},java.nio.charset.StandardCharsets.UTF_16);}
 public static void restoredBad(){client_secret=new String(new byte[]{(byte)255},java.nio.charset.StandardCharsets.UTF_8);}
 public static void restoredBounds(){client_secret=new String(new byte[]{65,66},1,2,java.nio.charset.StandardCharsets.UTF_8);}
 public static void restoredUnknownCharset(java.nio.charset.Charset c){client_secret=new String(new byte[]{65,66,67},c);}
 public static void copiedKey(){new javax.crypto.spec.SecretKeySpec(java.util.Arrays.copyOf(new byte[]{1,2,3,4},16),"AES");}
 public static void copiedRangeKey(){new javax.crypto.spec.SecretKeySpec(java.util.Arrays.copyOfRange(new byte[]{1,2,3,4},1,3),"AES");}
 public static void copiedEncodedKey(){new javax.crypto.spec.SecretKeySpec(java.util.Arrays.copyOf(java.util.Base64.getDecoder().decode("MDEyMzQ1Njc4OWFiY2RlZg=="),16),"AES");}
 public static void copiedIv(){new javax.crypto.spec.IvParameterSpec(java.util.Arrays.copyOfRange(new byte[]{1,2,3,4},4,20));}
 public static void copyUnknown(byte[] input){new javax.crypto.spec.SecretKeySpec(java.util.Arrays.copyOf(input,16),"AES");}
 public static void copyUnknownLength(int count){new javax.crypto.spec.SecretKeySpec(java.util.Arrays.copyOf(new byte[]{1,2},count),"AES");}
 public static void copyNegative(){new javax.crypto.spec.SecretKeySpec(java.util.Arrays.copyOf(new byte[]{1,2},-1),"AES");}
 public static void copyInvalidFrom(){new javax.crypto.spec.SecretKeySpec(java.util.Arrays.copyOfRange(new byte[]{1,2},3,16),"AES");}
 public static void copyReverse(){new javax.crypto.spec.SecretKeySpec(java.util.Arrays.copyOfRange(new byte[]{1,2},2,1),"AES");}
 public static void copyEmpty(){new javax.crypto.spec.SecretKeySpec(java.util.Arrays.copyOf(new byte[]{1,2},0),"AES");}
 public static void copyTooLarge(){new javax.crypto.spec.SecretKeySpec(java.util.Arrays.copyOf(new byte[]{1,2},8193),"AES");}
 public static void utf8Named() throws Exception {new javax.crypto.spec.SecretKeySpec("0123456789abcdef".getBytes("UTF-8"),"AES");}
 public static void utf8Standard(){new javax.crypto.spec.SecretKeySpec("0123456789abcdef".getBytes(java.nio.charset.StandardCharsets.UTF_8),"AES");}
 public static void utf8Lookup(){new javax.crypto.spec.SecretKeySpec("0123456789abcdef".getBytes(java.nio.charset.Charset.forName("utf8")),"AES");}
 public static void utf8Iv(){new javax.crypto.spec.IvParameterSpec("中文1234567890".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
 public static void otherCharset(){new javax.crypto.spec.SecretKeySpec("0123456789abcdef".getBytes(java.nio.charset.StandardCharsets.UTF_16),"AES");}
 public static void unknownCharset(java.nio.charset.Charset c){new javax.crypto.spec.SecretKeySpec("0123456789abcdef".getBytes(c),"AES");}
 public static void unknownCharsetName(String name) throws Exception {new javax.crypto.spec.SecretKeySpec("0123456789abcdef".getBytes(name),"AES");}
 public static void unknownUtf8Input(String input){new javax.crypto.spec.SecretKeySpec(input.getBytes(java.nio.charset.StandardCharsets.UTF_8),"AES");}
 public static void nullCharset() throws Exception {new javax.crypto.spec.SecretKeySpec("0123456789abcdef".getBytes((String)null),"AES");}
 public static void otherLookup(){new javax.crypto.spec.SecretKeySpec("0123456789abcdef".getBytes(java.nio.charset.Charset.forName("UTF-16")),"AES");}
 public static void encodedKey(){new javax.crypto.spec.SecretKeySpec(java.util.Base64.getDecoder().decode("MDEyMzQ1Njc4OWFiY2RlZg=="),"AES");}
 public static void androidEncodedKey(){new javax.crypto.spec.SecretKeySpec(android.util.Base64.decode("MDEyMzQ1Njc4OWFiY2RlZg==",0),"AES");}
 public static void androidNoWrapKey(){new javax.crypto.spec.SecretKeySpec(android.util.Base64.decode("MDEyMzQ1Njc4OWFiY2RlZg==",2),"AES");}
 public static void unsupportedFlags(){new javax.crypto.spec.SecretKeySpec(android.util.Base64.decode("MDEyMzQ1Njc4OWFiY2RlZg==",8),"AES");}
 public static void encodedIv(){new javax.crypto.spec.IvParameterSpec(java.util.Base64.getDecoder().decode("MDEyMzQ1Njc4OWFiY2RlZg=="));}
 public static byte[] encodedToken(){return java.util.Base64.getDecoder().decode("YWNjZXNzX3Rva2VuPWZpeHR1cmUtZW5jb2RlZC10b2tlbg==");}
 public static void externalEncodedKey(String encoded){new javax.crypto.spec.SecretKeySpec(java.util.Base64.getDecoder().decode(encoded),"AES");}
 public static void invalidEncodedKey(){new javax.crypto.spec.SecretKeySpec(java.util.Base64.getDecoder().decode("not%%%base64"),"AES");}
 public static void unknownFlags(String input,int flags){new javax.crypto.spec.SecretKeySpec(android.util.Base64.decode(input,flags),"AES");}
 public static void unsupportedDecoder(){new javax.crypto.spec.SecretKeySpec(java.util.Base64.getUrlDecoder().decode("MDEyMzQ1Njc4OWFiY2RlZg=="),"AES");}
 public static void key(){new javax.crypto.spec.SecretKeySpec("fixture-key-12345".getBytes(),"AES");}
 public static void array(){new javax.crypto.spec.SecretKeySpec(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16},"AES");}
 public static void iv(){new javax.crypto.spec.IvParameterSpec(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16});}
 public static void keySlice(){new javax.crypto.spec.SecretKeySpec(new byte[]{1,2,3,4,5,6},1,4,"AES");}
 public static void keyEmpty(){new javax.crypto.spec.SecretKeySpec(new byte[]{},"AES");}
 public static void keyBounds(){new javax.crypto.spec.SecretKeySpec(new byte[]{1,2,3},2,2,"AES");}
 public static void keyNegative(){new javax.crypto.spec.SecretKeySpec(new byte[]{1,2,3},-1,2,"AES");}
 public static void keyZero(){new javax.crypto.spec.SecretKeySpec(new byte[]{1,2,3},0,0,"AES");}
 public static void keyUnknown(int start){new javax.crypto.spec.SecretKeySpec(new byte[]{1,2,3},start,2,"AES");}
 public static void keyInput(byte[] input){new javax.crypto.spec.SecretKeySpec(input,"AES");}
 public static void keyEncodedSlice(){new javax.crypto.spec.SecretKeySpec(java.util.Base64.getDecoder().decode("MDEyMzQ1Njc4OWFiY2RlZg=="),1,4,"AES");}
 public static void ivSlice(){new javax.crypto.spec.IvParameterSpec(new byte[]{1,2,3,4,5,6},1,4);}
 public static void ivEmpty(){new javax.crypto.spec.IvParameterSpec(new byte[]{});}
 public static void ivBounds(){new javax.crypto.spec.IvParameterSpec(new byte[]{1,2,3},2,2);}
 public static void ivNegative(){new javax.crypto.spec.IvParameterSpec(new byte[]{1,2,3},-1,2);}
 public static void ivZero(){new javax.crypto.spec.IvParameterSpec(new byte[]{1,2,3},0,0);}
 public static void ivUnknown(int start){new javax.crypto.spec.IvParameterSpec(new byte[]{1,2,3},start,2);}
 public static void ivInput(byte[] input){new javax.crypto.spec.IvParameterSpec(input);}
 public static void ivEncodedSlice(){new javax.crypto.spec.IvParameterSpec(java.util.Base64.getDecoder().decode("MDEyMzQ1Njc4OWFiY2RlZg=="),1,4);}
 public static void keyNullAlgorithm(){new javax.crypto.spec.SecretKeySpec(new byte[]{1,2,3},null);}
 public static void keyUnknownAlgorithm(String algorithm){new javax.crypto.spec.SecretKeySpec(new byte[]{1,2,3},algorithm);}
 public static void gcm(){new javax.crypto.spec.GCMParameterSpec(128,new byte[]{1,2,3,4,5,6,7,8,9,10,11,12});}
 public static void gcmSlice(){new javax.crypto.spec.GCMParameterSpec(96,new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14},2,12);}
 public static void gcmEncoded(){new javax.crypto.spec.GCMParameterSpec(128,java.util.Base64.getDecoder().decode("MDEyMzQ1Njc4OWFi"));}
 public static void gcmInput(byte[] nonce){new javax.crypto.spec.GCMParameterSpec(128,nonce);}
 public static void gcmTag(int tag){new javax.crypto.spec.GCMParameterSpec(tag,new byte[]{1,2,3});}
 public static void gcmNegative(){new javax.crypto.spec.GCMParameterSpec(-1,new byte[]{1,2,3});}
 public static void gcmBounds(){new javax.crypto.spec.GCMParameterSpec(128,new byte[]{1,2,3},2,2);}
 public static void gcmOffset(){new javax.crypto.spec.GCMParameterSpec(128,new byte[]{1,2,3},-1,2);}
 public static void gcmEmpty(){new javax.crypto.spec.GCMParameterSpec(128,new byte[]{});}
 public static void gcmBranch(boolean b,byte[] supplied){byte[] nonce=new byte[]{1,2,3};if(b)nonce=supplied;new javax.crypto.spec.GCMParameterSpec(128,nonce);}
 public static void gcmRandom(){byte[] nonce=new byte[12];new java.security.SecureRandom().nextBytes(nonce);new javax.crypto.spec.GCMParameterSpec(128,nonce);}
 public static String concat(){return new StringBuilder().append("Bearer ").append("fixture-concat-token-789").toString();}
 public static void branch(boolean b,String input){String k="fixture-branch-key";if(b)k=input;new javax.crypto.spec.SecretKeySpec(k.getBytes(),"AES");}
 public static void overwrite(String input){String k="fixture-unused-key";k=input;new javax.crypto.spec.SecretKeySpec(k.getBytes(),"AES");}
 public static void salt(char[] password){new javax.crypto.spec.PBEKeySpec(password,new byte[]{1,2,3,4,5,6,7,8},120000,256);}
 public static void saltHigh(char[] password){new javax.crypto.spec.PBEKeySpec(password,new byte[]{1,2,3,4,5,6,7,8},131072,256);}
 public static void salt3(char[] password){new javax.crypto.spec.PBEKeySpec(password,new byte[]{1,2,3,4,5,6,7,8},120000);}
 public static void inputSalt(char[] password,byte[] salt){new javax.crypto.spec.PBEKeySpec(password,salt,120000,256);}
 public static void invalidSalt(char[] password){new javax.crypto.spec.PBEKeySpec(password,new byte[]{1,2,3},0,256);}
 public static void negativeSalt(char[] password){new javax.crypto.spec.PBEKeySpec(password,new byte[]{1,2,3},-120000,256);}
 public static void unknownIterations(char[] password,int count){new javax.crypto.spec.PBEKeySpec(password,new byte[]{1,2,3},count,256);}
 public static void emptySalt(char[] password){new javax.crypto.spec.PBEKeySpec(password,new byte[]{},120000,256);}
 public static void branchSalt(char[] password,boolean b,byte[] supplied){byte[] salt=new byte[]{1,2,3};if(b)salt=supplied;new javax.crypto.spec.PBEKeySpec(password,salt,120000,256);}
 public static void noSalt(char[] password){new javax.crypto.spec.PBEKeySpec(password);}
 public static String multiline(){return "password=fixture-line-secret\\nclient_secret=fixture-second-line-secret";}
}`;
 await writeFile(join(root,'DexFixture.java'),source);
 await writeFile(join(root,'OtherFixture.java'),'public class OtherFixture {public static final String access_token="fixture-second-dex-token";}');
 execFileSync(join(javaHome,'bin/javac'),['--release','8','-classpath',androidJar,join(root,'DexFixture.java'),join(root,'OtherFixture.java')]);
 for(const [dir,klass] of [['one','DexFixture'],['two','OtherFixture']]){await mkdir(join(root,dir));execFileSync(d8,['--output',join(root,dir),join(root,klass+'.class')],{env:{...process.env,JAVA_HOME:javaHome}});}
 execFileSync('python3',['-c',`import zipfile,sys,pathlib
p=pathlib.Path(sys.argv[1])
with zipfile.ZipFile(p/'fixture.apk','w') as z:
 z.writestr('AndroidManifest.xml',b'fixture')
 z.writestr('classes.dex',(p/'one/classes.dex').read_bytes())
 z.writestr('classes2.dex',(p/'two/classes.dex').read_bytes())
with zipfile.ZipFile(p/'broken.apk','w') as z:
 z.writestr('AndroidManifest.xml',b'fixture')
 z.writestr('classes.dex',b'dex\\n035\\0broken')
`,root]);
 for(const missing of [false,true]){
 const client=new Client({name:'dex-test',version:'1'});
 await client.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env:{...process.env,APP_SECURITY_REA_COMMAND:'',APP_SECURITY_DATA_DIR:join(root,missing?'missing':'store'),APP_SECURITY_DEXDUMP:missing?join(root,'absent'):dexdump},stderr:'pipe'}));
 try{
 const call=async(name,args)=>{const r=await client.callTool({name,arguments:args});assert.ok(!r.isError,JSON.stringify(r));return r.structuredContent;};
 const scan=async path=>{const imp=await call('import_local_artifact',{path});const task=await call('scan_android_hardcoding',{artifact_id:imp.artifact_id});for(let i=0;i<200;i++){const r=await call('get_scan_status',{scan_id:task.scan_id});if(!['running','queued'].includes(r.state))return r;await new Promise(r=>setTimeout(r,20));}assert.fail('timeout');};
 const status=await scan(join(root,'fixture.apk'));assert.equal(status.state,'partial');
 assert.equal(status.dex_scan.files_total,2);
 if(missing){assert.equal(status.dex_scan.files_checked,0);assert.equal(status.dex_scan.failures.dex_decoder_unavailable,2);continue;}
 assert.equal(status.dex_scan.files_checked,2);assert.deepEqual(status.dex_scan.failures,{});assert.equal(status.dex_scan.classes_checked,2);
 assert.ok(status.dex_scan.methods_without_flow>0);
 assert.ok(status.client_identifier_review.items.some(i=>i.classification==='client_identifier'&&i.evidence.usage==='static_field_value'&&i.evidence.field_category==='clientid'));
 const {findings}=await call('list_findings',{scan_id:status.scan_id,limit:100});
 assert.ok(findings.some(f=>f.rule_id==='HC-003'&&f.evidence.usage==='constant_field_assignment'));
 assert.ok(findings.some(f=>f.rule_id==='HC-001'&&f.evidence.usage==='static_field_value'));
 assert.ok(findings.some(f=>f.rule_id==='HC-002'&&f.evidence.usage==='constant_string_builder'));
 assert.ok(findings.some(f=>f.rule_id==='HC-002'&&f.evidence.path==='classes2.dex'));
 const guards=findings.filter(f=>f.rule_id==='HC-009');assert.deepEqual(guards.map(f=>f.evidence.method).sort(),['checkPassword','verifyPin']);assert.ok(guards.every(f=>f.evidence.comparison_result_controls_branch===true&&f.evidence.security_purpose==='unknown'&&Number.isInteger(f.evidence.comparison_file_offset)));
 const salts=findings.filter(f=>f.rule_id==='HC-008');assert.deepEqual(salts.map(f=>f.evidence.method).sort(),['salt','salt3','saltHigh']);assert.ok(salts.every(f=>f.evidence.salt_length===8&&f.evidence.iteration_count===(f.evidence.method==='saltHigh'?131072:120000)&&f.severity==='needs_review'));assert.equal(status.rules.find(r=>r.rule_id==='HC-008').status,'partial');
 assert.ok(status.dex_scan.constant_decode_recovered>=5);assert.ok(status.dex_scan.constant_decode_unresolved>=5);
 assert.ok(findings.some(f=>f.rule_id==='HC-002'&&f.evidence.usage==='constant_base64_decode'));
 assert.ok(findings.some(f=>f.rule_id==='HC-005'&&f.evidence.method==='encodedKey'&&f.evidence.transform==='base64_java_basic_one_layer'&&Number.isInteger(f.evidence.decode_file_offset)));
 const keys=findings.filter(f=>f.rule_id==='HC-005');assert.deepEqual(keys.map(f=>f.evidence.method).sort(),['androidEncodedKey','androidNoWrapKey','array','copiedEncodedKey','copiedKey','copiedRangeKey','encodedKey','key','keyEncodedSlice','keySlice','methodAndroidBase64Key','methodBase64Key','methodKey','methodNamedKey','methodUtf8Key','utf8Lookup','utf8Named','utf8Standard']);
 assert.ok(findings.some(f=>f.rule_id==='HC-007'&&f.evidence.method==='iv'));
 const ivs=findings.filter(f=>f.evidence.usage==='constant_to_IvParameterSpec');assert.deepEqual(ivs.map(f=>f.evidence.method).sort(),['copiedIv','encodedIv','iv','ivEncodedSlice','ivSlice','methodBase64Iv','utf8Iv']);
 for(const method of ['keySlice','ivSlice','keyEncodedSlice','ivEncodedSlice']){const f=findings.find(f=>f.evidence.method===method&&['HC-005','HC-007'].includes(f.rule_id));assert.equal(f.evidence.source_array_offset,1);assert.equal(f.evidence.material_length,4);assert.equal(f.evidence.provider_acceptance,'unknown');assert.equal(f.evidence.source_array_length,method.includes('Encoded')?16:6);if(method.includes('Encoded'))assert.equal(f.evidence.transform,'base64_java_basic_one_layer');}
 for(const method of ['utf8Named','utf8Standard','utf8Lookup','utf8Iv']){const f=findings.find(f=>f.evidence.method===method&&['HC-005','HC-007'].includes(f.rule_id));assert.equal(f.evidence.transform,'string_getbytes_utf8');assert.equal(f.evidence.material_length,16);assert.equal(f.evidence.encoded_length,16);assert.ok(Number.isInteger(f.evidence.encode_file_offset));}
 for(const [method,length,padding] of [['copiedKey',16,12],['copiedRangeKey',2,0],['copiedEncodedKey',16,0],['copiedIv',16,16]]){const f=findings.find(f=>f.evidence.method===method&&['HC-005','HC-007'].includes(f.rule_id));assert.equal(f.evidence.material_length,length);assert.equal(f.evidence.array_copy_steps[0].zero_padding_length,padding);assert.ok(Number.isInteger(f.evidence.array_copy_steps[0].file_offset));}
 assert.equal(findings.find(f=>f.evidence.method==='copiedEncodedKey'&&f.rule_id==='HC-005').evidence.transform,'base64_java_basic_one_layer');
 const restored=findings.filter(f=>f.evidence.usage==='constant_utf8_string_constructor');assert.deepEqual([...new Set(restored.map(f=>f.evidence.method))].sort(),['restoredNamed','restoredSlice']);
 const restoredField=findings.find(f=>f.evidence.method==='restoredField'&&f.evidence.usage==='constant_field_assignment');assert.ok(restoredField);assert.equal(restoredField.rule_id,'HC-003');assert.equal(restoredField.evidence.transform,'base64_java_basic_one_layer');assert.ok(Number.isInteger(restoredField.evidence.string_constructor_file_offset));
 assert.ok(!findings.some(f=>['restoredUnknown','restoredOther','restoredBad','restoredBounds','restoredUnknownCharset'].includes(f.evidence.method)&&f.evidence.usage==='constant_field_assignment'));
 const methodField=findings.find(f=>f.evidence.method==='methodField'&&f.evidence.usage==='constant_field_assignment');assert.ok(methodField);assert.equal(methodField.rule_id,'HC-003');assert.equal(methodField.evidence.callee_method,'zSecret');assert.equal(methodField.evidence.transform,'static_constant_string_return');assert.ok(Number.isInteger(methodField.evidence.caller_invoke_file_offset));
 const methodKey=findings.find(f=>f.evidence.method==='methodKey'&&f.rule_id==='HC-005');assert.equal(methodKey.evidence.callee_method,'zKey');assert.equal(methodKey.evidence.material_length,16);
 assert.ok(!findings.some(f=>['methodOverload','methodBranch','methodInstance','methodTooDeep','methodCycle','methodExtra'].includes(f.evidence.method)&&f.evidence.usage==='constant_field_assignment'));
 assert.ok(status.dex_scan.constant_method_summaries>=2);assert.ok(status.dex_scan.constant_method_returns_propagated>=2);
 for(const [method,depth] of [['methodWrapper',1],['methodWrapper4',4]]){const f=findings.find(f=>f.evidence.method===method&&f.evidence.usage==='constant_field_assignment');assert.ok(f);assert.equal(f.evidence.wrapper_depth,depth);assert.equal(f.evidence.return_chain.length,depth+1);assert.equal(f.evidence.return_chain.at(-1).callee_method,'zSecret');assert.ok(f.evidence.return_chain.slice(0,-1).every(x=>Number.isInteger(x.callee_invoke_file_offset)));}
 assert.ok(status.dex_scan.constant_method_summaries_unresolved>=3);
 for(const [method,transform,depth] of [['methodUtf8Key','string_getbytes_utf8',0],['methodNamedKey','string_getbytes_utf8',0],['methodBase64Key','base64_java_basic_one_layer',1],['methodAndroidBase64Key','base64_android_one_layer',0],['methodBase64Iv','base64_java_basic_one_layer',0]]){const f=findings.find(f=>f.evidence.method===method&&['HC-005','HC-007'].includes(f.rule_id));assert.equal(f.evidence.transform,transform);assert.equal(f.evidence.wrapper_depth,depth);assert.ok(Number.isInteger(f.evidence.caller_invoke_file_offset));assert.equal(f.evidence.material_length,16);assert.ok(f.evidence.return_chain.length>0);}
 assert.ok(!findings.some(f=>['methodOtherCharset','methodOtherFlags','doubleDecode'].includes(f.evidence.method)&&f.rule_id==='HC-005'));
 const nonces=findings.filter(f=>f.evidence.usage==='constant_nonce_to_GCMParameterSpec');assert.deepEqual(nonces.map(f=>f.evidence.method).sort(),['gcm','gcmEncoded','gcmSlice']);
 assert.ok(nonces.every(f=>f.rule_id==='HC-007'&&f.evidence.nonce_length===12&&f.evidence.encryption_use==='unknown'&&f.evidence.same_key_nonce_reuse==='unknown'&&f.title.includes('GCMParameterSpec')));
 const slice=nonces.find(f=>f.evidence.method==='gcmSlice');assert.equal(slice.evidence.source_array_offset,2);assert.equal(slice.evidence.source_array_length,14);assert.equal(slice.evidence.tag_length_bits,96);
 assert.equal(nonces.find(f=>f.evidence.method==='gcmEncoded').evidence.transform,'base64_java_basic_one_layer');
 assert.ok(findings.every(f=>f.value==='[REDACTED]'&&f.verification_level==='candidate'));
 const unavailable=await call('verify_android_finding',{scan_id:status.scan_id,finding_id:keys[0].finding_id});assert.equal(unavailable.status,'blocked');assert.equal(unavailable.reason,'rea_command_not_configured');
 const one=await call('get_finding',{scan_id:status.scan_id,finding_id:keys[0].finding_id});assert.ok(Number.isInteger(one.evidence.dex_code_unit_offset));assert.ok(one.evidence.member_sha256);
 for(const format of ['json','markdown']){const report=await call('export_report',{scan_id:status.scan_id,format});const text=await readFile(report.path,'utf8');assert.ok(!text.includes('fixture-')&&!text.includes('public-client-id')&&!text.includes('synthetic-method-secret')&&!text.includes('synthetic-restored-secret')&&!text.includes('synthetic-token')&&!text.includes('synthetic-slice'));}
 const rawExport=await call('export_report',{scan_id:status.scan_id,format:'json',include_sensitive_values:true});
 const rawReport=JSON.parse(await readFile(rawExport.path,'utf8'));
 const rawFinding=(method,rule)=>rawReport.findings.find(f=>f.evidence.method===method&&f.rule_id===rule);
 for(const [method,rule,expected] of [['array','HC-005','0102030405060708090a0b0c0d0e0f10'],['keySlice','HC-005','02030405'],['ivSlice','HC-007','02030405'],['keyEncodedSlice','HC-005','31323334'],['gcmSlice','HC-007','030405060708090a0b0c0d0e'],['salt','HC-008','0102030405060708'],['methodUtf8Key','HC-005',Buffer.from('0123456789abcdef').toString('hex')]]){const f=rawFinding(method,rule);assert.equal(f.value,expected);assert.equal(f.value_encoding,'hex');}
 assert.equal(rawFinding('checkPassword','HC-009').value,'fixture-fixed-auth-code');
 assert.equal(rawFinding('verifyPin','HC-009').value,'fixture-fixed-pin-code');
 const broken=await scan(join(root,'broken.apk'));assert.equal(broken.state,'partial');assert.equal(broken.dex_scan.files_checked,0);assert.equal(broken.dex_scan.failures.dex_format_unsupported,1);
 }finally{await client.close();}
 }
});
