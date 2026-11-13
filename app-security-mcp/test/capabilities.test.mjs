import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Client} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
for(const mode of ['missing-tools','missing-python','configured-rea'])test('capability discovery: '+mode,{timeout:15000},async()=>{
 const c=new Client({name:'capabilities-test',version:'1'});
 const marker='private-config-marker-never-return';
 const env={...process.env,APP_SECURITY_AAPT2:'',APP_SECURITY_DEXDUMP:'',APP_SECURITY_REA_COMMAND:mode==='configured-rea'?marker:'',APP_SECURITY_REA_ARGS:JSON.stringify([marker])};
 if(mode==='missing-python')env.APP_SECURITY_PYTHON='/nonexistent/app-security-python';
 await c.connect(new StdioClientTransport({command:process.execPath,args:[process.env.TEST_MCP_ENTRY??new URL('../dist/index.js',import.meta.url).pathname],env,stderr:'ignore'}));
 try{
  for(const platform of ['android','ios']){
   const r=await c.callTool({name:'get_analysis_capabilities',arguments:{platform}});assert.ok(!r.isError);const v=r.structuredContent;
   assert.equal(v.platform,platform);assert.equal(v.profiles['static-deep'].implemented,true);assert.equal(v.profiles['static-deep'].fallback_profile,'static-basic');
   assert.equal(v.dependencies.rea.execution_verified,false);assert.equal(v.dependencies.rea.status,mode==='configured-rea'?'configured_not_verified':'missing_or_invalid');
   assert.ok(!JSON.stringify(r).includes(marker));
   if(mode==='missing-python')assert.equal(v.dependencies.python.execution_verified,false);
   else {assert.equal(v.dependencies.python.status,'available');assert.match(v.dependencies.python.version,/^\d+\.\d+\.\d+$/);}
   if(platform==='android'){assert.equal(v.dependencies.aapt2.status,mode==='missing-python'?'unknown':'missing');assert.equal(v.dependencies.dexdump.execution_verified,false);}
   else {assert.equal(v.dependencies.aapt2,undefined);assert.equal(v.limits.ios_decode_attempt_limit.max,20000);}
  }
  const bad=await c.callTool({name:'get_analysis_capabilities',arguments:{platform:'invalid'}});assert.ok(bad.isError);
 }finally{await c.close();}
});
