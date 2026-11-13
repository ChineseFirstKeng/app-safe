import {mkdtemp,mkdir,readFile,writeFile,rm,cp,realpath} from 'node:fs/promises';
import {join} from 'node:path';import {tmpdir} from 'node:os';import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';import assert from 'node:assert/strict';
import {Client} from '@modelcontextprotocol/client';import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
const root=fileURLToPath(new URL('..',import.meta.url));const temp=await mkdtemp(join(tmpdir(),'app-security-claude-'));let client;
const env={PATH:process.env.PATH,HOME:temp,TMPDIR:process.env.TMPDIR??tmpdir(),CLAUDE_CONFIG_DIR:join(temp,'config'),CLAUDE_CODE_PLUGIN_CACHE_DIR:join(temp,'plugins')};
const run=(args)=>execFileSync('claude',args,{cwd:temp,env,encoding:'utf8',timeout:30000,stdio:['ignore','pipe','pipe']});
try{
 const market=join(temp,'market');await cp(join(root,'artifacts/plugin-marketplace'),market,{recursive:true});
 run(['plugin','validate',join(market,'plugins/app-security')]);run(['plugin','validate',market]);
 run(['plugin','marketplace','add',market]);const installed=JSON.parse(run(['plugin','install','app-security@app-security-local','--json']));
 // CLI output varies by version; the persisted registry is the installation authority.
 const registry=JSON.parse(await readFile(join(temp,'plugins','installed_plugins.json'),'utf8'));
 const entries=registry.plugins['app-security@app-security-local'];assert.ok(entries?.length);
 const path=await realpath(entries[0].installPath);assert.ok(path.startsWith((await realpath(temp))+'/'));
 const manifest=JSON.parse(await readFile(join(path,'.claude-plugin/plugin.json'),'utf8'));
 assert.equal(manifest.name,'app-security');const details=run(['plugin','details','app-security@app-security-local']);
 assert.match(details,/Skills \(3\)\s+android-check-hardcoding, app-security, ios-check-hardcoding/);
 assert.match(details,/MCP servers \(1\)\s+app-security/);
 await rm(market,{recursive:true,force:true});
 const server=manifest.mcpServers['app-security'];const args=server.args.map(s=>s.replaceAll('${CLAUDE_PLUGIN_ROOT}',path));
 client=new Client({name:'claude-cache-check',version:'1'});await client.connect(new StdioClientTransport({command:server.command,args,env:{PATH:process.env.PATH,HOME:temp,APP_SECURITY_DATA_DIR:join(temp,'data')},stderr:'ignore'}));
 const tools=await client.listTools();assert.equal(tools.tools.length,23);const health=await client.callTool({name:'health_check',arguments:{}});assert.equal(health.structuredContent.status,'ok');
 const summary={passed:true,scope:'isolated_claude_configuration_on_existing_host',claude_version:run(['--version']).trim(),plugin_version:manifest.version,installation:true,component_inventory:true,tools:tools.tools.length,installed_bundle_handshake:true,model_skill_invocation:'not_tested'};
 await mkdir(join(root,'artifacts/validation'),{recursive:true});await writeFile(join(root,'artifacts/validation/claude-install-summary.json'),JSON.stringify(summary,null,2),{mode:0o600});console.log(JSON.stringify(summary));
}finally{if(client)await client.close();await rm(temp,{recursive:true,force:true});}
