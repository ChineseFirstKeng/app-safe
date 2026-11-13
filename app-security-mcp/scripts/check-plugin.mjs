import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
const child = spawn('codex', ['app-server', '--stdio'], { stdio: ['pipe', 'pipe', 'pipe'] });
child.stderr.on('data', data => { if (process.env.PLUGIN_CHECK_DEBUG) process.stderr.write(data); });
const pending = new Map(); let id = 0;
createInterface({ input: child.stdout }).on('line', line => {
  try {
    const m = JSON.parse(line), p = pending.get(m.id);
    if (p) { pending.delete(m.id); m.error ? p.reject(new Error(JSON.stringify(m.error))) : p.resolve(m.result); }
  } catch { /* Non-protocol line */ }
});
const request = (method, params) => new Promise((resolve, reject) => {
  const n = ++id; pending.set(n, { resolve, reject });
  child.stdin.write(JSON.stringify({ id: n, method, params }) + '\n');
});
const timer = setTimeout(() => { console.error('Plugin check timed out'); child.kill(); process.exitCode = 1; }, 30000);
try {
  await request('initialize', { clientInfo: { name: 'app-security-plugin-check', version: '1.0.0' }, capabilities: { experimentalApi: true } });
  child.stdin.write(JSON.stringify({ method: 'initialized' }) + '\n');
  const result = await request('skills/list', { cwds: [process.cwd()], forceReload: true });
  const skills = result.data.flatMap(group => group.skills).filter(s => s.name.includes('app-security'));
  console.log('Skills:', JSON.stringify(skills));
  assert.ok(skills.some(s => s.path.includes('/plugins/cache/app-security-local/') && s.enabled));
  for (const name of ['app-security:android:check-hardcoding', 'app-security:ios:check-hardcoding']) assert.ok(skills.some(s => s.name === name && s.enabled));
  const inventory = await request('mcpServerStatus/list', { serverName: 'app-security', detail: 'full' });
  const servers = inventory.data.filter(s => s.name.includes('app-security'));
  if (process.env.PLUGIN_CHECK_DEBUG) console.log(JSON.stringify(servers));
  console.log('MCP:', JSON.stringify(servers.map(s => ({ name: s.name, tools: Object.keys(s.tools) }))));
  assert.ok(servers.some(s => s.pluginId === 'app-security@app-security-local' && Object.keys(s.tools).length === 23));
  console.log('PASS: Codex discovers the installed plugin Skill and all twenty-three bundled MCP tools.');
} finally { clearTimeout(timer); child.kill(); }
