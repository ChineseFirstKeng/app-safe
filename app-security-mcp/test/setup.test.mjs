import assert from 'node:assert/strict';
import { test } from 'node:test';
import { once } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, writeFile, mkdir, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse, stringify } from 'smol-toml';
import { createHttpApp, readConfig } from '../dist/http.js';
import { renderConfig } from '../packages/connector/bin/setup.mjs';

const exec = promisify(execFile);
const cli = fileURLToPath(new URL('../packages/connector/bin/cli.mjs', import.meta.url));

test('config editing preserves unrelated values, comments and complex TOML strings', () => {
  const original = '# personal settings\nmodel="test"\n[mcp_servers.other]\ncommand="other"\n[mcp_servers.app-security]\nurl="https://old.example/mcp"\n[mcp_servers.app-security.http_headers]\nAuthorization="Bearer old"\n[features]\nflag=true\n';
  const entry = { url: 'https://new.example/mcp', http_headers: { Authorization: 'Bearer fixture' }, enabled: true };
  const rendered = renderConfig(original, entry);
  const next = parse(original);
  next.mcp_servers['app-security'] = entry;
  assert.deepEqual(parse(rendered.text), parse(stringify(next)));
  assert.ok(rendered.text.includes('# personal settings'));
  const complex = 'notes="""keep this text\n[mcp_servers.app-security]\ninside a string\n"""\nmcp_servers={other={command="other"}}\n';
  const output = renderConfig(complex, entry);
  const expected = parse(complex);
  expected.mcp_servers['app-security'] = entry;
  assert.deepEqual(parse(output.text), parse(stringify(expected)));
});

test('setup and doctor: fresh install, backup, repeat, failure and secret handling', { timeout: 30000 }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'app-security-setup-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const token = 'fixture-setup-token-0123456789-abcdef';
  const app = createHttpApp(readConfig({ MCP_AUTH_TOKEN: token, MCP_PUBLIC_URL: 'http://127.0.0.1/mcp' }));
  app.server.listen(0, '127.0.0.1');
  await once(app.server, 'listening');
  t.after(() => app.close());
  const url = `http://127.0.0.1:${app.server.address().port}/mcp`;
  const home = join(root, 'codex');
  const env = { ...process.env, CODEX_HOME: home, MCP_URL: url, MCP_AUTH_TOKEN: token };
  const run = (args, overrides = {}) => exec(process.execPath, [cli, ...args], { env: { ...env, ...overrides }, timeout: 20000 });

  const dry = await run(['setup', '--client', 'codex', '--dry-run']);
  assert.ok(!dry.stdout.includes(token));
  await assert.rejects(stat(home), { code: 'ENOENT' });

  await assert.rejects(run(['setup'], { MCP_AUTH_TOKEN: 'wrong-but-valid-length-token-0123456789' }), error => {
    assert.ok(!error.stderr.includes('wrong-but-valid'));
    return error.code === 1;
  });
  await assert.rejects(stat(home), { code: 'ENOENT' });

  await mkdir(join(home, 'skills', 'app-security'), { recursive: true });
  const original = '# preserve me\nmodel="fixture-model"\n[mcp_servers.other]\ncommand="other-mcp"\n';
  await writeFile(join(home, 'config.toml'), original);
  await writeFile(join(home, 'skills', 'app-security', 'SKILL.md'), 'old custom skill');
  const setup = await run(['setup', '--client', 'codex']);
  assert.ok(setup.stdout.includes('安装完成'));
  assert.ok(!setup.stdout.includes(token) && !setup.stderr.includes(token));
  const config = parse(await readFile(join(home, 'config.toml'), 'utf8'));
  assert.equal(config.model, 'fixture-model');
  assert.equal(config.mcp_servers.other.command, 'other-mcp');
  assert.equal(config.mcp_servers['app-security'].http_headers.Authorization, `Bearer ${token}`);
  if (process.platform !== 'win32') assert.equal((await stat(join(home, 'config.toml'))).mode & 0o777, 0o600);
  const backups = await readdir(join(home, 'backups', 'app-security'));
  assert.equal(backups.length, 1);
  assert.equal(await readFile(join(home, 'backups', 'app-security', backups[0], 'config.toml'), 'utf8'), original);
  assert.equal(await readFile(join(home, 'skills', 'app-security', 'SKILL.md'), 'utf8'), 'old custom skill');

  const installed = await readFile(join(home, 'config.toml'), 'utf8');
  const repeat = await run(['setup'], { MCP_AUTH_TOKEN: '' });
  assert.match(repeat.stdout, /无需重复安装/);
  assert.equal(await readFile(join(home, 'config.toml'), 'utf8'), installed);
  assert.equal((await readdir(join(home, 'backups', 'app-security'))).length, 1);
  await rm(join(home, 'skills'), { recursive: true });
  const doctor = await run(['doctor', '--client', 'codex'], { MCP_AUTH_TOKEN: '' });
  assert.match(doctor.stdout, /PASS/);
  await run(['setup']);
  await assert.rejects(stat(join(home, 'skills')), { code: 'ENOENT' });
  assert.ok(!doctor.stdout.includes(token));

  await assert.rejects(run(['setup', '--client', 'unsupported']));
  assert.equal(await readFile(join(home, 'config.toml'), 'utf8'), installed);
  await writeFile(join(home, 'config.toml'), 'broken = [');
  await assert.rejects(run(['setup']));
  assert.equal(await readFile(join(home, 'config.toml'), 'utf8'), 'broken = [');
});
