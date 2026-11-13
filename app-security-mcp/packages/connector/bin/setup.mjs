import { homedir } from 'node:os';
import { resolve, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { mkdir, readFile, writeFile, rename, rm, lstat, chmod } from 'node:fs/promises';
import { parse, stringify } from 'smol-toml';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

const DEFAULT_URL = 'https://www.hunluanshuihu.icu/mcp';
export class SetupError extends Error {}

function sameValues(a, b) {
  const normalize = value => {
    if (Array.isArray(value)) return value.map(normalize);
    if (value && typeof value === 'object' && [null, Object.prototype].includes(Object.getPrototypeOf(value))) {
      return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, normalize(item)]));
    }
    return value;
  };
  return isDeepStrictEqual(normalize(a), normalize(b));
}

export function parseOptions(args) {
  const result = { client: 'codex', dryRun: false };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--dry-run') result.dryRun = true;
    else if (['--client', '--url'].includes(arg) && args[i + 1] && !args[i + 1].startsWith('--')) {
      result[arg.slice(2)] = args[++i];
    } else throw new SetupError('参数无效。使用 --help 查看用法；token 请在隐藏输入提示或 MCP_AUTH_TOKEN 环境变量中提供。');
  }
  if (result.client !== 'codex') throw new SetupError('当前安装器仅支持 --client codex。');
  return result;
}

function validatedUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new SetupError('MCP URL 无效。'); }
  const local = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(local && url.protocol === 'http:')) || url.username || url.password || url.search || url.hash) {
    throw new SetupError('远程 MCP 地址必须使用 HTTPS，且不能含账号、密码、查询参数或片段。');
  }
  return url.href;
}

async function optionalRead(path) {
  try { return await readFile(path, 'utf8'); } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

async function assertPlainPath(path, directory = false) {
  try {
    const stat = await lstat(path);
    if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())) {
      throw new SetupError(`目标不是普通${directory ? '目录' : '文件'}，为避免覆盖链接已停止：${path}`);
    }
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
}

function readConfig(text) {
  try { return parse(text ?? ''); } catch {
    throw new SetupError('现有 config.toml 无法解析，未修改任何配置。请先修复 TOML 语法。');
  }
}

export function renderConfig(text, entry) {
  const expected = readConfig(text);
  if (expected.mcp_servers !== undefined && (typeof expected.mcp_servers !== 'object' || Array.isArray(expected.mcp_servers))) {
    throw new SetupError('config.toml 中 mcp_servers 类型不正确。');
  }
  expected.mcp_servers ??= {};
  expected.mcp_servers['app-security'] = entry;
  // 常规 TOML 仅替换本服务的 table，保留其他注释和排版。
  // 复杂写法若无法安全局部编辑，回退到保留完整配置值的 TOML 序列化。
  const headers = [...text.matchAll(/^[ \t]*\[.+\][ \t]*(?:#.*)?$/gm)];
  let candidate = '', last = 0;
  for (let i = 0; i < headers.length; i++) {
    const h = headers[i];
    let belongs = false;
    try { belongs = Object.hasOwn(parse(h[0]).mcp_servers ?? {}, 'app-security'); } catch { /* 非表头或字符串内部 */ }
    if (belongs) {
      candidate += text.slice(last, h.index);
      last = headers[i + 1]?.index ?? text.length;
    }
  }
  candidate += text.slice(last);
  candidate = candidate.trimEnd() + '\n\n' + stringify({ mcp_servers: { 'app-security': entry } });
  try { if (sameValues(parse(candidate), expected)) return { text: candidate, reformatted: false }; } catch { /* 使用已解析的数据 */ }
  const serialized = stringify(expected);
  if (!sameValues(parse(serialized), expected)) throw new SetupError('无法无损保存配置值，已停止。');
  return { text: serialized, reformatted: true };
}

function hiddenToken() {
  if (!process.stdin.isTTY || !process.stdin.setRawMode) {
    throw new SetupError('没有可交互终端，也没有可复用 token。请在终端运行，或通过 MCP_AUTH_TOKEN 环境变量提供 token。');
  }
  return new Promise((resolveToken, reject) => {
    let value = '';
    const wasRaw = process.stdin.isRaw;
    process.stdin.setRawMode(true);
    process.stdin.resume();
    const finish = (error) => {
      process.stdin.off('data', onData);
      process.stdin.setRawMode(Boolean(wasRaw));
      process.stdin.pause();
      process.stderr.write('\n');
      error ? reject(error) : resolveToken(value.trim());
    };
    const onData = chunk => {
      for (const char of chunk.toString('utf8')) {
        if (char === '\u0003' || char === '\u0004') { finish(new SetupError('已取消，配置未修改。')); return; }
        if (char === '\r' || char === '\n') { finish(); return; }
        if (char === '\u007f' || char === '\b') value = value.slice(0, -1);
        else if (/^[A-Za-z0-9_-]$/.test(char)) value += char;
      }
    };
    process.stdin.on('data', onData);
    process.stderr.write('请输入 MCP 固定 token（不回显）：');
  });
}

function savedToken(entry, url) {
  if (entry?.url !== url) return undefined;
  const auth = entry.http_headers?.Authorization;
  if (typeof auth === 'string' && auth.startsWith('Bearer ')) return auth.slice(7);
  return typeof entry.bearer_token_env_var === 'string' ? process.env[entry.bearer_token_env_var] : undefined;
}

export async function verifyRemote(url, token) {
  const client = new Client({ name: 'app-security-setup', version: '0.3.0' });
  const transport = new StreamableHTTPClientTransport(new URL(url), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  try {
    await client.connect(transport, { timeout: 15000 });
    const { tools } = await client.listTools(undefined, { timeout: 15000 });
    if (!tools.some(tool => tool.name === 'health_check')) throw new Error('Tool missing');
    const result = await client.callTool({ name: 'health_check', arguments: {} }, { timeout: 15000 });
    if (result.isError || result.structuredContent?.status !== 'ok') throw new Error('Health check failed');
    return tools.map(tool => tool.name);
  } catch {
    throw new SetupError('MCP 连接验证失败：请检查 token、服务地址和网络。本次未写入配置。');
  } finally { await client.close(); await transport.close(); }
}

export async function runSetup(command, options) {
  const home = resolve(process.env.CODEX_HOME || join(homedir(), '.codex'));
  const configPath = join(home, 'config.toml');
  await assertPlainPath(home, true);
  await assertPlainPath(configPath);
  const original = await optionalRead(configPath);
  const config = readConfig(original);
  const entry = config.mcp_servers?.['app-security'];
  const url = validatedUrl(options.url ?? process.env.MCP_URL ?? (command === 'doctor' ? entry?.url : undefined) ?? DEFAULT_URL);
  console.log(`Codex 配置：${configPath}\nMCP 地址：${url}`);
  if (options.dryRun) {
    console.log('预览：验证连接后更新 MCP 配置并备份旧文件；不安装本地 Skill。未写文件，未发送 token。');
    return;
  }
  let token = process.env.MCP_AUTH_TOKEN || savedToken(entry, url);
  if (!token && command === 'doctor') throw new SetupError('未找到有效配置中的 token，请先运行 setup --client codex。');
  token ??= await hiddenToken();
  if (!/^[A-Za-z0-9_-]{32,}$/.test(token)) throw new SetupError('token 格式无效：至少 32 个字母、数字、下划线或连字符。');
  if (command === 'doctor') {
    if (!entry || entry.enabled === false) throw new SetupError('app-security MCP 未配置或被禁用。请重新运行 setup。');
    const tools = await verifyRemote(url, token);
    console.log(`PASS：配置和 MCP 协议连接正常。工具：${tools.join(', ')}`);
    console.log('工具是否已加载到当前对话，需要重启 Codex 后在新对话中验证。');
    return;
  }
  const tools = await verifyRemote(url, token);
  console.log(`远程验证通过：${tools.join(', ')}`);
  const target = {
    url, enabled: true,
    startup_timeout_sec: entry?.startup_timeout_sec ?? 30,
    tool_timeout_sec: entry?.tool_timeout_sec ?? 60,
    http_headers: { Authorization: `Bearer ${token}` },
  };
  const rendered = renderConfig(original ?? '', target);
  if (sameValues(entry, target)) {
    await chmod(configPath, 0o600);
    console.log('已是当前 MCP 配置，无需重复安装。重新连接后可调用 get_workflow。');
    return;
  }
  await mkdir(home, { recursive: true, mode: 0o700 });
  const lock = join(home, '.app-security-setup.lock');
  try { await mkdir(lock, { mode: 0o700 }); } catch (error) {
    if (error.code === 'EEXIST') throw new SetupError('已有安装任务或遗留安装锁，请确认没有其他安装进程后重试。');
    throw error;
  }
  const id = `${new Date().toISOString().replace(/[:.]/g, '-')}-${randomUUID().slice(0, 8)}`;
  const backup = join(home, 'backups', 'app-security', id);
  const tempConfig = join(home, `.app-security-config-${id}.tmp`);
  try {
    if (await optionalRead(configPath) !== original) throw new SetupError('安装期间配置已被其他程序修改，请重试。');
    await mkdir(backup, { recursive: true, mode: 0o700 });
    if (original !== null) await writeFile(join(backup, 'config.toml'), original, { flag: 'wx', mode: 0o600 });
    await writeFile(tempConfig, rendered.text, { flag: 'wx', mode: 0o600 });
    // 在替换配置前再次检查，避免网络验证期间或准备阶段的并发修改丢失。
    if (await optionalRead(configPath) !== original) throw new SetupError('配置发生并发修改，安装已回退，请重试。');
    await rename(tempConfig, configPath);
  } finally {
    await rm(tempConfig, { force: true });
    await rm(lock, { recursive: true, force: true });
  }
  if (rendered.reformatted) console.log('复杂 TOML 已重新排版，其他配置值均保留；原始注释可在备份中查看。');
  console.log(`安装完成。备份：${backup}`);
  console.log('请完全重启 Codex 并新建对话，输入：读取 app-security 的 get_workflow，并运行全部演示工具。');
}
